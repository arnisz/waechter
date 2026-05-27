# Waechter

Waechter is an asynchronous Python worker that pulls pending URLs from a backend API, scans them with multiple providers, aggregates the provider scores, and posts the final scan result back to the backend.

Current version: **0.1.0**

## Features

- Async polling loop with exponential backoff.
- Provider-based scan architecture.
- Built-in heuristic URL checks.
- Optional Google Safe Browsing provider.
- Optional DNSBL provider (UCEPROTECT Level 3 via Redis).
- Optional local ClamAV provider via `clamd` and `INSTREAM`.
- Weighted Bayesian noisy-OR score aggregation.
- Structured JSON logs.

## Requirements

- Python 3.13 or compatible Python 3 version.
- A backend implementing the internal Waechter API endpoints listed below.
- Optional: Google Safe Browsing API key.
- Optional: ClamAV daemon on Linux/Raspberry Pi for local content scanning.

## Installation

Clone the repository, then run the interactive installer from the project root:

```bash
python install.py
```

On Windows PowerShell:

```powershell
py install.py
```

The installer guides you through the basic setup:

- creates or reuses `.venv`,
- installs Python dependencies from `requirements.txt`,
- installs Waechter as an editable local package,
- creates missing default files under `config/` and `data/keywords/heuristic/`,
- writes or updates `.env` with the required runtime settings.

You will be prompted for:

- `WORKER_BASE_URL`
- `WAECHTER_TOKEN`
- optional `GOOGLE_SAFE_BROWSING_API_KEY`
- polling, batch, threshold, and concurrency settings
- optional ClamAV settings
- optional DNSBL / Redis settings

After installation, activate the virtual environment and start the worker:

```bash
source .venv/bin/activate
python main.py
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python main.py
```

Settings can be changed later in `.env` and `config/waechter.yaml`. **Note:** Environment variables (like `CLAMAV_ENABLED`) take precedence over YAML configuration files.

### Manual Installation

If you do not want to use the installer, create a virtual environment manually:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

Create your local environment file:

```bash
cp .env.example .env
```

Then edit `.env` for your deployment.

## Configuration

Required variables:

```env
WORKER_BASE_URL=https://your-backend.example
WAECHTER_TOKEN=your_internal_worker_token
```

Optional variables:

```env
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key
CLAMAV_ENABLED=false
DNSBL_ENABLED=false
DNSBL_REDIS_URL=redis://localhost:6379/0
SCAN_CONCURRENCY=20
BATCH_SIZE=50
MIN_WAIT_MS=5000
MAX_WAIT_MS=60000
LOG_LEVEL=INFO
THRESHOLD_WARNING=0.70
THRESHOLD_BLOCK=0.95
```

`CLAMAV_ENABLED=true` enables the local ClamAV provider. This is intended for Linux systems where `clamd` exposes a Unix socket, for example `/run/clamav/clamd.ctl`.

## Running

Start the worker:

```bash
python main.py
```

For debug logs:

```bash
LOG_LEVEL=DEBUG python main.py
```

On Windows PowerShell:

```powershell
$env:LOG_LEVEL='DEBUG'
python main.py
```

## ClamAV Setup

On Debian/Raspberry Pi OS, install ClamAV:

```bash
sudo apt update
sudo apt install clamav clamav-daemon
sudo systemctl enable --now clamav-daemon
```

Check that the daemon and socket exist:

```bash
sudo systemctl status clamav-daemon
ls -l /run/clamav/clamd.ctl
```

The worker process must have permission to access the ClamAV socket. If the worker logs `Permission denied` or `No such file`, check the `clamav-daemon` service status, socket path, and user/group permissions.

The ClamAV provider:

- downloads only `http` and `https` URLs,
- follows up to 7 redirects,
- scans up to 5 MB of downloaded content,
- returns `raw_score = 1.0` when ClamAV reports `FOUND`,
- returns `raw_score = 0.9` if the redirect limit is exceeded,
- returns `raw_score = 0.1` for partial scans caused by the 5 MB limit,
- returns `raw_score = 0.0` when ClamAV reports no finding.

## Systemd Example

Example unit:

```ini
[Unit]
Description=Waechter URL scanning worker
After=network-online.target clamav-daemon.service
Wants=network-online.target
Requires=clamav-daemon.service

[Service]
Type=simple
WorkingDirectory=/opt/waechter
EnvironmentFile=/opt/waechter/.env
ExecStart=/opt/waechter/.venv/bin/python /opt/waechter/main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Reload and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now waechter
sudo journalctl -u waechter -f
```

When using systemd, environment variables from your shell are not inherited. Put production values in the configured `EnvironmentFile`.

## API Endpoints

All API requests use:

```http
Authorization: Bearer <WAECHTER_TOKEN>
Content-Type: application/json
```

The base URL is configured with `WORKER_BASE_URL`.

### Health Check

```http
GET /api/internal/health
```

Expected behavior:

- `2xx`: worker startup continues.
- `401`: worker exits.
- other errors: logged; the polling loop continues retrying.

### Fetch Pending Links

```http
GET /api/internal/links/pending?limit=<BATCH_SIZE>
```

Expected response:

```json
{
  "links": [
    {
      "id": "dc2f7579169b9774736a0403baafaae5",
      "short_code": "check-das",
      "target_url": "https://example.com",
      "created_at": "2026-05-03T14:10:13.840Z"
    }
  ]
}
```

If no links are returned, the worker increases its wait time up to `MAX_WAIT_MS`.

### Post Scan Result

```http
POST /api/internal/links/{link_id}/scan-result
```

Request body:

```json
{
  "aggregate_score": 1.0,
  "status": "blocked",
  "scans": [
    {
      "provider": "heuristic",
      "raw_score": 0.0,
      "raw_response": null
    },
    {
      "provider": "clamav",
      "raw_score": 1.0,
      "raw_response": "stream: Eicar-Test-Signature FOUND"
    }
  ]
}
```

`status` is one of:

- `active`
- `warning`
- `blocked`

A `404` response is treated as a non-fatal condition, for example when the link was manually overridden or no longer needs a scan result.

### Release Stale Claims

```http
POST /api/internal/links/release-stale
```

This endpoint is called at startup and periodically while the worker is idle.

## Providers

### Heuristic Provider

Always enabled. Scores simple URL risk signals:

- raw IP hostnames,
- suspicious TLDs,
- very long URLs,
- brand names on non-official domains,
- URL userinfo tricks such as `https://www.amazon.de@evil.com/login`,
- punycode hostnames,
- long redirect chains,
- redirects to raw IP addresses.

Heuristic data is loaded from CSV files:

- `data/keywords/heuristic/brand_keywords.csv` lists brand keywords and their impersonation score.
- `data/keywords/heuristic/brand_domains.csv` lists official domains for each brand.
- `data/keywords/heuristic/path_keywords.csv` and `data/keywords/heuristic/url_keywords.csv` define generic keyword signals.
- `data/keywords/heuristic/suspicious_tlds.csv` defines suspicious TLD suffixes.
- `data/keywords/heuristic/trusted_domains.csv` defines global allowlisted domains (score short-circuit to `0.0`).
- `data/keywords/heuristic/identity_providers.csv` defines tolerated IdP targets for cross-domain form actions.
- `data/keywords/heuristic/hosting_platforms.csv` defines domains where WHOIS age checks are skipped.

`brand_domains.csv` has this format:

```csv
brand,domain,match_mode
amazon,amazon.de,etld1
amazon,pay.amazon.de,exact
```

`match_mode=etld1` matches the registrable domain, for example `www.amazon.de` -> `amazon.de`. `match_mode=exact` matches only the exact hostname. Known official brand domains reduce soft context signals such as login, payment, and form keywords, but they are not a full whitelist.

### Google Safe Browsing Provider

Enabled when `GOOGLE_SAFE_BROWSING_API_KEY` is set. It uses the Google Safe Browsing threat match API and returns `raw_score = 1.0` when a match is found.

### ClamAV Provider

Enabled with `CLAMAV_ENABLED=true`. It downloads URL content and streams it to local `clamd` through `INSTREAM`.

### DNSBL Provider

Enabled with `DNSBL_ENABLED=true`. It extracts the hostname, resolves it to IPv4 addresses, and checks them against the UCEPROTECT Level 3 list stored in a Redis database. It uses an optimized lookup covering masks from /32 down to /8.

## Score Aggregation

Provider results are aggregated with a weighted Bayesian noisy-OR model:

```text
P(malicious) = 1 - product((1 - raw_score) ^ weight)
```

This means:

- `raw_score = 0.0` means no positive signal, not proof that a URL is safe.
- multiple independent weak signals strengthen the aggregate score.
- a provider score of `1.0` makes the aggregate score `1.0`.

The aggregate score is mapped to a status using:

- `THRESHOLD_WARNING`, default `0.70`
- `THRESHOLD_BLOCK`, default `0.95`

## Tests

Run the test suite:

```bash
pip install -e ".[dev]"
pytest
```

On Windows PowerShell:

```powershell
pip install -e ".[dev]"
pytest
```

## Repository Hygiene

Do not commit `.env`, virtual environments, caches, logs, local archives, or IDE state. The included `.gitignore` excludes those files. Commit `.env.example` so deployments have a documented configuration template.

## License

Waechter is licensed under the GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
