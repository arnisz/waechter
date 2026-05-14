#!/usr/bin/env python3
"""
Waechter Installer

Ziel:
- Interaktiv durch die Grundinstallation führen
- .env schreiben/aktualisieren (ENV Variablen abfragen)
- Abhängigkeiten per pip installieren (aus dem Internet)
- Standard-Konfigurationsdateien und Keyword-CSV erzeugen, falls sie fehlen

Hinweis:
- Das Skript arbeitet im Projektwurzelverzeichnis (da, wo auch main.py liegt)
- Optional wird eine virtuelle Umgebung unter ".venv" angelegt und genutzt
"""

from __future__ import annotations

import os
import sys
import re
import shutil
import subprocess
from pathlib import Path
from textwrap import dedent


PROJECT_ROOT = Path(__file__).resolve().parent
MAIN_PY = PROJECT_ROOT / "main.py"
ENV_FILE = PROJECT_ROOT / ".env"
ENV_EXAMPLE_FILE = PROJECT_ROOT / ".env.example"
REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"
SANITIZED_REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.sanitized.txt"
VENV_DIR = PROJECT_ROOT / ".venv"


DEFAULT_CONFIG_YAML = dedent(
    """
    providers:
      heuristic:
        enabled: true
        weight: 0.6
        thresholds:
          redirect:
            warning: 3
            high: 5
            max: 10
          long_url_chars: 500
        scores:
          ip_address: 0.6
          suspicious_tld: 0.5
          long_url: 0.4
          aws_lambda_phishing: 0.8
          url_keywords: 0.4
          path_keywords: 0.3
          whois:
            missing_creation: 0.5
            age_lt_7d: 1.0
            age_lt_30d: 0.7
            fail_default: 0.5
          redirects:
            too_many: 0.8
            many: 0.5
            warning: 0.2
            domain_mismatch: 0.5
            to_ip: 0.7
          html:
            form_and_password: 1.0
            form_and_email: 0.7
            xhr_or_fetch: 0.5
          parsing_failed: 0.8
        lists:
          suspicious_tlds: [".tk", ".ml", ".ga", ".cf"]
        keyword_files:
          brand: "data/keywords/heuristic/brand_keywords.csv"
          brand_domains: "data/keywords/heuristic/brand_domains.csv"
          path: "data/keywords/heuristic/path_keywords.csv"
          url:  "data/keywords/heuristic/url_keywords.csv"

      google_safe_browsing:
        enabled: true
        weight: 1.0
        api:
          daily_limit: 10000
          client:
            id: "waechter"
            version: "1.1.0"

      clamav:
        enabled: false
        weight: 1.0
        connection:
          socket_path: "/var/run/clamav/clamd.ctl"
        limits:
          max_bytes: 5242880   # 5 MiB
          max_redirects: 7
        timeouts:
          download_sec: 10
          scan_sec: 10
    """
).strip() + "\n"


DEFAULT_BRAND_CSV = dedent(
    """
    keyword,score
    disney,0.8
    netflix,0.8
    paypal,0.8
    apple,0.8
    microsoft,0.8
    bank,0.7
    gov,0.6
    support,0.4
    verify,0.5
    secure,0.5
    login,0.5
    account,0.5
    billing,0.5
    visa,0.5
    mastercard,0.5
    google,0.8
    gmail,0.5
    facebook,0.5
    amazon,0.5
    xbox,0.5
    playstation,0.5
    ing,0.5
    hsbc,0.5
    """
).strip() + "\n"


DEFAULT_BRAND_DOMAINS_CSV = dedent(
    """
    brand,domain,match_mode
    amazon,amazon.de,etld1
    amazon,amazon.com,etld1
    amazon,amazon.co.uk,etld1
    amazon,pay.amazon.de,exact
    amazon,payments.amazon.de,exact
    paypal,paypal.com,etld1
    paypal,paypal.de,etld1
    microsoft,microsoft.com,etld1
    microsoft,office.com,etld1
    microsoft,live.com,etld1
    apple,apple.com,etld1
    google,google.com,etld1
    google,gmail.com,etld1
    facebook,facebook.com,etld1
    """
).strip() + "\n"


DEFAULT_PATH_CSV = dedent(
    """
    path
    /login
    /verify
    /account
    /secure
    /update
    /signin
    /auth
    /payment
    /payments
    """
).strip() + "\n"

DEFAULT_URL_CSV = dedent(
    """
    keyword
    verify
    support
    secure
    billing
    update
    identity
    unlock
    confirm
    payment
    payments
    """
).strip() + "\n"


def info(msg: str) -> None:
    print(f"[INFO] {msg}")


def warn(msg: str) -> None:
    print(f"[WARN] {msg}")


def error(msg: str) -> None:
    print(f"[ERROR] {msg}")


def prompt(text: str, default: str | None = None, required: bool = False, secret: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        raw = input(f"{text}{suffix}: ").strip()
        if not raw and default is not None:
            raw = default
        if required and not raw:
            warn("Eingabe erforderlich.")
            continue
        return raw


def prompt_bool(text: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{text} ({d}): ").strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes", "1", "true"):
            return True
        if raw in ("n", "no", "0", "false"):
            return False
        warn("Bitte 'y' oder 'n' eingeben.")


def ensure_directories_and_files() -> None:
    cfg_dir = PROJECT_ROOT / "config"
    data_dir = PROJECT_ROOT / "data" / "keywords" / "heuristic"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    cfg_file = cfg_dir / "waechter.yaml"
    if not cfg_file.exists():
        cfg_file.write_text(DEFAULT_CONFIG_YAML, encoding="utf-8")
        info(f"Konfigurationsdatei erstellt: {cfg_file}")
    else:
        info(f"Konfigurationsdatei vorhanden: {cfg_file}")

    brand = data_dir / "brand_keywords.csv"
    brand_domains = data_dir / "brand_domains.csv"
    path_csv = data_dir / "path_keywords.csv"
    url_csv = data_dir / "url_keywords.csv"
    if not brand.exists():
        brand.write_text(DEFAULT_BRAND_CSV, encoding="utf-8")
        info(f"Brand-CSV erstellt: {brand}")
    if not brand_domains.exists():
        brand_domains.write_text(DEFAULT_BRAND_DOMAINS_CSV, encoding="utf-8")
        info(f"Brand-Domains-CSV erstellt: {brand_domains}")
    if not path_csv.exists():
        path_csv.write_text(DEFAULT_PATH_CSV, encoding="utf-8")
        info(f"Path-CSV erstellt: {path_csv}")
    if not url_csv.exists():
        url_csv.write_text(DEFAULT_URL_CSV, encoding="utf-8")
        info(f"URL-CSV erstellt: {url_csv}")


def python_executable_of_venv(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def create_or_use_venv() -> Path:
    info("Python-Version: " + sys.version.replace("\n", " "))
    if prompt_bool("Virtuelle Umgebung (.venv) erstellen und verwenden?", default=True):
        import venv
        if not VENV_DIR.exists():
            info("Erzeuge virtuelle Umgebung unter .venv …")
            builder = venv.EnvBuilder(with_pip=True)
            builder.create(VENV_DIR)
        else:
            info(".venv ist bereits vorhanden – wird verwendet.")
        return python_executable_of_venv(VENV_DIR)
    else:
        info("Verwende das aktuelle Python der Umgebung.")
        return Path(sys.executable)


def sanitize_requirements_file(src: Path, dst: Path) -> list[str]:
    if not src.exists():
        warn("requirements.txt nicht gefunden – installiere minimale Abhängigkeiten.")
        lines = [
            "aiohttp>=3.8,<4",
            "idna>=3.0",
            "python-dotenv>=1.0,<2",
            "python-whois>=0.9",
            "PyYAML>=6.0",
            "tldextract>=5.0,<6",
        ]
        dst.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return lines

    raw = src.read_bytes()
    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        text = raw.decode("latin-1", errors="ignore")

    # Entferne NULs und unsichtbare Steuerzeichen
    text = text.replace("\x00", "")
    text = re.sub(r"[\r]+", "\n", text)

    # Filtern: Ignoriere Kommentare/Leerzeilen, trimme Whitespaces
    tmp_lines: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Entferne eingebettete Leerzeichen und nicht druckbare Zeichen
        line = re.sub(r"\s+", "", line)
        # Ganz grobe Validierung: nur erlaubte Zeichen
        if not re.match(r"^[A-Za-z0-9_.\-~=<>!,:]+$", line):
            warn(f"Überspringe verdächtige Zeile in requirements.txt: {line}")
            continue
        tmp_lines.append(line)

    # Deduplizieren bei Erhalt der Reihenfolge
    seen = set()
    clean_lines: list[str] = []
    for l in tmp_lines:
        if l.lower() in seen:
            continue
        seen.add(l.lower())
        clean_lines.append(l)

    if not any(l.lower().startswith("aiohttp") for l in clean_lines):
        clean_lines.append("aiohttp>=3.8,<4")
    if not any("python-dotenv" in l.lower() for l in clean_lines):
        clean_lines.append("python-dotenv>=1.0,<2")
    if not any("python-whois" in l.lower() for l in clean_lines):
        clean_lines.append("python-whois>=0.9")
    if not any(l.lower().startswith("pyyaml") for l in clean_lines):
        clean_lines.append("PyYAML>=6.0")
    if not any(l.lower().startswith("idna") for l in clean_lines):
        clean_lines.append("idna>=3.0")
    if not any(l.lower().startswith("tldextract") for l in clean_lines):
        clean_lines.append("tldextract>=5.0,<6")

    dst.write_text("\n".join(clean_lines) + "\n", encoding="utf-8")
    return clean_lines


def pip_install(python_bin: Path, req_file: Path) -> None:
    info("Aktualisiere pip …")
    subprocess.check_call([str(python_bin), "-m", "pip", "install", "--upgrade", "pip"], cwd=str(PROJECT_ROOT))
    info("Installiere Abhängigkeiten (dies lädt Pakete aus dem Internet) …")
    subprocess.check_call([str(python_bin), "-m", "pip", "install", "-r", str(req_file)], cwd=str(PROJECT_ROOT))
    info("Installiere Waechter im Editable-Modus …")
    subprocess.check_call([str(python_bin), "-m", "pip", "install", "-e", str(PROJECT_ROOT)], cwd=str(PROJECT_ROOT))

    if prompt_bool("Entwickler-Tools (pytest, aioresponses) installieren?", default=False):
        subprocess.check_call([str(python_bin), "-m", "pip", "install", "-e", f"{PROJECT_ROOT}[dev]"], cwd=str(PROJECT_ROOT))


def load_env_example_defaults() -> dict[str, str]:
    defaults: dict[str, str] = {}
    if ENV_EXAMPLE_FILE.exists():
        for line in ENV_EXAMPLE_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            defaults[k.strip()] = v.strip()
    return defaults


def write_env(env_values: dict[str, str]) -> None:
    existing: dict[str, str] = {}
    lines: list[str] = []
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                existing[k.strip()] = v
            lines.append(line)

    # Update/insert keys
    for k, v in env_values.items():
        existing[k] = v

    # Schreibe schlank neu zusammen (ohne Kommentare beizubehalten)
    content = "\n".join([f"{k}={v}" for k, v in existing.items()]) + "\n"
    ENV_FILE.write_text(content, encoding="utf-8")
    info(f".env geschrieben: {ENV_FILE}")


def configure_env_interactively() -> None:
    info("Konfiguriere ENV Variablen (.env)")
    defaults = load_env_example_defaults()

    worker_base_url = prompt("WORKER_BASE_URL (API-Endpoint)", default=defaults.get("WORKER_BASE_URL"), required=True)
    waechter_token = prompt("WAECHTER_TOKEN (Auth Token)", default=defaults.get("WAECHTER_TOKEN"), required=True)

    gsb_key = prompt("GOOGLE_SAFE_BROWSING_API_KEY (optional)", default=os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", ""))

    # Betriebs-Parameter (optionale Defaults)
    min_wait = prompt("MIN_WAIT_MS", default=os.environ.get("MIN_WAIT_MS", "5000"))
    max_wait = prompt("MAX_WAIT_MS", default=os.environ.get("MAX_WAIT_MS", "60000"))
    batch_size = prompt("BATCH_SIZE", default=os.environ.get("BATCH_SIZE", "50"))
    concurrency = prompt("SCAN_CONCURRENCY", default=os.environ.get("SCAN_CONCURRENCY", "20"))
    th_warn = prompt("THRESHOLD_WARNING", default=os.environ.get("THRESHOLD_WARNING", "0.70"))
    th_block = prompt("THRESHOLD_BLOCK", default=os.environ.get("THRESHOLD_BLOCK", "0.95"))

    # ClamAV
    clamav_enabled = prompt_bool("ClamAV Integration aktivieren?", default=False)
    clamav_socket = ""
    if clamav_enabled:
        default_socket = os.environ.get("CLAMAV_SOCKET_PATH", "/var/run/clamav/clamd.ctl")
        clamav_socket = prompt("CLAMAV_SOCKET_PATH (UNIX Socket)", default=default_socket)

    # Optional: expliziter Pfad zur YAML
    cfg_path = prompt("WAECHTER_CONFIG Pfad (leer = Standard)", default="")
    kw_dir = prompt("WAECHTER_KEYWORDS_DIR (leer = Standard)", default="")

    values = {
        "WORKER_BASE_URL": worker_base_url,
        "WAECHTER_TOKEN": waechter_token,
        "GOOGLE_SAFE_BROWSING_API_KEY": gsb_key,
        "MIN_WAIT_MS": min_wait,
        "MAX_WAIT_MS": max_wait,
        "BATCH_SIZE": batch_size,
        "SCAN_CONCURRENCY": concurrency,
        "THRESHOLD_WARNING": th_warn,
        "THRESHOLD_BLOCK": th_block,
        "CLAMAV_ENABLED": "true" if clamav_enabled else "false",
    }
    if clamav_enabled and clamav_socket:
        values["CLAMAV_SOCKET_PATH"] = clamav_socket
    if cfg_path:
        values["WAECHTER_CONFIG"] = cfg_path
    if kw_dir:
        values["WAECHTER_KEYWORDS_DIR"] = kw_dir

    write_env(values)


def main() -> int:
    print("=" * 72)
    print("Waechter Installer")
    print("=" * 72)

    if not MAIN_PY.exists():
        error("main.py nicht gefunden. Bitte im Projektwurzelverzeichnis ausführen.")
        return 2

    ensure_directories_and_files()

    py = create_or_use_venv()

    # requirements.txt säubern und installieren
    try:
        clean_lines = sanitize_requirements_file(REQUIREMENTS_FILE, SANITIZED_REQUIREMENTS_FILE)
        if not clean_lines:
            warn("Keine gültigen Anforderungen gefunden – setze Minimalset.")
            SANITIZED_REQUIREMENTS_FILE.write_text("aiohttp\nidna\npython-dotenv\npython-whois\nPyYAML\ntldextract\n", encoding="utf-8")
        pip_install(py, SANITIZED_REQUIREMENTS_FILE)
    except subprocess.CalledProcessError as e:
        error(f"Paketinstallation fehlgeschlagen (Exit {e.returncode}). Sie können es später erneut versuchen: {py} -m pip install -r {SANITIZED_REQUIREMENTS_FILE}")

    configure_env_interactively()

    print("\nFertig! Nächste Schritte:")
    if str(py).lower().endswith("python.exe") or "/bin/python" in str(py):
        if py.parent.name.lower() == "scripts" or py.parent.name == "bin":
            # venv-Aktivierungshinweise
            if os.name == "nt":
                print(f"1) Aktivieren: {VENV_DIR}\\Scripts\\activate.bat")
            else:
                print(f"1) Aktivieren: source {VENV_DIR}/bin/activate")
            print("2) Starten:    python main.py")
        else:
            print(f"1) Starten:    {py} main.py")
    else:
        print("1) Starten:    python main.py")

    print("\nHinweis: Einstellungen können in der .env und in config/waechter.yaml angepasst werden.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        raise SystemExit(130)
