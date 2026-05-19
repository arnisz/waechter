# agents.md – Wächter Agenten-Dokumentation

Dieses Dokument beschreibt Zweck, Architektur, Datenfluss, Konfiguration und Betrieb des Wächter-Workers ("Agent"). Es fasst die Inhalte aus README, status.md und der Codeanalyse zusammen und dient als Einstieg für Entwicklung, Betrieb und On‑Call.

## 1. Zweck und Überblick

- Wächter ist ein asynchroner Python‑Worker, der periodisch beim Backend ausstehende URLs abholt, sie mit mehreren Providern prüft, die Einzelwerte zu einem Gesamtscore aggregiert und das Ergebnis an das Backend zurückmeldet.
- Der Worker ist zustandsarm (stateless) und kann horizontal skaliert werden. Konfiguration erfolgt per `.env`/Umgebungsvariablen und optional `config/waechter.yaml` (ENV > YAML).

## 2. Architektur und Hauptkomponenten

- Polling‑Loop (`waechter.loop.pull_loop`)
  - Steuert den Lebenszyklus: Healthcheck, Freigabe verwaister Claims, Abruf von Pending‑Links, parallele Verarbeitung mit `asyncio.Semaphore` und Exponential Backoff (`MIN_WAIT_MS` .. `MAX_WAIT_MS`).

- API‑Client (`waechter.api.WorkerApi`)
  - Endpunkte: `GET /api/internal/health`, `GET /api/internal/links/pending`, `POST /api/internal/links/{link_id}/scan-result`, `POST /api/internal/links/release-stale`.
  - Authentifizierung via `Authorization: Bearer <WAECHTER_TOKEN>`.

- Provider‑Schicht (`waechter.providers.*`)
  - Abstraktionen in `waechter.providers.base`: `ScanProvider` (ABC), `QuotaAwareProvider`, Fehlerklassen `QuotaExhaustedError`, `RedirectLimitExceededError`.
  - Implementierungen:
    - `HeuristicProvider` – immer aktiv; statische/heuristische Merkmale (IP‑Host, verdächtige TLDs, sehr lange URLs, Brand‑Imitation mit Keywords und offiziellen Domains, Punycode, Redirect‑Muster, HTML‑Formularindikatoren, Domainalter über WHOIS).
    - `GoogleSafeBrowsingProvider` – optional, benötigt `GOOGLE_SAFE_BROWSING_API_KEY`.
    - `ClamAVProvider` – optional, `CLAMAV_ENABLED=true`; lädt Inhalte (Größen‑ und Redirect‑Limits) und prüft per lokalem `clamd` (INSTREAM).
    - `PhishStatsProvider` – standardmäßig aktiv; fragt die kostenfreie PhishStats-Datenbank ab; nutzt optionalen Redis-Cache.
    - `ScreenshotProvider` – aktiv per Default, abschaltbar via `SCREENSHOT_ENABLED=false`; öffnet die URL in einem Playwright‑gesteuerten Headless‑Chromium, rendert die Seite und speichert ein PNG‑Abbild (1024 × 768 px) unter `SCREENSHOT_DIR/<link_id>.png`. Liefert keinen Score, stellt das Bild aber nachgelagerten Analyse‑Schritten bereit.

- Aggregation (`waechter.aggregation`)
  - Kombiniert Provider‑Ergebnisse mit gewichtetem Bayesian noisy‑OR: P(malicious) = 1 − Π(1 − raw_score)^weight.
  - Mappt den Gesamtscore auf Status: `active`, `warning`, `blocked` via `THRESHOLD_WARNING` und `THRESHOLD_BLOCK`.

- Logging (`waechter.logger`)
  - Strukturierte JSON‑Logs; wichtige Ereignisse: Providerstart/‑ergebnis, Fehler, abgeschlossene Scans inkl. Einzelwerte.

## 3. Datenfluss (Happy Path)

1. Start: Healthcheck und `release-stale` beim Backend.
2. Polling: `links/pending?limit=BATCH_SIZE` → Liste ausstehender Links.
3. Verarbeitung: Für jeden Link werden aktivierte Provider aufgerufen; Ergebnisse werden gesammelt.
4. Aggregation: Gesamtscore berechnen, Status bestimmen, Payload bereinigen (keine internen Gewichte übertragen).
5. Ergebnis posten: `POST /links/{id}/scan-result` mit Aggregat und Einzelwerten.
6. Leerlauf: Bei leeren Batches Backoff bis `MAX_WAIT_MS`, dann erneut `release-stale`.

## 4. Konfiguration

- Primär über `.env`/Umgebungsvariablen:
  - `WORKER_BASE_URL`, `WAECHTER_TOKEN` (Pflicht)
  - Optional: `GOOGLE_SAFE_BROWSING_API_KEY`, `CLAMAV_ENABLED`, `CLAMAV_SOCKET_PATH`, `SCREENSHOT_ENABLED`, `SCREENSHOT_DIR` (Pfad für PNG‑Abbilder, Standard: `./screenshots`), `SCREENSHOT_TIMEOUT_MS` (Browser‑Timeout je URL, Standard: `10000`)
  - Betriebsparameter: `SCAN_CONCURRENCY`, `BATCH_SIZE`, `MIN_WAIT_MS`, `MAX_WAIT_MS`, `LOG_LEVEL`, `THRESHOLD_WARNING`, `THRESHOLD_BLOCK`
- YAML (`config/waechter.yaml`) ergänzt/überschreibt feingranular Provider‑Einstellungen (Gewichte, Grenzwerte, Keyword‑Dateien). ENV hat Vorrang vor YAML.

## 5. Provider – Details Heuristik

Der `HeuristicProvider` nutzt u. a.:
- Hostname‑Normalisierung und Punycode‑Erkennung
- IP‑Adressen als Host
- verdächtige TLD‑Liste
- sehr lange URLs
- Brand‑Kontext: Keywords (`data/keywords/heuristic/brand_keywords.csv`) + offizielle Domains (`brand_domains.csv`, Modi `etld1`/`exact`)
- Pfad‑ und URL‑Keywords (`path_keywords.csv`, `url_keywords.csv`)
- WHOIS‑basierte Domainalter‑Signale (neu/fehlend → höhere Scores)
- Redirect‑Heuristiken (Anzahl, Domain‑Mismatch, Redirect auf IP)
- HTML‑Signale (Formular + Passwort/Email, XHR/fetch)

Hinweis zu WHOIS: Aktuell erfolgt die Abfrage pro registrierbarer Basis‑Domain synchron via `python-whois` im Thread‑Pool (siehe `_check_whois_age`). Ein explizites Cache‑Layer ist noch nicht implementiert (siehe Pflichtenheft, Punkt 1).

## 6. Provider – Details Screenshot

Der `ScreenshotProvider` nutzt **Playwright** (async API) mit Headless‑Chromium. In der Standardkonfiguration (`config/waechter.yaml`) ist er aktiviert; per `SCREENSHOT_ENABLED` kann er explizit übersteuert werden:

- Viewport: 1024 × 768 px, festes Format, kein Scaling.
- Ablauf: `page.goto(url, timeout=SCREENSHOT_TIMEOUT_MS, wait_until="domcontentloaded")` → optional `page.wait_for_load_state("networkidle")` mit kurzem Timeout → `page.screenshot(path=<SCREENSHOT_DIR>/<link_id>.png, full_page=False)`.
- Dateiname: `<link_id>.png` — die `link_id` ist die stabile Kennung eines Links; die Ziel‑URL kann nachträglich editiert werden, die `link_id` bleibt konstant. Ein URL‑Hash wäre daher ungeeignet. Bei einem Rescan wird die Datei überschrieben; es wird immer nur der aktuelle Stand vorgehalten.
- Interface‑Erweiterung: Die Basisklasse `ScanProvider.scan()` erhält einen optionalen Parameter `link_id: str | None = None`. Bestehende Provider ignorieren ihn; der `ScreenshotProvider` verwendet ihn zur Benennung der Ausgabedatei. Ist `link_id` nicht gesetzt, wird der Screenshot nicht gespeichert und eine Warnung geloggt.
- Sicherheit: Playwright wird im Sandbox‑Modus gestartet (`--no-sandbox` nur wenn explizit via `SCREENSHOT_NO_SANDBOX=true` gesetzt); kein Zugriff auf lokale Ressourcen; JavaScript‑Ausführung ist auf die Ziel‑Seite beschränkt.
- Fehlerverhalten: Bei Timeout, DNS‑Fehler oder sonstigem Browser‑Fehler wird der Fehler geloggt (Level `WARNING`). Beim Start loggt der Worker außerdem, ob der Screenshot-Provider effektiv aktiv ist (`screenshot_enabled_effective`) und falls nicht, warum (`screenshot_disabled_reason`). Der Provider gibt kein Ergebnis zurück; das Scan‑Ergebnis enthält keinen Screenshot‑Eintrag, der Gesamtlauf wird nicht unterbrochen.
- Abhängigkeit: `playwright` Python‑Paket; Chromium‑Binary muss via `playwright install chromium` bereitgestellt sein.

## 7. Fehler‑ und Quotenbehandlung

- Provider dürfen `QuotaExhaustedError` auslösen; der Loop protokolliert Warnungen und fährt mit anderen Providern fort.
- Netzwerkfehler/Timeouts führen zu defensiven Defaults (z. B. WHOIS‑Fail‑Default, HTML‑Analyse best‑effort).
- Bei `401 Unauthorized` beendet der Worker den Prozess frühzeitig.

## 7.5 Redis Caching (optional)

- Wird vom GoogleSafeBrowsingProvider und vom PhishStatsProvider genutzt, um API-Quota bzw. Last auf der PhishStats-Community-API zu sparen.
- Falls Redis nicht konfiguriert oder nicht erreichbar ist, erfolgen die Anfragen direkt (Fallback).
- Cache-Keys: provider-spezifisch (z. B. `gsb_cache:<sha256_url_hash>`, `phishstats_cache:<sha256_url_hash>`), TTL konfigurierbar (`REDIS_TTL_SEC`).
- Betrieb: Redis läuft idealerweise im RAM (nicht persistent).

## 8. Betrieb und Deployment

> **⚠️ WICHTIGER HINWEIS ZUM SYSTEM-INSTALLER:**
> Der System-Installer (`waechter.installer`) verwendet eine strikte Allowlist (Whitelist) für Umgebungsvariablen (`ENV_KEYS`). Variablen, die nicht explizit in dieser Liste im Code hinterlegt sind, werden bei einem Lauf des Installers (z. B. bei einem Update) stillschweigend aus der `/etc/waechter/waechter.env` entfernt. Dies kann dazu führen, dass funktionierende Konfigurationen (wie z.B. Caching via Redis) plötzlich nicht mehr greifen und funktionierende Systeme beschädigt werden. Zudem werden lokale Dateien wie `waechter.yaml` und Keyword-CSVs nun aus `.example`-Vorlagen generiert, um ein Überschreiben lokaler Änderungen durch Updates zu verhindern. Bei Modifikationen am System muss stets sichergestellt werden, dass neue ENV-Variablen auch im Installer Code (`constants.py`, `models.py`, `env.py`) eingetragen werden!


- Shell-Installer: `install.sh` ist nun ein **selbsttragender** Bootstrap für Systemdeployments und Curl-and-run-Szenarien. Er prüft Root-Rechte, installiert minimale Bootstrap-Pakete (`git`, `python3`, `python3-venv`, `ca-certificates`), klont/aktualisiert das Repo nach `/opt/waechter`, erzeugt die venv und ruft anschließend den Python-Installer via `python -m waechter.installer` auf.
- Python-Installer: Die eigentliche Installationslogik liegt jetzt unter `waechter.installer.*` (`env`, `clamav`, `playwright`, `systemd`, `users`, `uninstall`, `runtime`). Damit sind Parsing, Idempotenz, Fehlerbehandlung und Tests in Python statt in Bash konzentriert.
- Self-Update-Verhalten: Der Bash-Bootstrap bleibt klein und stabil; bei jedem Lauf kopiert der Python-Installer die Repo-Version von `install.sh` nach `/usr/local/sbin/waechter.sh`. Die Python-Kernlogik wird durch den vorgeschalteten `git fetch`/`git reset --hard` automatisch aktualisiert und im selben Lauf genutzt – ohne zweites Re-Exec.
- Einschränkung / bewusst akzeptiert: Änderungen **am Bash-Bootstrap selbst** wirken wegen der Natur selbstaktualisierender Launcher erst beim nächsten Aufruf von `/usr/local/sbin/waechter.sh` (N+1). Da der Bootstrap absichtlich minimal gehalten wird, ist dieser Trade-off akzeptabel; Änderungen in `waechter.installer.*` greifen bereits im aktuellen Lauf.
- `waechter-installsh.sh` ist nur noch ein abwärtskompatibler Wrapper und sollte nicht mehr als primärer Einstiegspunkt dokumentiert werden.
- Single‑Binary Start: `python main.py` (nach Aktivierung des venv)
- Logging: `LOG_LEVEL=DEBUG` für Diagnose; bei systemd werden ENV nicht vom Shell‑Kontext geerbt → `EnvironmentFile` benutzen.
- ClamAV: `clamd` muss laufen und Socket‑Pfad muss passen; Größen‑ und Redirect‑Limits beachten.
- PhishStats: API-Key-frei; nutzt `_where`-Filter für exakte URL-Matches.
- ClamAV HTTP-Fehlerdiagnose: Wenn Zielseiten automatisierte Abrufe blockieren (z. B. `403 Forbidden`, WAF/Bot-Protection), loggt der Provider strukturierte Diagnosefelder wie `http_status`, `final_url`, `redirect_count`, `server`, `response_preview` und `block_hint`. Dadurch lassen sich Access-Denied-/Bot-Block-Fälle wesentlich schneller eingrenzen.
- Screenshot‑Provider: `playwright install chromium` nach `pip install playwright` ausführen; auf headless‑Servern ggf. `libgbm`, `libnss3` und weitere System‑Abhängigkeiten installieren. Screenshots landen unter `SCREENSHOT_DIR` (Standard: `./screenshots`); Verzeichnis muss vom Worker‑Prozess beschreibbar sein.
- Skalierung: Mehrere Worker‑Instanzen möglich; Backend sollte Idempotenz/Claiming sicherstellen. Jede Instanz benötigt einen eigenen `SCREENSHOT_DIR`, falls Screenshots persistent gespeichert werden sollen.

## 9. Tests

- Pytest‑Suite vorhanden (u. a. Aggregation, Provider‑Heuristik). Externe Provider‑Tests (GSB/ClamAV) können marker‑basiert ausgeschlossen werden.
- Screenshot‑Tests: Playwright‑Tests können mit dem Marker `@pytest.mark.playwright` versehen und im CI ohne Display via `xvfb` oder `--headed=false` ausgeführt werden.

## 10. Bekannte Verbesserungspunkte (Auszug)

- WHOIS‑Caching (siehe Pflichtenheft, Punkt „1. WHOIS‑Caching fehlt”): eTLD+1‑Schlüssel, TTL ~24h, In‑Memory oder Redis zur Vermeidung von Registrar‑IP‑Bans.
- Metriken/Observability: Zähler für Provider‑Aufrufe, Fehlerraten, Redirect‑Verteilungen, durchschnittliche Aggregat‑Scores.
- Circuit‑Breaker/Rate‑Limit für externe Dienste.
- Screenshot‑Analyse: Der `ScreenshotProvider` erstellt derzeit nur das PNG‑Abbild. Eine nachgelagerte visuelle Auswertung (z. B. OCR via Tesseract, Phishing‑Klassifikator auf Bildebene) ist als optionale Erweiterungsstufe geplant.

## 11. Quellen

- README.md (Install, Konfiguration, API, Betrieb)
- status.md (Umsetzungsstand)
- Code: `src/waechter/*` (Loop, Providers, Aggregation, Logger, Types, Config)