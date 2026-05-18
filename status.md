# Wächter Projektstatus

## Status: Planung -> Umsetzung (Python-Migration abgeschlossen)
Die Anforderungen aus dem überarbeiteten Pflichtenheft Version 1.1 wurden analysiert und in Python (asyncio) implementiert.

## Geplant / Erledigt
- [x] Initialisierung des Python-Projekts (venv, aiohttp, pytest)
- [x] Implementierung der Types / Interfaces (TypedDict) `src/types.py`
- [x] Implementierung strukturierter JSON-Logs `src/logger.py`
- [x] Implementierung der API-Client-Funktionen zum Worker (WorkerApi mit aiohttp) `src/api.py`
- [x] Implementierung der Provider-Architektur (ABC, HeuristicProvider, GoogleSafeBrowsingProvider, ClamAVProvider) `src/providers/`
- [x] Implementierung der Score-Aggregation `src/aggregation.py`
- [x] Implementierung des asynchronen Pull-Loops (asyncio Semaphore, exp. Backoff) `src/loop.py`
- [x] Hauptskript `main.py`
- [x] Unittests geschrieben (`tests/test_aggregation.py`, `tests/test_providers.py`) und erfolgreich durchgelaufen.
- [x] Fix: ClamAVProvider respektiert nun die Umgebungsvariable `CLAMAV_ENABLED` (Vorrang vor YAML-Config).
- [x] Verbesserung: Explizites Logging von Exceptions in ClamAVProvider bei Download- oder Scan-Fehlern.

## In Arbeit
- Das Basis MVP (Phase 1-4) ist fertig.
- [x] Screenshot‑Provider (`ScreenshotProvider`): URL in Headless‑Chromium öffnen, PNG‑Abbild (1024 × 768 px) unter `SCREENSHOT_DIR/<link_id>.png` speichern.
  - Abhängigkeit: `playwright` + `playwright install chromium`
  - ENV: `SCREENSHOT_ENABLED`, `SCREENSHOT_DIR`, `SCREENSHOT_TIMEOUT_MS`, `SCREENSHOT_NO_SANDBOX`
  - Interface: `ScanProvider.scan()` erhält optionalen Parameter `link_id: str | None = None`; Loop übergibt `link["id"]`; bestehende Provider bleiben unverändert
  - Implementierungsdateien: `src/waechter/providers/base.py` (Signatur), `src/waechter/providers/screenshot.py`, Registrierung in `src/waechter/providers/__init__.py`, Loop‑Integration in `src/waechter/loop.py`, `main.py`
  - Tests: `tests/test_screenshot_provider.py` (Playwright‑Marker, CI‑tauglich via Headless‑Mode)

## Erledigt
- **2026-05-18**: Screenshot‑Provider implementiert.
  - `ScanProvider.scan` Signatur um `link_id` erweitert, um kontextsensitive Speicherung zu ermöglichen.
  - `ScreenshotProvider` nutzt Playwright mit Headless-Chromium.
  - Konfiguration via Umgebungsvariablen (`SCREENSHOT_ENABLED`, `SCREENSHOT_DIR`, etc.) integriert.
  - Integration in den `pull_loop` und `main.py` abgeschlossen.
  - **Sicherheit**: Der `ScreenshotProvider` wird nun als letzter Provider in der Liste geführt, um sicherzustellen, dass er erst nach den anderen Analysen ausgeführt wird.
  - Playwright zu `requirements.txt` hinzugefügt.
- **2026-05-18**: Logging für blockierte ClamAV-Downloads verbessert.
  - `ClamAVProvider` protokolliert bei HTTP-Fehlern jetzt strukturierte Felder wie `http_status`, `final_url`, `redirect_count`, `server`, `response_preview` und `block_hint`.
  - 401/403-/429-Antworten werden grob klassifiziert (z. B. `possible_bot_protection_or_access_denied`, `rate_limited`), damit Bot-Schutz / WAF / Access-Denied-Fälle schneller erkennbar sind.
  - Das generische Loop-Log für Providerfehler enthält nun zusätzlich `url`, `error_type` und den vollständigen Fehlertext.
  - Testfall ergänzt: blockierter Abruf (`403`) erzeugt einen aussagekräftigen Fehler mit strukturiertem Log-Kontext.
- **2026-05-18**: Screenshot-Erzeugung repariert und robuster gemacht.
  - Hauptursache 1: In `config/waechter.yaml` fehlte ein `screenshot`-Block; dadurch war der Provider effektiv deaktiviert und tauchte nicht in `provider_names` auf.
  - Hauptursache 2: `playwright` war nur in `requirements.txt`, aber nicht in `pyproject.toml`; Installationen über `pip install .` / Paketinstallation brachten die Abhängigkeit daher nicht automatisch mit.
  - Korrektur: Standardkonfiguration `providers.screenshot.enabled: true` ergänzt, Startup-Logging um `screenshot_enabled_effective`, `screenshot_enabled_source`, `screenshot_disabled_reason` und `screenshot_dir` erweitert.
  - Robustheit: Seitenaufbau jetzt via `domcontentloaded` plus optionalem kurzem `networkidle`-Warten, damit Seiten mit dauerhaft aktiven Requests trotzdem ein PNG erzeugen können.
  - Testabdeckung ergänzt: `tests/test_screenshot_provider.py` prüft Aktivierung, Abhängigkeitsfehler und PNG-Speicherung über einen gemockten Playwright-Lauf.
- **2026-05-18**: Screenshot-Logging für Playwright-Startfehler erweitert.
  - Kritische Screenshot-Fehler loggen jetzt strukturierte Diagnosefelder wie `failure_stage`, `failure_reason`, `browser_engine`, `headless`, `browser_args`, `timeout_ms`, `playwright_cache_dir`, `playwright_browsers_path`, `python_executable` und `python_version`.
  - Fehlende Playwright-Browser-Binaries werden explizit als `playwright_browser_binary_missing` klassifiziert.
  - Der Pfad zur fehlenden Browser-Binary wird aus dem Fehlertext extrahiert (`executable_missing_path`) und mit einem konkreten `install_hint` geloggt.
  - Test ergänzt: fehlende Browser-Binaries erzeugen ein aussagekräftiges, strukturiertes Fehlerlog.
- **2026-05-18**: Installationsskript für Screenshot-/Playwright-Setup korrigiert.
  - `install.py` erzeugt nun auch im Default-YAML einen `screenshot`-Block mit sinnvollen Standardwerten.
  - Der Installer fragt jetzt `SCREENSHOT_ENABLED`, `SCREENSHOT_DIR`, `SCREENSHOT_TIMEOUT_MS` und `SCREENSHOT_NO_SANDBOX` interaktiv ab und schreibt sie in die `.env`.
  - Zusätzlich kann der Installer Playwright Chromium direkt über denselben Python-Interpreter der Projektumgebung installieren (`python -m playwright install chromium`).
  - Tests ergänzt: Screenshot-Block im Installer-Default und Playwright-Installationskommando werden validiert.
- **2026-05-18**: Shell-Installer `waechter-installsh.sh` auf aktuellen Stand gebracht.
  - Self-Update-Pfad korrigiert (`waechter-installsh.sh` statt veralteter Script-Referenz).
  - Screenshot-ENVs (`SCREENSHOT_ENABLED`, `SCREENSHOT_DIR`, `SCREENSHOT_TIMEOUT_MS`, `SCREENSHOT_NO_SANDBOX`) werden jetzt geladen und in die Environment-Datei geschrieben.
  - Das Skript installiert bei aktivem Screenshot-Provider nun sowohl typische Playwright/Chromium-Laufzeitbibliotheken als auch die Chromium-Browser-Binary via `python -m playwright install chromium` in der Projekt-venv.
  - Der systemd-Service berücksichtigt beschreibbare Screenshot-Pfade jetzt korrekt, auch wenn `SCREENSHOT_DIR` außerhalb von `/opt/waechter` liegt.
- **2026-05-18**: Screenshot-Fehler für fehlende Systembibliotheken präzisiert.
  - Playwright/Chromium-Startfehler mit `error while loading shared libraries` werden jetzt als `playwright_system_library_missing` klassifiziert.
  - Die fehlende Shared Library (`missing_shared_library`, z. B. `libnspr4.so`) und – wenn bekannt – das zugehörige Debian/Ubuntu-Paket (`linux_package_hint`, z. B. `libnspr4`) werden strukturiert geloggt.
  - Der Shell-Installer installiert nun auch `libnspr4`; der Python-Installer warnt auf Linux explizit vor fehlenden Chromium-Systembibliotheken.

## Nächste Schritte
- Deployment Setup / Containerisierung / systemd Konfiguration auf dem Hetzner VPS und Cloudflare Konfiguration prüfen.
- Systemd-Unit um `SCREENSHOT_DIR` und optionale Sandbox-Einstellung erweitern; auf Zielsystemen die benötigten Headless-Bibliotheken für Chromium prüfen.
