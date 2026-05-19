# Wächter Projektstatus

## Status: Planung -> Umsetzung (Python-Migration abgeschlossen)
Die Anforderungen aus dem überarbeiteten Pflichtenheft Version 1.1 wurden analysiert und in Python (asyncio) implementiert.

## Geplant / Erledigt
- [x] Initialisierung des Python-Projekts (venv, aiohttp, pytest)
- [x] Implementierung der Types / Interfaces (TypedDict) src/types.py
- [x] Implementierung strukturierter JSON-Logs src/logger.py
- [x] Implementierung der API-Client-Funktionen zum Worker (WorkerApi mit aiohttp) src/api.py
- [x] Implementierung der Provider-Architektur (ABC, HeuristicProvider, GoogleSafeBrowsingProvider, ClamAVProvider) src/providers/
- [x] Implementierung der Score-Aggregation src/aggregation.py
- [x] Implementierung des asynchronen Pull-Loops (asyncio Semaphore, exp. Backoff) src/loop.py
- [x] Hauptskript main.py
- [x] Unittests geschrieben (tests/test_aggregation.py, tests/test_providers.py) und erfolgreich durchgelaufen.
- [x] Fix: ClamAVProvider respektiert nun die Umgebungsvariable CLAMAV_ENABLED (Vorrang vor YAML-Config).
- [x] Verbesserung: Explizites Logging von Exceptions in ClamAVProvider bei Download- oder Scan-Fehlern.
- [x] PhishStats-Provider (PhishStatsProvider): Abfrage der kostenfreien PhishStats Community-Datenbank.
- [x] Bugfix: Installer/Updater überschreibt keine lokalen Konfigurations- oder Keyword-Daten mehr.

## In Arbeit
- Das Basis MVP (Phase 1-4) ist fertig.

## Erledigt
- **2026-05-18**: Screenshot‑Provider implementiert.
- **2026-05-18**: Logging für blockierte ClamAV-Downloads verbessert.
- **2026-05-18**: Screenshot-Erzeugung repariert und robuster gemacht.
- **2026-05-18**: Screenshot-Logging für Playwright-Startfehler erweitert.
- **2026-05-18**: Installationsskript für Screenshot-/Playwright-Setup korrigiert.
- **2026-05-18**: Shell-Installer waechter-installsh.sh auf aktuellen Stand gebracht.
- **2026-05-18**: Shell-Installer auf minimalen Bash-Bootstrap + Python-Kernlogik umgestellt.
- **2026-05-18**: Screenshot-Fehler für fehlende Systembibliotheken präzisiert.
- **2026-05-19**: Optionaler Redis-Cache für Google Safe Browsing implementiert.
  - Redis wird zur Vermeidung hoher Belastungen von GSB genutzt.
  - Konfiguration via YAML oder ENV möglich.
  - Implementierung in GoogleSafeBrowsingProvider mit Fallback-Logik.
- **2026-05-19**: PhishStats-Provider integriert.
  - Implementierung des PhishStatsProvider basierend auf der offenen REST-Schnittstelle.
  - Gewichtung auf 0,7 festgelegt.
- **2026-05-19**: Bugfix: Überschreiben von Konfiguration/Daten bei Updates verhindert.
  - config/waechter.yaml und data/keywords/heuristic/*.csv werden nicht mehr von git getrackt.
  - .gitignore aktualisiert, um diese Dateien zu ignorieren.
  - .example-Dateien als Templates erstellt.
  - Installer prüfen nun vor dem Erstellen, ob Dateien bereits existieren.
  - install.sh sichert und restauriert Konfigurationsdaten während des Updates.
  - Lokale Anpassungen bleiben nun auch bei Repository-Updates erhalten.

## Nächste Schritte
- Deployment Setup / Containerisierung / systemd Konfiguration auf dem Hetzner VPS prüfen.
