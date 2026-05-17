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

## Nächste Schritte
- Deployment Setup / Containerisierung / systemd Konfiguration auf dem Hetzner VPS und Cloudflare Konfiguration prüfen. 

