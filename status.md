# Wächter Projektstatus

## Status: Umsetzung (Python-Migration abgeschlossen) — Erweiterung: DNSBL-Provider

Die Anforderungen aus dem Pflichtenheft Version 1.2 wurden analysiert. Das Basis-MVP (Phase 1–4) ist in Python (asyncio) umgesetzt. Aktuell wird der Funktionsumfang um einen DNSBL-Provider (UCEPROTECT Level 3 via Redis) erweitert.

## Erledigt

- [x] Initialisierung des Python-Projekts (venv, aiohttp, pytest)
- [x] Implementierung der Types / Interfaces (TypedDict) `src/waechter/types.py`
- [x] Implementierung strukturierter JSON-Logs `src/logger.py`
- [x] Implementierung der API-Client-Funktionen zum Worker (WorkerApi mit aiohttp) `src/api.py`
- [x] Implementierung der Provider-Architektur (ABC, HeuristicProvider, GoogleSafeBrowsingProvider, ClamAVProvider) `src/providers/`
- [x] Implementierung der Score-Aggregation `src/aggregation.py`
- [x] Implementierung des asynchronen Pull-Loops (asyncio Semaphore, exp. Backoff) `src/loop.py`
- [x] Hauptskript `main.py`
- [x] Unittests geschrieben (`tests/test_aggregation.py`, `tests/test_providers.py`, `tests/test_dnsbl_provider.py`) und erfolgreich durchgelaufen.
- [x] Test-Hygiene bereinigt: kopierter Godaddy-Restblock aus `tests/test_providers.py` entfernt.
- [x] Modul-Hygiene bereinigt: `types.py` aus dem Repo-Root nach `src/waechter/types.py` verschoben, um Shadowing der Standardbibliothek zu vermeiden.
- [x] Brand-Daten aktualisiert: `netflix.com` und `disney.com` in `brand_domains.csv` sowie in der `.example`-Vorlage ergänzt.
- [x] Letzte Verifikation: `pytest tests` läuft grün (67 Tests).
- [x] Fix: ClamAVProvider respektiert nun die Umgebungsvariable `CLAMAV_ENABLED` (Vorrang vor YAML-Config).
- [x] Verbesserung: Explizites Logging von Exceptions in ClamAVProvider bei Download- oder Scan-Fehlern.
- [x] Implementierung der Heuristik: Domains, die weniger als 3 Tage alt sind, werden als hochgradig spam-verdächtig eingestuft (150% Gewichtung).
- [x] Dokumentation auf Pflichtenheft v1.2 aktualisiert (agents.md, pflichtenheft.md) — DNSBL-Provider spezifiziert.
- [x] DNSBL-Provider (`src/waechter/providers/dnsbl.py`) vollständig implementiert:
  - [x] Modul/Klasse `DnsblProvider(ScanProvider)`, optional via `DNSBL_ENABLED`.
  - [x] Asynchrone DNS-Auflösung (A-Records, IPv4) und asynchroner Redis-Client (`redis.asyncio`).
  - [x] Optimierter UCEPROTECT-Lookup-Algorithmus (Maskenschlüssel `u-{mask}:{net_int}`, /32→/8) per MGET.
  - [x] Konfiguration `DNSBL_*` (ENV > YAML), Score-Mapping, defensive Fehler-Defaults.
  - [x] Integration in Provider-Factory und Aggregation (`DNSBL_WEIGHT`).
  - [x] Umfassende Unit-Tests in `tests/test_dnsbl_provider.py`.
  - [x] README-Abschnitt zum DNSBL-Provider ergänzt.

## In Arbeit

- [ ] Deployment Setup / Containerisierung / systemd-Konfiguration auf dem Hetzner VPS; Cloudflare-Konfiguration prüfen.

## Nächste Schritte

- DNSBL-Provider gemäß `prompt_dnsbl_provider.md` implementieren und abnehmen.
- Deployment Setup / Containerisierung / systemd-Konfiguration auf dem Hetzner VPS; Cloudflare-Konfiguration prüfen. Beim Deployment sicherstellen, dass die DNSBL-Redis-Instanz erreichbar und die UCEPROTECT-Liste befüllt ist.

## Verbesserungen des Algorithmus
 - [x] Neufassung des heuristic Providers
 - [x] Testsuite anpassen an den Code des Heuristic providers erforderlich (Erweiterung der Tests für neue Heuristik-Features)

## Offene Punkte / Backlog (aus Pflichtenheft v1.2)

- WHOIS-Caching (Pflichtenheft Punkt 3) — eTLD+1-Schlüssel, TTL ~24h, In-Memory/Redis.
- DNS-Auflösungs-Cache für den DNSBL-Provider (Pflichtenheft Punkt 5).
- Optionale CDN-Allowlist für den DNSBL-Provider zur Reduktion von False Positives (Pflichtenheft Punkt 4).
- Metriken/Observability (Provider-Aufrufe, Fehlerraten, DNSBL-Hits/Misses).
- Root-`test_redis.py` enthält Top-Level-Code und bleibt ein Discovery-Risiko, falls statt `pytest tests` wieder ein kompletter Root-Lauf genutzt wird.
