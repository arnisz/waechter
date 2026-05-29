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
- [x] Letzte Verifikation: `pytest tests` läuft grün (68 Tests).
- [x] Testsuite auf neue Provider-Subpaket-Architektur migriert: API-Änderungen (Dataclass-Attributzugriff statt Dict-Subscript, `provider.analyzer.check_whois_age`, `provider.domains.brand_context`, neue Modulpfade für Logger/Funktionen) in allen betroffenen Testdateien nachgezogen.
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
- [ ] Nächster Implementierungsschritt: Installations- und Betriebs-Findings korrigieren, die bei Debian-Installation oder Laufzeit zu Fehlern führen können.

## Aktuelle Findings aus Dokumentations-/Codeprüfung

Diese Punkte müssen vor dem nächsten produktiven Rollout umgesetzt oder bewusst entschieden werden:

- Undokumentierte bzw. unvollständig dokumentierte Provider: `main.py` integriert zusätzlich `PhishStatsProvider` und `ScreenshotProvider`. README, agents.md und Pflichtenheft beschreiben aktuell primär Heuristik, Google Safe Browsing, ClamAV und DNSBL.
- `PhishStatsProvider` ist ohne Konfigurationsabschnitt standardmäßig aktiv und erzeugt externe Requests zu `api.phishstats.info`. In Firewall-/NAT-Umgebungen muss dieser Egress dokumentiert, erlaubt oder der Provider standardmäßig deaktiviert werden.
- `ScreenshotProvider` benötigt Playwright/Chromium und zusätzliche Debian-Systembibliotheken. Ohne vollständige Installation kann der Provider zur Laufzeit scheitern; mit aktivem Provider entstehen zusätzliche Browser-/SSRF-/Egress-Risiken beim Laden beliebiger Zielseiten hinter der Firewall.
- `.env.example`, README, `config/waechter.yaml`, `install.py` und Provider-Code sind nicht deckungsgleich. Es fehlen u. a. `DNSBL_*`, `PHISHSTATS_ENABLED`, `SCREENSHOT_*` und Redis-Cache-Variablen in `.env.example`; außerdem weichen Defaultwerte für `MAX_WAIT_MS`, `THRESHOLD_WARNING` und `THRESHOLD_BLOCK` ab.
- Provider-Metadaten verwenden teils `URLCHECK_CLAMAV_*`/`URLCHECK_DNSBL_*`, während die dokumentierte und im Installer verwendete Konvention `CLAMAV_*`/`DNSBL_*` lautet.
- Der DNSBL-ENV-Vorrang ist für alle dokumentierten Optionen zu vereinheitlichen: `DNSBL_TIMEOUT_MS`, `DNSBL_MAX_IPS`, `DNSBL_SCORE_LISTED`, `DNSBL_USE_SPAMSCORE` und `DNSBL_WEIGHT` müssen konsistent aus ENV/YAML aufgelöst werden.
- Die Debian-Dokumentation muss explizit zwischen Minimalbetrieb hinter Firewall/NAT und optionalen Providern mit zusätzlichem Egress unterscheiden.

## Nächste Schritte

- Installations- und Betriebs-Findings aus der Dokumentations-/Codeprüfung beheben: Konfigurationsmatrix vereinheitlichen, `.env.example` aktualisieren, README/agents/Pflichtenheft angleichen, optionale Provider-Defaults prüfen und Debian-Installationspfad verifizieren.
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
