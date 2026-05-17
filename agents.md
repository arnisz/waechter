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
  - Optional: `GOOGLE_SAFE_BROWSING_API_KEY`, `CLAMAV_ENABLED`, `CLAMAV_SOCKET_PATH`
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

Hinweis zu WHOIS: Aktuell erfolgt die Abfrage pro registrierbarer Basis‑Domain synchron via `python-whois` im Thread‑Pool (siehe `_check_whois_age`). Ein explizites Cache‑Layer ist noch nicht implementiert (siehe Pflichtenheft, Punkt 3).

## 6. Fehler‑ und Quotenbehandlung

- Provider dürfen `QuotaExhaustedError` auslösen; der Loop protokolliert Warnungen und fährt mit anderen Providern fort.
- Netzwerkfehler/Timeouts führen zu defensiven Defaults (z. B. WHOIS‑Fail‑Default, HTML‑Analyse best‑effort).
- Bei `401 Unauthorized` beendet der Worker den Prozess frühzeitig.

## 7. Betrieb und Deployment

- Single‑Binary Start: `python main.py` (nach Aktivierung des venv)
- Logging: `LOG_LEVEL=DEBUG` für Diagnose; bei systemd werden ENV nicht vom Shell‑Kontext geerbt → `EnvironmentFile` benutzen.
- ClamAV: `clamd` muss laufen und Socket‑Pfad muss passen; Größen‑ und Redirect‑Limits beachten.
- Skalierung: Mehrere Worker‑Instanzen möglich; Backend sollte Idempotenz/Claiming sicherstellen.

## 8. Tests

- Pytest‑Suite vorhanden (u. a. Aggregation, Provider‑Heuristik). Externe Provider‑Tests (GSB/ClamAV) können marker‑basiert ausgeschlossen werden.

## 9. Bekannte Verbesserungspunkte (Auszug)

- WHOIS‑Caching (siehe Pflichtenheft, Punkt „3. WHOIS‑Caching fehlt“): eTLD+1‑Schlüssel, TTL ~24h, In‑Memory oder Redis zur Vermeidung von Registrar‑IP‑Bans.
- Metriken/Observability: Zähler für Provider‑Aufrufe, Fehlerraten, Redirect‑Verteilungen, durchschnittliche Aggregat‑Scores.
- Circuit‑Breaker/Rate‑Limit für externe Dienste.

## 10. Quellen

- README.md (Install, Konfiguration, API, Betrieb)
- status.md (Umsetzungsstand)
- Code: `src/waechter/*` (Loop, Providers, Aggregation, Logger, Types, Config)