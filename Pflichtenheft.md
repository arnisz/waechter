# Pflichtenheft – Wächter URL‑Scanning‑Worker

Version: 1.1 • Datum: 2026-05-18

## 1. Zielsetzung und Scope

- Ziel ist ein robuster, skalierbarer Worker („Wächter“), der verdächtige URLs aus einem Backend entgegennimmt, mit mehreren Prüfern (Providern) bewertet, die Ergebnisse zu einem Gesamtscore aggregiert und diesen inklusive Einzelwerte an das Backend zurückliefert.
- Scope umfasst Worker‑Prozess, Provider‑Integrationen (Heuristik, Google Safe Browsing, ClamAV) und Konfigurations-/Betriebsartefakte. Das Backend selbst ist außerhalb des Scopes, wird jedoch über definierte interne Endpunkte angebunden.

Nicht‑Ziele:
- Vollständige Content‑Analyse jenseits der ClamAV‑Limits (z. B. große Dateien, komplexes JS‑Rendering).
- Umfassendes Whitelisting/Trust‑System jenseits offizieller Brand‑Domains.

## 2. Begriffe

- Link: vom Backend gelieferter Prüfkandidat (`id`, `short_code`, `target_url`, `created_at`).
- Provider: modulare Prüflogik mit `raw_score` und optionalem `raw_response` (Heuristik/GSB/ClamAV).
- Aggregat‑Score: kombinierter Risikowert aus allen Provider‑Scores (Bayesian noisy‑OR mit Gewichten).
- Status: `active`, `warning`, `blocked`, basierend auf Schwellwerten.

## 3. Systemkontext

- Eingehend: `GET /api/internal/links/pending?limit=N` liefert Batches von Links.
- Ausgehend: `POST /api/internal/links/{link_id}/scan-result` übermittelt Ergebnis.
- Verwaltungsendpunkte: `GET /api/internal/health`, `POST /api/internal/links/release-stale`.
- Externe Dienste: Google Safe Browsing API (optional), lokaler `clamd` (optional), WHOIS‑Registrare (über `python-whois`).

## 4. Funktionale Anforderungen

F1. Polling‑Loop
- Der Worker prüft zyklisch auf Pending‑Links, mit exponentiellem Backoff bei Leerläufen (`MIN_WAIT_MS`..`MAX_WAIT_MS`).

F2. Nebenläufige Verarbeitung
- Bis zu `SCAN_CONCURRENCY` Links werden parallel verarbeitet. Pro Link werden aktivierte Provider sequenziell/parallel gemäß Implementierung aufgerufen; Fehler eines Providers verhindern nicht die Gesamtauswertung.

F3. Provider‑Prüfungen
- Heuristik: URL/Host/Keyword‑Signale, Redirect‑ und HTML‑Indikatoren, WHOIS‑basierte Altersprüfung.
- Google Safe Browsing: Bedrohungstreffer → hoher Score.
- ClamAV: Inhalte herunterladen (nur http/https), Redirect‑Limit, Größenlimit, Scan via `clamd`.

F4. Aggregation und Statusmapping
- Aggregation per gewichtetem Bayesian noisy‑OR. Schwellen: `THRESHOLD_WARNING`, `THRESHOLD_BLOCK`.

F5. Ergebnisübermittlung
- Übermittlung des Aggregats und der Einzelwerte als JSON. Interne Felder (z. B. Gewichte) werden nicht übertragen.

F6. Fehlerbehandlung
- Netzwerk‑, Zeitüberschreitungs‑ und Quotenfehler werden geloggt; der Worker fährt fort. Bei `401 Unauthorized` beendet sich der Prozess.

F7. Konfiguration
- ENV‑Variablen steuern Basisverhalten; YAML kann Provider‑Details/Listen konfigurieren. ENV hat Vorrang.

## 5. Nicht‑funktionale Anforderungen

N1. Performance/Throughput
- Ziel: Verarbeitung von mindestens `BATCH_SIZE * SCAN_CONCURRENCY` Links pro Intervall ohne dauerhafte Staus; Antwortzeiten der Provider begrenzen (Timeouts ~5s, wo sinnvoll).

N2. Zuverlässigkeit/Resilienz
- Backoff bei Leerlast/Fehlern; defensive Defaults (z. B. WHOIS‑Fail‑Default). Keine ungebremsten Endlosschleifen.

N3. Sicherheit
- Secret‑Handling via ENV/`.env`; Übertragung nur über HTTPS; `WAECHTER_TOKEN` per Bearer‑Auth; keine Protokollierung sensibler Inhalte.

N4. Wartbarkeit
- Strukturierte Logs (JSON), klare Fehlerklassen, modulare Provider‑Schnittstellen; Konfigurationsdateien versionieren; Tests für Kernlogik.

N5. Observability
- Logs enthalten Korrelationen (`link_id`, Provider, Scores). Optional Metriken (Zähler für Provider‑Aufrufe/Fehler).

## 6. Schnittstellen

- Interne Backend‑API: wie in README beschrieben (Health, Pending, Scan‑Result, Release‑Stale).
- Externe Provider:
  - Google Safe Browsing: HTTP API mit API‑Key, Quotenbeachtung.
  - ClamAV: lokaler Socket (`INSTREAM`), Rechte und Pfad müssen konfiguriert sein.
  - WHOIS: Abfragen über `python-whois` gegen Registrare (Rate‑Limits/Bans beachten).

## 7. Betrieb/Deployment

- Konfiguration per `.env` und `config/waechter.yaml`; bei systemd über `EnvironmentFile` einbinden.
- Start: venv aktivieren, `python main.py` ausführen; Logging‑Level via `LOG_LEVEL`.
- ClamAV: Dienst aktiv und Socket zugreifbar; Größen‑/Redirect‑Limits im Provider beachten.

## 8. Test und Abnahme

- Unit‑Tests decken Aggregation, Heuristik und Provider‑Schnittstellen ab; externe Provider können testseitig markiert/ausgeschaltet werden.
- Abnahmekriterien (Beispiele):
  - Aggregationsformel liefert erwartete Ergebnisse für definierte Testvektoren.
  - Heuristik erkennt Punycode/IP‑Hosts/verdächtige TLDs/Brand‑Imitationen gemäß Testdaten.
  - ClamAV meldet Treffer (Eicar‑Signatur) und respektiert Limits.
  - Backend‑Roundtrip (Mock/Dev) funktioniert: Pending → Scan → Result.

## 9. Bekannte Lücken / Risiken / To‑dos

3. WHOIS-Caching fehlt

Wenn Angreifer 50 verschiedene Phishing-Links generieren, die alle auf dieselbe neu registrierte Subdomain zeigen, feuert dein Wächter 50 separate WHOIS-Abfragen für dieselbe Domain ab. Das führt unweigerlich zum IP-Ban durch die WHOIS-Registrare.

Produktions-Tipp: Ein kleiner, In-Memory- oder Redis-Cache für bereits geprüfte Basis-Domains (z. B. 24 Stunden Gültigkeit für das Domain-Alter) ist für den Live-Betrieb essenziell.

Umsetzungsvorschlag und Abnahmekriterien:
- Schlüssel: registrierbare Basis‑Domain (eTLD+1) gemäß `tldextract`.
- TTL: 24h für positive Ergebnisse (Alter/Creation‑Date ermittelt); 1h für Fehlerfälle (negative Caching‑Strategie, um Thundering Herd zu vermeiden).
- Speicher: In‑Memory (LRU, Größenlimit) oder Redis (empfohlen für Mehrinstanzenbetrieb). Konfiguration via ENV (`WHOIS_CACHE_ENABLED`, `WHOIS_CACHE_TTL_H`, `REDIS_URL`).
- Verhalten: Mehrere Links mit gleicher Basis‑Domain innerhalb der TTL dürfen höchstens eine WHOIS‑Abfrage auslösen.
- Observability: Zähler für WHOIS‑Hits/Misses/Bans; Log‑Eintrag bei Rate‑Limit‑Erkennung, optional Circuit‑Breaker (temporär WHOIS deaktivieren und Fail‑Default verwenden).

Akzeptanztest (Beispiel):
- 50 Links mit unterschiedlichen Subdomains derselben neu registrierten Domain erzeugen: Es erfolgt maximal 1 WHOIS‑Abfrage innerhalb der TTL; alle weiteren Anfragen bedienen sich aus dem Cache (Miss=1, Hit≥49).

## 10. Anhänge/Quellen

- README.md (Install, Konfiguration, API)
- status.md (Umsetzungsstand)
- Quellcode: `src/waechter/*` (Loop, Providers, Aggregation, Logger, Types, Config)