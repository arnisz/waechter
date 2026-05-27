# Pflichtenheft – Wächter URL‑Scanning‑Worker

Version: 1.2 • Datum: 2026-05-27

Änderungen ggü. 1.1: Aufnahme des DNSBL‑Providers (UCEPROTECT Level 3 via Redis) in Scope, funktionale Anforderungen, Schnittstellen und Risiken.

## 1. Zielsetzung und Scope

- Ziel ist ein robuster, skalierbarer Worker („Wächter"), der verdächtige URLs aus einem Backend entgegennimmt, mit mehreren Prüfern (Providern) bewertet, die Ergebnisse zu einem Gesamtscore aggregiert und diesen inklusive Einzelwerte an das Backend zurückliefert.
- Scope umfasst Worker‑Prozess, Provider‑Integrationen (Heuristik, Google Safe Browsing, ClamAV, DNSBL) und Konfigurations-/Betriebsartefakte. Das Backend selbst ist außerhalb des Scopes, wird jedoch über definierte interne Endpunkte angebunden.

Nicht‑Ziele:
- Vollständige Content‑Analyse jenseits der ClamAV‑Limits (z. B. große Dateien, komplexes JS‑Rendering).
- Umfassendes Whitelisting/Trust‑System jenseits offizieller Brand‑Domains.
- Befüllung/Pflege der UCEPROTECT‑Redis‑Liste – der DNSBL‑Provider liest nur, das Einspielen der Daten erfolgt durch einen separaten, hier nicht spezifizierten Prozess.

## 2. Begriffe

- Link: vom Backend gelieferter Prüfkandidat (`id`, `short_code`, `target_url`, `created_at`).
- Provider: modulare Prüflogik mit `raw_score` und optionalem `raw_response` (Heuristik/GSB/ClamAV/DNSBL).
- Aggregat‑Score: kombinierter Risikowert aus allen Provider‑Scores (Bayesian noisy‑OR mit Gewichten).
- Status: `active`, `warning`, `blocked`, basierend auf Schwellwerten.
- DNSBL: DNS‑based Blocklist. Hier konkret: UCEPROTECT Level 3, vorgehalten in einer Redis‑Datenbank mit maskierten IPv4‑Netz‑Schlüsseln.

## 3. Systemkontext

- Eingehend: `GET /api/internal/links/pending?limit=N` liefert Batches von Links.
- Ausgehend: `POST /api/internal/links/{link_id}/scan-result` übermittelt Ergebnis.
- Verwaltungsendpunkte: `GET /api/internal/health`, `POST /api/internal/links/release-stale`.
- Externe Dienste: Google Safe Browsing API (optional), lokaler `clamd` (optional), WHOIS‑Registrare (über `python-whois`), Redis mit UCEPROTECT‑Level‑3‑Daten (optional, für DNSBL), öffentliche DNS‑Resolver (für DNSBL‑Namensauflösung).

## 4. Funktionale Anforderungen

F1. Polling‑Loop
- Der Worker prüft zyklisch auf Pending‑Links, mit exponentiellem Backoff bei Leerläufen (`MIN_WAIT_MS`..`MAX_WAIT_MS`).

F2. Nebenläufige Verarbeitung
- Bis zu `SCAN_CONCURRENCY` Links werden parallel verarbeitet. Pro Link werden aktivierte Provider sequenziell/parallel gemäß Implementierung aufgerufen; Fehler eines Providers verhindern nicht die Gesamtauswertung.

F3. Provider‑Prüfungen
- Heuristik: URL/Host/Keyword‑Signale, Redirect‑ und HTML‑Indikatoren, WHOIS‑basierte Altersprüfung (Domains < 3 Tage gelten als hochgradig spam-verdächtig).
- Google Safe Browsing: Bedrohungstreffer → hoher Score.
- ClamAV: Inhalte herunterladen (nur http/https), Redirect‑Limit, Größenlimit, Scan via `clamd`.
- DNSBL: Hostnamen aus der URL extrahieren, IPv4‑Adressen per DNS auflösen und gegen die UCEPROTECT‑Level‑3‑Liste in Redis prüfen; gelistete IP → erhöhter Score.

F4. Aggregation und Statusmapping
- Aggregation per gewichtetem Bayesian noisy‑OR. Schwellen: `THRESHOLD_WARNING`, `THRESHOLD_BLOCK`.
- Das DNSBL‑Gewicht ist moderat zu wählen (siehe Risiko in Abschnitt 9), sodass ein einzelnes L3‑Listing eine Warnung erzeugt, aber nicht allein zum `blocked`‑Status führt.

F5. Ergebnisübermittlung
- Übermittlung des Aggregats und der Einzelwerte als JSON. Interne Felder (z. B. Gewichte) werden nicht übertragen.

F6. Fehlerbehandlung
- Netzwerk‑, Zeitüberschreitungs‑ und Quotenfehler werden geloggt; der Worker fährt fort. Bei `401 Unauthorized` beendet sich der Prozess.
- DNS‑Auflösungsfehler und Redis‑Nichterreichbarkeit im DNSBL‑Provider führen zu einem neutralen Default‑Score (0.0) ohne Abbruch des Scans.

F7. Konfiguration
- ENV‑Variablen steuern Basisverhalten; YAML kann Provider‑Details/Listen konfigurieren. ENV hat Vorrang.

## 5. Nicht‑funktionale Anforderungen

N1. Performance/Throughput
- Ziel: Verarbeitung von mindestens `BATCH_SIZE * SCAN_CONCURRENCY` Links pro Intervall ohne dauerhafte Staus; Antwortzeiten der Provider begrenzen (Timeouts ~5s, wo sinnvoll; DNSBL: `DNSBL_TIMEOUT_MS`, Default 3000 ms für DNS + Redis zusammen).
- DNSBL‑Lookups dürfen den Event‑Loop nicht blockieren: asynchroner Redis‑Client und nicht‑blockierende DNS‑Auflösung sind verpflichtend. Die bis zu 25 Maskenschlüssel pro IP sollen in einem Roundtrip (MGET/Pipeline) abgefragt werden.

N2. Zuverlässigkeit/Resilienz
- Backoff bei Leerlast/Fehlern; defensive Defaults (z. B. WHOIS‑Fail‑Default, DNSBL‑Fail‑Default). Keine ungebremsten Endlosschleifen.

N3. Sicherheit
- Secret‑Handling via ENV/`.env`; Übertragung nur über HTTPS; `WAECHTER_TOKEN` per Bearer‑Auth; keine Protokollierung sensibler Inhalte. Redis‑Passwort und Verbindungs‑URL werden nicht geloggt.

N4. Wartbarkeit
- Strukturierte Logs (JSON), klare Fehlerklassen, modulare Provider‑Schnittstellen; Konfigurationsdateien versionieren; Tests für Kernlogik. Der DNSBL‑Provider folgt der bestehenden `ScanProvider`‑Schnittstelle; Redis‑Client und DNS‑Auflösung sind für Tests injizierbar.

N5. Observability
- Logs enthalten Korrelationen (`link_id`, Provider, Scores). Optional Metriken (Zähler für Provider‑Aufrufe/Fehler, DNSBL‑Hits/Misses).

## 6. Schnittstellen

- Interne Backend‑API: wie in README beschrieben (Health, Pending, Scan‑Result, Release‑Stale).
- Externe Provider:
  - Google Safe Browsing: HTTP API mit API‑Key, Quotenbeachtung.
  - ClamAV: lokaler Socket (`INSTREAM`), Rechte und Pfad müssen konfiguriert sein.
  - WHOIS: Abfragen über `python-whois` gegen Registrare (Rate‑Limits/Bans beachten).
  - DNSBL/Redis: Redis‑Datenbank mit UCEPROTECT‑Level‑3‑Daten. Schlüsselschema `u-{mask}:{net_int}` (Maske 8..32), Wert JSON `[isp_name, asn, spamscore]`. Lesezugriff per asynchronem Redis‑Client; Verbindung konfigurierbar über `DNSBL_REDIS_URL` (kann eine separate Instanz/DB sein) und optional `DNSBL_REDIS_PASSWORD`.
  - DNS: Namensauflösung der A‑Records (IPv4) über die System‑/Konfigurations‑Resolver. IPv6/AAAA wird nicht ausgewertet, da die UCEPROTECT‑Daten IPv4‑only sind.

## 7. Betrieb/Deployment

- Konfiguration per `.env` und `config/waechter.yaml`; bei systemd über `EnvironmentFile` einbinden.
- Start: venv aktivieren, `python main.py` ausführen; Logging‑Level via `LOG_LEVEL`.
- ClamAV: Dienst aktiv und Socket zugreifbar; Größen‑/Redirect‑Limits im Provider beachten.
- DNSBL: Redis‑Instanz mit befüllter UCEPROTECT‑Liste erreichbar; `DNSBL_ENABLED=true` zum Aktivieren.

## 8. Test und Abnahme

- Unit‑Tests decken Aggregation, Heuristik und Provider‑Schnittstellen ab; externe Provider können testseitig markiert/ausgeschaltet werden.
- Abnahmekriterien (Beispiele):
  - Aggregationsformel liefert erwartete Ergebnisse für definierte Testvektoren.
  - Heuristik erkennt Punycode/IP‑Hosts/verdächtige TLDs/Brand‑Imitationen gemäß Testdaten.
  - ClamAV meldet Treffer (Eicar‑Signatur) und respektiert Limits.
  - DNSBL: gelistete IP führt zu `raw_score > 0` und liefert ISP/ASN/Maske im `raw_response`; nicht gelistete IP führt zu `raw_score = 0.0`; der spezifischste Maskentreffer (größte Maske) gewinnt; bei nicht erreichbarem Redis bzw. DNS‑Fehler neutraler Default‑Score 0.0 ohne Scan‑Abbruch; IP‑Literal‑Hosts überspringen die DNS‑Auflösung; private/reservierte IPs werden ausgefiltert.
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

4. DNSBL: False-Positive-Risiko UCEPROTECT Level 3

UCEPROTECT Level 3 ist eine ASN‑weite Blockliste: Wird eine kritische Menge an Spam aus einem Autonomen System gemeldet, kann das gesamte AS gelistet werden – inklusive legitimer Sites, die nur zufällig beim selben Hoster/Provider liegen. Ein einzelnes L3‑Listing ist daher ein schwaches Einzelsignal mit erhöhter False‑Positive‑Quote.

Maßnahmen:
- Moderates Aggregationsgewicht (`DNSBL_WEIGHT`, Default 0.6): L3‑Treffer soll `warning` mit auslösen können, aber nicht allein `blocked` erzwingen.
- Optional konfigurierbare CDN-/Großanbieter‑Allowlist (z. B. Cloudflare), um bekannte False‑Positive‑Bereiche auszunehmen.
- `raw_response` transparent halten (aufgelöste IPs, ISP, ASN, getroffene Maske), damit Backend/Review nachvollziehen können, warum gelistet wurde.

5. DNSBL: fehlender DNS-Auflösungs-Cache

Mehrere Links auf dieselbe Domain lösen denselben Hostnamen wiederholt auf. Ein kurzlebiger DNS‑Cache (oder die Wiederverwendung eines gemeinsamen Resolvers mit Heuristik) reduziert externe DNS‑Roundtrips. Bewertung als Verbesserung, nicht als Blocker für die erste Umsetzung.

## 10. Anhänge/Quellen

- README.md (Install, Konfiguration, API)
- status.md (Umsetzungsstand)
- agents.md (Agenten-/Betriebsdokumentation)
- prompt_dnsbl_provider.md (Implementierungs‑Prompt DNSBL‑Provider)
- Quellcode: `src/waechter/*` (Loop, Providers, Aggregation, Logger, Types, Config)