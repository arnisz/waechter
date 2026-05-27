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
    - `DnsblProvider` – optional, `DNSBL_ENABLED=true`; löst den Hostnamen der URL auf und prüft die IPv4‑Adressen gegen die UCEPROTECT‑Level‑3‑Liste in einer Redis‑Datenbank.

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
  - DNSBL: `DNSBL_ENABLED`, `DNSBL_REDIS_URL`, `DNSBL_REDIS_PASSWORD`, `DNSBL_TIMEOUT_MS`, `DNSBL_MAX_IPS`, `DNSBL_SCORE_LISTED`, `DNSBL_USE_SPAMSCORE`, `DNSBL_WEIGHT`
  - Betriebsparameter: `SCAN_CONCURRENCY`, `BATCH_SIZE`, `MIN_WAIT_MS`, `MAX_WAIT_MS`, `LOG_LEVEL`, `THRESHOLD_WARNING`, `THRESHOLD_BLOCK`
- YAML (`config/waechter.yaml`) ergänzt/überschreibt feingranular Provider‑Einstellungen (Gewichte, Grenzwerte, Keyword‑Dateien). ENV hat Vorrang vor YAML.

## 5. Provider – Details (Heuristik & DNSBL)

### 5.1 Heuristik

Der `HeuristicProvider` (Improvement v2) nutzt u. a.:
- **Globale Trusted-Domain Allowlist**: Domains in `trusted_domains` (Konfiguration) führen sofort zu einem Score von 0.0.
- **Entkoppelte Erkennung offizieller Domains**: Domains in `brand_domains.csv` werden auch ohne Keyword-Treffer als offiziell erkannt (hilfreich für Infrastruktur-Domains wie `googleapis.com`).
- **Subdomain-Heuristik**: Erkennt zufällig aussehende Labels (Entropie-Check) und ungewöhnlich lange/tiefe Subdomain-Strukturen.
- **Brand‑Kontext**: Keywords (`brand_keywords.csv`) + offizielle Domains (`brand_domains.csv`, Modi `etld1`, `exact`, `subdomain_of`).
- **Identity-Provider Awareness**: Cross-Domain Form-Actions zu bekannten Providern (Google, Microsoft, etc.) werden deutlich geringer bestraft als unbekannte Cross-Domain Ziele.
- **WHOIS-Optimierung**: Überspringt WHOIS-Abfragen für bekannte Hosting-Plattformen (z.B. `workers.dev`, `vercel.app`), da das Alter der Basis-Domain hier nicht aussagekräftig für die Subdomain ist.
- **Transparente Ergebnisse**: Das Feld `reasons` enthält für jeden erkannten Signal-Typ eine menschenlesbare Erklärung inkl. des jeweiligen Score-Beitrags.
- Hostname‑Normalisierung und Punycode‑Erkennung.
- IP‑Adressen als Host.
- Verdächtige TLD‑Liste.
- Sehr lange URLs.
- Pfad‑ und URL‑Keywords (`path_keywords.csv`, `url_keywords.csv`).
- Redirect‑Heuristiken (Anzahl, Domain‑Mismatch, Redirect auf IP).
- HTML‑Signale (Formular + Passwort/Email, XHR/fetch).

Hinweis zu WHOIS: Aktuell erfolgt die Abfrage pro registrierbarer Basis‑Domain synchron via `python-whois` im Thread‑Pool (siehe `_check_whois_age`). Ein explizites Cache‑Layer ist noch nicht implementiert (siehe Pflichtenheft, Punkt 3).

### 5.2 DNSBL (UCEPROTECT Level 3)

Der `DnsblProvider` (`src/waechter/providers/dnsbl.py`) ist optional und nur aktiv bei `DNSBL_ENABLED=true`.

Ablauf:
1. Hostname aus `target_url` extrahieren; IDN/Unicode‑Hosts nach Punycode/ASCII konvertieren.
2. Asynchrone DNS‑Auflösung der A‑Records (IPv4). Ist der Host bereits ein IP‑Literal, entfällt die Auflösung.
3. IPv6/AAAA werden übersprungen – die UCEPROTECT‑Redis‑Daten sind IPv4‑only (32‑Bit‑Maske). Private/loopback/reservierte IPs werden herausgefiltert.
4. Für jede verbleibende IPv4 ein Lookup gegen Redis: absteigende Netzmasken von /32 bis /8, Schlüssel `u-{mask}:{net_int}` mit `net_int = ip_int & (0xFFFFFFFF << (32 - mask))`. Treffer ist der spezifischste vorhandene Schlüssel; der Wert ist JSON `[isp_name, asn, spamscore]`.
5. Score und `raw_response` (aufgelöste IPs, gelistete IPs, ISP/ASN/Maske, Quelle) werden gebildet.

Score‑Mapping:
- Keine IP gelistet → `raw_score = 0.0`.
- Mindestens eine IP gelistet → `raw_score = DNSBL_SCORE_LISTED` (Default `0.6`).
- DNS‑/Redis‑Fehler, nur IPv6, nur private IPs → neutraler Default `0.0` (keine Bestrafung), Grund im `raw_response`.
- Optional (`DNSBL_USE_SPAMSCORE`, Default `false`) Skalierung anhand des `spamscore`.

Wichtiger Hinweis: UCEPROTECT Level 3 listet ganze Autonome Systeme (ASN‑weit) und erzeugt dadurch relativ viele False Positives für legitime Sites auf betroffenem Shared Hosting. Der Provider ist daher als „Warnsignal, nicht Alleinblocker" konzipiert; das Aggregationsgewicht `DNSBL_WEIGHT` ist bewusst moderat (Default `0.6`).

## 6. Fehler‑ und Quotenbehandlung

- Provider dürfen `QuotaExhaustedError` auslösen; der Loop protokolliert Warnungen und fährt mit anderen Providern fort.
- Netzwerkfehler/Timeouts führen zu defensiven Defaults (z. B. WHOIS‑Fail‑Default, HTML‑Analyse best‑effort, DNSBL neutraler Score 0.0 bei DNS‑/Redis‑Fehler).
- Bei `401 Unauthorized` beendet der Worker den Prozess frühzeitig.

## 7. Betrieb und Deployment

- Single‑Binary Start: `python main.py` (nach Aktivierung des venv)
- Logging: `LOG_LEVEL=DEBUG` für Diagnose; bei systemd werden ENV nicht vom Shell‑Kontext geerbt → `EnvironmentFile` benutzen.
- ClamAV: `clamd` muss laufen und Socket‑Pfad muss passen; Größen‑ und Redirect‑Limits beachten.
- DNSBL: Eine Redis‑Instanz mit befüllter UCEPROTECT‑Level‑3‑Liste muss erreichbar sein (`DNSBL_REDIS_URL`). Das Befüllen der Liste liegt außerhalb des Worker‑Scopes; der Provider liest nur. Redis kann eine separate Instanz/DB sein.
- Skalierung: Mehrere Worker‑Instanzen möglich; Backend sollte Idempotenz/Claiming sicherstellen.

## 8. Tests

- Pytest‑Suite vorhanden (u. a. Aggregation, Provider‑Heuristik). Externe Provider‑Tests (GSB/ClamAV/DNSBL) können marker‑basiert ausgeschlossen werden; der DNSBL‑Test arbeitet mit gemocktem Redis‑Client und gemockter DNS‑Auflösung.

## 9. Bekannte Verbesserungspunkte (Auszug)

- WHOIS‑Caching (siehe Pflichtenheft, Punkt „3. WHOIS‑Caching fehlt"): eTLD+1‑Schlüssel, TTL ~24h, In‑Memory oder Redis zur Vermeidung von Registrar‑IP‑Bans.
- DNS‑Auflösungs‑Cache für den DNSBL‑Provider: Mehrere Links derselben Domain lösen denselben Host wiederholt auf; ein kurzlebiger Cache (oder Wiederverwendung des Heuristik‑Resolvers) spart externe DNS‑Roundtrips.
- CDN‑Allowlist für DNSBL: Bekannte CDN‑/Großanbieter‑Bereiche (z. B. Cloudflare) können in L3 gelistet sein und False Positives erzeugen; optionale Allowlist erwägen.
- Metriken/Observability: Zähler für Provider‑Aufrufe, Fehlerraten, Redirect‑Verteilungen, DNSBL‑Hits/Misses, durchschnittliche Aggregat‑Scores.
- Circuit‑Breaker/Rate‑Limit für externe Dienste.

## 10. Quellen

- README.md (Install, Konfiguration, API, Betrieb)
- status.md (Umsetzungsstand)
- prompt_dnsbl_provider.md (Implementierungs‑Prompt DNSBL‑Provider)
- Code: `src/waechter/*` (Loop, Providers, Aggregation, Logger, Types, Config)