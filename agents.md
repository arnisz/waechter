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

### 3.1 Schnittstellenvertrag zwischen Wächter und Link‑Verkürzer

Der Wächter ist der Worker für den Link‑Verkürzer. Der Link‑Verkürzer besitzt die Datenbank, verwaltet Claims und stellt interne HTTP‑Endpunkte bereit; der Wächter fragt diese Endpunkte ab, führt die Sicherheitsprüfung aus und schreibt ausschließlich über die API zurück.

**Authentifizierung und Basis‑URL**
- Alle internen Requests gehen an `WORKER_BASE_URL` und nutzen `Authorization: Bearer <WAECHTER_TOKEN>`.
- `401 Unauthorized` gilt als Konfigurations-/Secret‑Fehler und beendet den Worker frühzeitig.

**Boot/Health**
- `GET /api/internal/health` prüft beim Start, ob die Gegenstelle erreichbar ist.
- `POST /api/internal/links/release-stale` gibt verwaiste Claims frei. Vorgesehen ist der Aufruf beim Boot und danach periodisch, damit nach Worker‑Crashes keine Links dauerhaft `claimed` bleiben.

**Pending‑Links / Claiming**
- `GET /api/internal/links/pending?limit=<BATCH_SIZE>` liefert bereits von der Gegenstelle geclaimte Links im Format `PendingLink`:
  - `id`: stabile 32‑Zeichen‑Hex‑ID; wird für API‑Calls verwendet.
  - `short_code`: nur für Logging/Diagnose; nicht als Primärschlüssel verwenden.
  - `target_url`: zu prüfende Ziel‑URL.
  - `created_at`: ISO‑Zeitstempel.
- Der Wächter setzt Claims nicht direkt in der Datenbank, sondern verlässt sich auf das Claiming der Gegenstelle beim Pending‑Abruf.

**Scan‑Ergebnis**
- Nach Provider‑Ausführung und Aggregation sendet der Wächter `POST /api/internal/links/{id}/scan-result` mit:
  - `aggregate_score`: berechneter Gesamtscore, auf eine endliche Zahl normalisiert und gerundet.
  - `status`: `active`, `warning` oder `blocked` gemäß `THRESHOLD_WARNING`/`THRESHOLD_BLOCK`.
  - `scans`: eine Zeile pro erfolgreichem Provider‑Ergebnis mit `provider`, `raw_score`, `raw_response`.
- `raw_response` ist `null`, wenn der Provider‑Score unter `0.3` liegt oder keine Rohdaten vorliegen. Komplexe Rohdaten (`dict`/`list`) werden vor dem Senden als gültiger JSON‑String serialisiert, damit das Gegenstellen‑Interface `string | null` erfüllt wird.
- Interne Aggregationsgewichte (`weight`) werden nicht an die Gegenstelle übertragen; sie dienen nur der lokalen Score‑Berechnung.

**Erwartetes Verhalten der Gegenstelle nach erfolgreichem POST**
- Die Gegenstelle markiert den Link als geprüft (`checked=1`), speichert `spam_score`, `status` und `last_checked_at`, setzt `claimed_at=NULL`, legt Provider‑Zeilen in `security_scans` an und invalidiert den Link‑Cache (`LINKS_KV.delete("link:" + short_code)`).
- `200 OK` mit `{ "ok": true }` bedeutet: Ergebnis wurde übernommen.
- `404` bedeutet: Link nicht gefunden oder `manual_override=1`; der Wächter ignoriert diesen Fall bewusst, weil manuell übersteuerte Links nicht überschrieben werden sollen.
- Andere `4xx`/`5xx`‑Antworten gelten als Fehler. Der Wächter loggt Status und Antworttext, damit Payload‑ oder Validierungsprobleme der Gegenstelle nachvollziehbar sind.

**Fehler- und Recovery‑Semantik**
- Wenn das Posten des Ergebnisses fehlschlägt, bleibt der Link auf Gegenstellen‑Seite typischerweise geclaimt und ungeprüft. Das ist beabsichtigt: `release-stale` gibt Claims nach Ablauf des Backend‑Timeouts wieder frei, sodass der Link erneut in `pending` auftauchen kann.
- Provider‑Fehler verhindern nicht automatisch den gesamten Scan; erfolgreiche Provider‑Resultate werden weiter aggregiert. Wenn alle Provider fehlschlagen oder deaktiviert sind, wird kein Ergebnis gepostet.

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
- Aktueller Audit-Hinweis: Die Implementierung enthält zusätzlich `PhishStatsProvider` und `ScreenshotProvider`. Beide können im Betrieb zusätzliche Fehlerquellen erzeugen und müssen im nächsten Implementierungsschritt vollständig dokumentiert oder standardmäßig deaktiviert werden.
- PhishStats erzeugt ausgehende Requests zu `api.phishstats.info`; dieser Egress muss in Firewall-/NAT-Umgebungen bewusst erlaubt oder per `PHISHSTATS_ENABLED=false` deaktiviert werden.
- Screenshot benötigt Playwright/Chromium plus Debian-Systembibliotheken. Ohne Browser-Installation schlägt der Provider zur Laufzeit fehl; mit Browser-Scanning entstehen SSRF-/Egress- und Browser-Isolationsrisiken, da Zielseiten hinter der Firewall/NAT geladen werden.
- Debian-Betrieb hinter Firewall/IPv4-NAT ist grundsätzlich möglich, weil keine eingehenden öffentlichen Ports benötigt werden. Erforderlich sind kontrollierte ausgehende Verbindungen zum Backend und zu bewusst aktivierten externen Providern; interne Netze/Metadata-Adressen sollten für Content-Download- und Screenshot-Provider per Firewall blockiert werden.
- Skalierung: Mehrere Worker‑Instanzen möglich; Backend sollte Idempotenz/Claiming sicherstellen.

## 8. Tests

- Pytest‑Suite vorhanden (u. a. Aggregation, Provider‑Heuristik). Externe Provider‑Tests (GSB/ClamAV/DNSBL) können marker‑basiert ausgeschlossen werden; der DNSBL‑Test arbeitet mit gemocktem Redis‑Client und gemockter DNS‑Auflösung.
- Aktuelle Verifikation: `pytest tests` läuft grün mit 67 Tests.
- Test-Hygiene: In `tests/test_providers.py` war ein kopierter Godaddy-Block versehentlich an `test_heuristic_provider_gmail_low_risk` angehängt. Dieser Rest wurde entfernt, damit der Test wieder nur seine eigentliche Aussage prüft.
- Modul-Hygiene: Das TypedDict-Modul wurde aus dem Repo-Root nach `src/waechter/types.py` verschoben, damit es die Standardbibliothek `types` nicht mehr schatten kann.
- Datenpflege: `brand_domains.csv` und `brand_domains.csv.example` wurden um `netflix.com` und `disney.com` ergänzt, um die Brand-Context-Tests an die aktuelle Datenlage anzupassen.
- Rest-Risiko im Repo-Root: `test_redis.py` enthält Top-Level-Code. Wenn künftig wieder ein Root-`pytest`-Lauf statt `pytest tests` verwendet wird, sollte dieses Skript umbenannt oder mit `if __name__ == "__main__":` geschützt werden.

## 9. Bekannte Verbesserungspunkte (Auszug)

- Konfigurations-/Dokumentationskonsistenz: README, `.env.example`, `config/waechter.yaml`, Installer und Provider-Code sind für `DNSBL_*`, `CLAMAV_*`, `PHISHSTATS_*`, `SCREENSHOT_*`, Redis-Cache-Variablen und Defaults zu vereinheitlichen.
- Debian-Installationspfad: Playwright/Chromium-Installation, Systembibliotheken, systemd-Hardening und klare Provider-Defaults ergänzen; frische Installation muss ohne manuelle Nacharbeit starten oder optionale Provider sauber deaktivieren.
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
