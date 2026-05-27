Abstrahierte Provider-Architektur zu wiederverwendbarem Template

python

```python
"""
Provider Blueprint – Waechter URL-Scanner Framework
====================================================

Generischer Bauplan für alle Scanner-Provider.
Jeder konkrete Provider erbt von QuotaAwareProvider und implementiert
die scan()-Methode gemäß dem hier beschriebenen Muster.

Mindest-Checkliste für einen neuen Provider:
  [x] Klasse erbt von QuotaAwareProvider
  [x] name, weight, daily_limit als Klassenattribute
  [x] __init__: Konfiguration laden, masked key loggen, Redis optional initialisieren
  [x] Redis-Konfiguration: Env-Vars haben Vorrang vor YAML-Config
  [x] scan(): Cache-Lookup → Quota → HTTP → Status prüfen → Normalisieren
              → Cache befüllen → result zurückgeben
  [x] HTTP-Fehler (4xx/5xx) explizit vor resp.json() abfangen
  [x] Rückgabeformat: {"raw_score": float} + optionale Felder
  [x] Strukturiertes Logging mit snake_case Event-Namen
"""

import json
import hashlib
import logging
import os
from typing import Any, Dict

import aiohttp

try:
    import redis.asyncio as redis
except ImportError:
    # Redis ist optional. Ist das Paket nicht installiert, bleibt Caching deaktiviert.
    redis = None

from waechter.providers.base import QuotaAwareProvider
from waechter.config_loader import as_bool, provider_cfg, cfg_get

logger = logging.getLogger(__name__)


class ProviderTemplate(QuotaAwareProvider):
    """
    Generischer Bauplan für einen Waechter-Provider.

    Jeder Provider kapselt genau eine externe Scan-API. Er ist zuständig für:
      - Konfiguration (API-Key, Gewichtung, Limits)
      - sicheres Logging des API-Keys (nur maskiert, niemals im Klartext)
      - optionales Redis-Caching zur Schonung der API-Quota
      - Quota-Verwaltung via Basisklasse
      - den eigentlichen HTTP-Call inkl. expliziter Fehlerbehandlung
      - Normalisierung der Antwort auf das interne Ergebnisformat

    Namenskonvention:
      - Klassenname:   <ServiceName>Provider  (z. B. VirusTotalProvider)
      - name-Attribut: snake_case des Dienstnamens (z. B. "virustotal")
        → muss exakt mit dem Schlüssel in der YAML-Konfiguration übereinstimmen
    """

    # ------------------------------------------------------------------
    # Klassenattribute – werden durch provider_cfg() zur Laufzeit überschrieben
    # ------------------------------------------------------------------

    #: Eindeutiger Bezeichner; muss mit dem YAML-Konfigurationsschlüssel übereinstimmen.
    name: str = "provider_template"

    #: Gewichtung im Score-Aggregator (0.0 – 1.0).
    weight: float = 1.0

    #: Maximale API-Aufrufe pro Tag. Wird von QuotaAwareProvider überwacht.
    daily_limit: int = 10_000

    # ------------------------------------------------------------------
    # Konstruktor
    # ------------------------------------------------------------------

    def __init__(self, api_key: str):
        """
        Initialisiert den Provider.

        Reihenfolge der Initialisierungsschritte:
          1. Basisklasse (Quota-Zähler etc.)
          2. Providerspezifische Konfiguration aus YAML laden
          3. API-Credentials setzen + maskierten Key für sicheres Logging vorbereiten
          4. Enabled-Flag auswerten (Config UND vorhandener Key)
          5. Init-Zustand loggen (mit maskiertem Key, nie im Klartext)
          6. Redis-Cache optional aufbauen (Env-Vars > YAML-Config)

        Args:
            api_key: Wird typischerweise aus einer Umgebungsvariable oder
                     dem Secret-Store übergeben, nicht aus der YAML.
        """
        super().__init__()

        # Lädt den zum `name` passenden Abschnitt aus der Konfigurationsdatei.
        cfg = provider_cfg(self.name)

        # ── Konfigurierbare Basisparameter ────────────────────────────
        self.weight = float(cfg.get("weight", self.weight))
        self.daily_limit = int((cfg.get("api", {}) or {}).get("daily_limit", self.daily_limit))

        # ── Provider-spezifische Parameter ────────────────────────────
        # Beispiel: Client-Identifikation für APIs, die das verlangen.
        # Nicht benötigte Parameter hier entfernen oder durch eigene ersetzen.
        client_cfg = (cfg.get("api", {}) or {}).get("client", {}) or {}
        self.client_id: str = str(client_cfg.get("id", "waechter"))
        self.client_version: str = str(client_cfg.get("version", "1.0.0"))

        # ── Credentials ───────────────────────────────────────────────
        self.api_key = api_key

        # Maskierter Key für sicheres Logging: "abcd…wxyz" bzw. Fehlerfall-Marker.
        # Regel: Niemals den API-Key im Klartext in Log-Ausgaben schreiben.
        if len(api_key) >= 8:
            self._masked_key = api_key[:4] + "…" + api_key[-4:]
        elif not api_key:
            self._masked_key = "(not set)"
        else:
            self._masked_key = "(too short)"

        # Provider ist nur aktiv, wenn er in der Config aktiviert ist
        # UND ein API-Key vorhanden ist – beides muss erfüllt sein.
        self.enabled: bool = as_bool(cfg.get("enabled", True)) and bool(self.api_key)

        # ── Init-Logging ──────────────────────────────────────────────
        # Wird einmal beim Start ausgegeben, um Konfigurationsprobleme
        # (falscher Key, Provider versehentlich deaktiviert) sofort sichtbar zu machen.
        logger.info(
            f"{self.name}_init",
            extra={"extra_data": {
                "enabled": self.enabled,
                "api_key_masked": self._masked_key,
            }},
        )

        # ── Redis-Cache (optional) ─────────────────────────────────────
        # Konfigurationsreihenfolge (höchste Priorität zuerst):
        #   1. Umgebungsvariablen (REDIS_ENABLED, REDIS_URL, REDIS_TTL_SEC)
        #   2. Globaler "redis"-Abschnitt in der YAML-Config
        #
        # Env-Vars ermöglichen Deployment-spezifische Overrides (z. B. Docker/K8s)
        # ohne die Konfigurationsdatei anzufassen.
        #
        # Alle Provider teilen sich dieselbe Redis-Instanz, unterscheiden sich
        # aber durch ihren Cache-Key-Präfix (→ scan()).
        self.redis_client = None
        self.redis_ttl: int = 21_600  # Fallback: 6 Stunden

        redis_cfg = cfg_get("redis", {})

        # Env-Var überschreibt YAML; fehlt sie, gilt YAML-Wert (Default: False)
        redis_enabled_env = os.environ.get("REDIS_ENABLED")
        redis_enabled = (
            as_bool(redis_enabled_env)
            if redis_enabled_env is not None
            else as_bool(redis_cfg.get("enabled", False))
        )

        if redis and redis_enabled:
            # Env-Var überschreibt YAML-URL
            redis_url = os.environ.get("REDIS_URL") or redis_cfg.get("url")
            if redis_url:
                try:
                    self.redis_client = redis.from_url(redis_url, decode_responses=True)

                    # Env-Var überschreibt YAML-TTL
                    ttl_env = os.environ.get("REDIS_TTL_SEC")
                    self.redis_ttl = (
                        int(ttl_env)
                        if ttl_env is not None
                        else int(redis_cfg.get("ttl_sec", self.redis_ttl))
                    )

                    logger.info(
                        f"{self.name}_redis_enabled",
                        extra={"extra_data": {"url": redis_url, "ttl": self.redis_ttl}},
                    )
                except Exception as exc:
                    # Redis-Fehler sind nicht kritisch – Provider läuft ohne Cache weiter.
                    logger.warning("%s: Redis-Verbindung fehlgeschlagen: %s", self.name, exc)
                    self.redis_client = None

    # ------------------------------------------------------------------
    # Haupt-Methode
    # ------------------------------------------------------------------

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        link_id: str | None = None,
    ) -> Dict[str, Any]:
        """
        Scannt eine URL mit der externen API dieses Providers.

        Ablauf (immer in dieser Reihenfolge):
          1. Early-Exit wenn Provider deaktiviert
          2. Cache-Lookup       → bei Treffer sofort zurückgeben
          3. Quota prüfen & inkrementieren
          4. HTTP-Request
          5. HTTP-Statuscode prüfen (4xx/5xx vor resp.json() abfangen!)
          6. Antwort normalisieren → result-Dict + strukturiertes Logging
          7. Ergebnis in Cache schreiben
          8. result-Dict zurückgeben

        Args:
            url:     Die zu prüfende URL.
            session: Gemeinsame aiohttp-Session des Scanners (wird nicht geschlossen).
            link_id: Optionale interne ID für Logging/Tracing.

        Returns:
            Dict mit mindestens:
              - "raw_score" (float, 0.0–1.0):
                    0.0 = unbedenklich / kein Fund
                    1.0 = Bedrohung erkannt
                    Zwischenwerte sind erlaubt (z. B. Confidence-Score).
            Optional zusätzlich:
              - "raw_response" (str): Rohantwort als JSON-String (für Debugging).
              - "error"        (str): Fehlerbeschreibung; raw_score ist dann 0.0
                                      (fail-open – ein API-Ausfall sperrt keine URLs).
        """
        # ── 1. Early-Exit ─────────────────────────────────────────────
        if not self.enabled:
            return {"raw_score": 0.0}

        # ── 2. Cache-Lookup ───────────────────────────────────────────
        # URL wird gehasht → kurze, kollisionsfreie Keys auch bei langen URLs.
        # Präfix "<name>_cache:" verhindert Kollisionen zwischen Providern,
        # die sich dieselbe Redis-Instanz teilen.
        cache_key = None
        if self.redis_client:
            try:
                url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
                cache_key = f"{self.name}_cache:{url_hash}"
                cached = await self.redis_client.get(cache_key)
                if cached:
                    logger.debug("%s: Cache-Treffer für %s", self.name, url)
                    return json.loads(cached)
            except Exception as exc:
                # Cache-Fehler nie propagieren – im Zweifel API direkt aufrufen.
                logger.warning(f"{self.name}_redis_get_error", extra={"extra_data": {"error": str(exc)}})

        # ── 3. Quota-Check ────────────────────────────────────────────
        # Wirft QuotaExceededError wenn daily_limit erreicht ist.
        # Der Scanner-Core fängt diesen Fehler und überspringt den Provider.
        self.check_and_increment_quota()

        # ── 4. HTTP-Request ───────────────────────────────────────────
        # TODO: API-Endpunkt, Payload-Struktur und Auth-Mechanismus anpassen.
        api_url = f"https://api.example.com/v1/scan?key={self.api_key}"
        payload = {
            "client": {
                "clientId": self.client_id,
                "clientVersion": self.client_version,
            },
            "target": {"url": url},  # TODO: URL-Einbettung an API anpassen
        }

        try:
            async with session.post(api_url, json=payload) as resp:

                # ── 5. HTTP-Fehlerbehandlung ───────────────────────────
                # WICHTIG: Status vor resp.json() prüfen!
                # Bei 4xx/5xx liefert die API oft kein valides JSON,
                # sondern eine HTML-Fehlerseite → json()-Aufruf würde werfen.
                # Außerdem unterscheiden sich Fehlerursachen (401 = Key ungültig,
                # 429 = Rate-Limit, 5xx = API-Ausfall) und sollten separat geloggt werden.
                status = resp.status
                if status >= 400:
                    body = await resp.text()
                    logger.error(
                        f"{self.name}_http_error",
                        extra={"extra_data": {
                            "http_status": status,
                            "api_key_masked": self._masked_key,
                            # Nur Preview loggen – Antwort kann sehr groß sein
                            "response_preview": body[:300],
                        }},
                    )
                    return {"raw_score": 0.0, "error": f"http_{status}"}

                data = await resp.json()

            # ── 6. Normalisierung & Logging ────────────────────────────
            # TODO: Antwortstruktur der Ziel-API hier auswerten.
            #
            # Muster:
            #   - Bedrohung gefunden → raw_score = 1.0, raw_response speichern,
            #     WARNING mit strukturierten Threat-Infos loggen
            #   - Kein Fund          → raw_score = 0.0,
            #     DEBUG mit cached=False loggen (unterscheidbar von Cache-Hits)

            matches = data.get("matches") or []  # TODO: Feldname anpassen

            if matches:
                result: Dict[str, Any] = {
                    "raw_score": 1.0,
                    "raw_response": json.dumps(data),
                }
                logger.warning(
                    f"{self.name}_threat_found",
                    extra={"extra_data": {
                        "url": url,
                        "match_count": len(matches),
                        # TODO: relevante Felder aus matches extrahieren
                        "threat_types": list({m.get("threatType") for m in matches}),
                    }},
                )
            else:
                result = {"raw_score": 0.0}
                logger.debug(
                    f"{self.name}_no_threat",
                    extra={"extra_data": {"url": url, "cached": False}},
                )

            # ── 7. Cache befüllen ──────────────────────────────────────
            if self.redis_client and cache_key:
                try:
                    await self.redis_client.set(
                        cache_key, json.dumps(result), ex=self.redis_ttl
                    )
                except Exception as exc:
                    logger.warning(f"{self.name}_redis_set_error", extra={"extra_data": {"error": str(exc)}})

            # ── 8. Ergebnis zurückgeben ────────────────────────────────
            return result

        except Exception as exc:
            # Fail-open: Ein einzelner API-Ausfall soll keine URLs fälschlicherweise
            # sperren. Fehlertyp loggen erleichtert die Ursachenanalyse.
            logger.error(
                f"{self.name}_request_failed",
                extra={"extra_data": {
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "api_key_masked": self._masked_key,
                }},
            )
            return {"raw_score": 0.0, "error": str(exc)}
```

---

**Was gegenüber dem Original verändert/ergänzt wurde:**

| Bereich             | Änderung                                                                                   |
| ------------------- | ------------------------------------------------------------------------------------------ |
| Klassen-Docstring   | Erklärt Verantwortlichkeiten, Namenskonvention, Vererbung                                  |
| `__init__`-Schritte | Jeder Initialisierungsblock hat einen benannten Kommentarabschnitt                         |
| `enabled`-Logik     | Erklärt warum _beides_ (Config + Key) nötig ist                                            |
| Redis-Präfix        | `{self.name}_cache:` statt hartcodiertem `gsb_cache:` → kollisionssicher für alle Provider |
| `scan()`-Docstring  | Vollständige Args/Returns-Beschreibung inkl. Zwischenwerte                                 |
| Ablaufnummern       | 1–7 im Code mit Erklärung, warum die Reihenfolge so ist                                    |
| Fail-open-Kommentar | Erklärt bewusste Designentscheidung beim Exception-Handling                                |
| `TODO`-Marker       | Kennzeichnen exakt die zwei Stellen, die pro Provider angepasst werden müssen              |

**Alle Änderungen gegenüber der ersten Blueprint-Version:**

| Bereich                       | Was und warum                                                                                   |
| ----------------------------- | ----------------------------------------------------------------------------------------------- |
| `_masked_key`                 | Neu. Key nie im Klartext loggen – der maskierte Wert reicht zur Diagnose                        |
| Init-Logging                  | Neu. Konfigurationsfehler (Key fehlt, Provider disabled) beim Start sofort sichtbar             |
| Redis Env-Vars                | Neu. `REDIS_ENABLED` / `REDIS_URL` / `REDIS_TTL_SEC` überschreiben YAML → Docker/K8s-kompatibel |
| Default TTL                   | 3 600 → **21 600 s** (6 h) – die Redis-DB füllt sich sonst nicht schnell genug                  |
| HTTP-Status-Check             | Neu. `status >= 400` **vor** `resp.json()` prüfen – sonst Exception auf HTML-Fehlerseiten       |
| `matches = data.get(…) or []` | `None`-safe; verhindert `TypeError` bei explizit `null` in der API-Antwort                      |
| Strukturiertes Logging        | Alle Events als `{self.name}_<event>` mit `extra_data`-Dict statt Freitext                      |
| Threat-Logging                | WARNING mit `match_count` + `threat_types` statt stummem Score-Setzen                           |
| No-threat-Logging             | DEBUG mit `cached: False` – unterscheidbar von Cache-Hits im Log                                |
| `response_preview[:300]`      | Große Fehler-Bodies begrenzen, um Log-Flooding zu verhindern                                    |

**Besonderheiten**
Damit die Provider auch aktiviert werden müssen sie Konfigurierbar sein.
models.py, constants.py, env.py, main.py und install.py müssen angepasst werden. Das wird leicht vergessen!