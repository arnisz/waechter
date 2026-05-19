import json
import hashlib
import logging
from typing import Any, Dict

import aiohttp

try:
    import redis.asyncio as redis
except ImportError:
    redis = None

from waechter.providers.base import QuotaAwareProvider
from waechter.config_loader import as_bool, provider_cfg, cfg_get

logger = logging.getLogger(__name__)


class PhishStatsProvider(QuotaAwareProvider):
    """
    PhishStats Provider für Waechter.
    
    Fragt die kostenfreie Community-Datenbank von PhishStats ab.
    Da die Schnittstelle offen ist, wird kein API-Key benötigt.
    """

    # ------------------------------------------------------------------
    # Klassenattribute
    # ------------------------------------------------------------------

    name: str = "phishstats"
    weight: float = 0.7
    daily_limit: int = 10_000  # Großzügiges Limit für freie IP-Abfragen

    # ------------------------------------------------------------------
    # Konstruktor
    # ------------------------------------------------------------------

    def __init__(self, api_key: str = ""):
        """
        Initialisiert den PhishStats-Provider.
        Da kein API-Key benötigt wird, wird der Parameter ignoriert.
        """
        super().__init__()

        cfg = provider_cfg(self.name)

        # ── Konfigurierbare Basisparameter ────────────────────────────
        self.weight = float(cfg.get("weight", self.weight))
        self.daily_limit = int((cfg.get("api", {}) or {}).get("daily_limit", self.daily_limit))

        # ── Credentials & Aktivierung ─────────────────────────────────
        # PhishStats benötigt keinen API-Key! Der Provider ist aktiv, 
        # solange er in der Config nicht explizit auf 'false' gesetzt wurde.
        self.enabled: bool = as_bool(cfg.get("enabled", True))

        # ── Redis-Cache (optional) ────────────────────────────────────
        self.redis_client = None
        self.redis_ttl: int = 3600  # Fallback: 1 Stunde

        redis_cfg = cfg_get("redis", {})
        if redis and as_bool(redis_cfg.get("enabled", False)):
            redis_url = redis_cfg.get("url")
            if redis_url:
                try:
                    self.redis_client = redis.from_url(redis_url, decode_responses=True)
                    self.redis_ttl = int(redis_cfg.get("ttl_sec", self.redis_ttl))
                    logger.info(
                        "%s: Redis-Cache aktiviert",
                        self.name,
                        extra={"extra_data": {"url": redis_url, "ttl": self.redis_ttl}},
                    )
                except Exception as exc:
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
        
        # ── 1. Early-Exit ─────────────────────────────────────────────
        if not self.enabled:
            return {"raw_score": 0.0}

        # ── 2. Cache-Lookup ───────────────────────────────────────────
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
                logger.warning("%s: Redis get-Fehler: %s", self.name, exc)

        # ── 3. Quota-Check ────────────────────────────────────────────
        self.check_and_increment_quota()

        # ── 4. HTTP-Request ───────────────────────────────────────────
        # Nutzt den dynamischen Filter-Operator '_where' der PhishStats API
        api_url = "https://api.phishstats.info/api/phishing"
        params = {
            "_where": f"(url,eq,{url})"
        }

        try:
            # aiohttp übernimmt hier automatisch das URL-Encoding der Klammern und der Ziel-URL
            async with session.get(api_url, params=params) as resp:
                resp.raise_for_status() 
                data = await resp.json()

            # ── 5. Normalisierung ──────────────────────────────────────
            result: Dict[str, Any] = {"raw_score": 0.0}
            
            # PhishStats gibt bei einem Treffer ein JSON-Array der Datensätze zurück.
            # Ist das Array befüllt, ist die URL verifiziertes Phishing.
            if isinstance(data, list) and len(data) > 0:
                result = {
                    "raw_score": 1.0,
                    "raw_response": json.dumps(data),
                }

            # ── 6. Cache befüllen ──────────────────────────────────────
            if self.redis_client and cache_key:
                try:
                    await self.redis_client.set(
                        cache_key, json.dumps(result), ex=self.redis_ttl
                    )
                except Exception as exc:
                    logger.warning("%s: Redis set-Fehler: %s", self.name, exc)

            # ── 7. Ergebnis zurückgeben ────────────────────────────────
            return result

        except Exception as exc:
            # Fail-open
            logger.error("%s: Request fehlgeschlagen: %s", self.name, exc)
            return {"raw_score": 0.0, "error": str(exc)}
