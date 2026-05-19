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


class GoogleSafeBrowsingProvider(QuotaAwareProvider):
    name = "google_safe_browsing"
    weight = 1.0
    daily_limit = 10000

    def __init__(self, api_key: str):
        super().__init__()
        cfg = provider_cfg(self.name)

        # weight and daily limit from config (fallbacks preserve previous behavior)
        self.weight = float(cfg.get("weight", 1.0))
        self.daily_limit = int((cfg.get("api", {}) or {}).get("daily_limit", 10000))

        client = (cfg.get("api", {}) or {}).get("client", {}) or {}
        self.client_id = str(client.get("id", "waechter"))
        self.client_version = str(client.get("version", "1.1.0"))

        self.api_key = api_key
        # enabled flag respects config but requires an API key
        self.enabled = as_bool(cfg.get("enabled", True)) and bool(self.api_key)

        # Optional Redis Cache
        self.redis_client = None
        self.redis_ttl = 21600
        
        redis_cfg = cfg_get("redis", {})
        
        import os
        redis_enabled_env = os.environ.get("REDIS_ENABLED")
        if redis_enabled_env is not None:
            redis_enabled = as_bool(redis_enabled_env)
        else:
            redis_enabled = as_bool(redis_cfg.get("enabled", False))

        if redis and redis_enabled:
            url_redis = os.environ.get("REDIS_URL", redis_cfg.get("url"))
            if url_redis:
                try:
                    self.redis_client = redis.from_url(url_redis, decode_responses=True)
                    
                    ttl_env = os.environ.get("REDIS_TTL_SEC")
                    if ttl_env is not None:
                        self.redis_ttl = int(ttl_env)
                    else:
                        self.redis_ttl = int(redis_cfg.get("ttl_sec", 21600))
                        
                    logger.info("GoogleSafeBrowsing: Redis cache enabled", extra={"extra_data": {"url": url_redis, "ttl": self.redis_ttl}})
                except Exception as e:
                    logger.warning("GoogleSafeBrowsing: Failed to connect to Redis: %s", e)
                    self.redis_client = None

    async def scan(self, url: str, session: aiohttp.ClientSession, link_id: str | None = None) -> Dict[str, Any]:
        if not self.enabled:
            return {"raw_score": 0.0}

        # 1. Check Redis Cache
        cache_key = None
        if self.redis_client:
            try:
                # Use hash of URL as key to avoid issues with long/complex URLs
                url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
                cache_key = f"gsb_cache:{url_hash}"
                cached_val = await self.redis_client.get(cache_key)
                if cached_val:
                    logger.debug("GoogleSafeBrowsing: Cache hit for %s", url)
                    return json.loads(cached_val)
            except Exception as e:
                logger.warning("GoogleSafeBrowsing: Redis error (get): %s", e)

        # 2. Quota Check & API Call
        self.check_and_increment_quota()
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {"clientId": self.client_id, "clientVersion": self.client_version},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            async with session.post(api_url, json=payload) as resp:
                resp.raise_for_status()
                data = await resp.json()
                
                result = {"raw_score": 0.0}
                if "matches" in data and len(data["matches"]) > 0:
                    result = {
                        "raw_score": 1.0,
                        "raw_response": json.dumps(data)
                    }

                # 3. Store in Redis Cache
                if self.redis_client and cache_key:
                    try:
                        await self.redis_client.set(cache_key, json.dumps(result), ex=self.redis_ttl)
                    except Exception as e:
                        logger.warning("GoogleSafeBrowsing: Redis error (set): %s", e)

                return result

        except Exception as e:
            logger.error("GoogleSafeBrowsing request failed: %s", e)
            return {"raw_score": 0.0, "error": str(e)}
