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

        self._masked_key = (api_key[:4] + "…" + api_key[-4:]) if len(api_key) >= 8 else ("(not set)" if not api_key else "(too short)")
        logger.info("google_safe_browsing_init", extra={"extra_data": {
            "enabled": self.enabled,
            "api_key_masked": self._masked_key,
        }})

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
                status = resp.status
                if status >= 400:
                    body = await resp.text()
                    logger.error("google_safe_browsing_http_error", extra={"extra_data": {
                        "http_status": status,
                        "api_key_masked": self._masked_key,
                        "response_preview": body[:300],
                    }})
                    return {"raw_score": 0.0, "error": f"http_{status}"}

                data = await resp.json()

                matches = data.get("matches") or []
                if matches:
                    result = {"raw_score": 1.0, "raw_response": json.dumps(data)}
                    logger.warning("google_safe_browsing_threat_found", extra={"extra_data": {
                        "url": url,
                        "match_count": len(matches),
                        "threat_types": list({m.get("threatType") for m in matches}),
                    }})
                else:
                    result = {"raw_score": 0.0}
                    logger.debug("google_safe_browsing_no_threat", extra={"extra_data": {
                        "url": url,
                        "cached": False,
                    }})

                # 3. Store in Redis Cache
                if self.redis_client and cache_key:
                    try:
                        await self.redis_client.set(cache_key, json.dumps(result), ex=self.redis_ttl)
                    except Exception as e:
                        logger.warning("GoogleSafeBrowsing: Redis error (set): %s", e)

                return result

        except Exception as e:
            logger.error("google_safe_browsing_request_failed", extra={"extra_data": {
                "error_type": type(e).__name__,
                "error": str(e),
                "api_key_masked": self._masked_key,
            }})
            return {"raw_score": 0.0, "error": str(e)}
