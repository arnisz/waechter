from __future__ import annotations

import json
import logging

import aiohttp

from waechter.providers.base import ProviderResult, QuotaAwareProvider, QuotaExhaustedError
from waechter.providers._phishstats.config import load_phishstats_settings
from waechter.providers._shared.redis_cache import UrlJsonRedisCache


logger = logging.getLogger(__name__)


class PhishStatsProvider(QuotaAwareProvider):
    """PhishStats provider based on the community phishing database."""

    name = "phishstats"
    weight = 0.7
    daily_limit = 10_000
    optional_env_vars = ("REDIS_ENABLED", "REDIS_URL", "REDIS_TTL_SEC")

    def __init__(self, api_key: str = ""):
        del api_key
        super().__init__()
        self.settings = load_phishstats_settings()
        self.weight = self.settings.weight
        self.daily_limit = self.settings.daily_limit
        self.enabled = self.settings.enabled
        self.cache: UrlJsonRedisCache | None = None
        self.redis_client = None
        self.redis_ttl = 21600

        try:
            self.cache, cache_settings = UrlJsonRedisCache.from_global_settings(
                provider_name=self.name,
                logger=logger,
                key_prefix=f"{self.name}_cache",
            )
            if self.cache:
                self.redis_client = self.cache.client
                self.redis_ttl = cache_settings.ttl
                logger.info(
                    "%s: Redis cache enabled",
                    self.name,
                    extra={"extra_data": {"url": cache_settings.url, "ttl": cache_settings.ttl}},
                )
        except Exception as exc:
            logger.warning("%s: Redis connection failed: %s", self.name, exc)
            self.cache = None
            self.redis_client = None

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        link_id: str | None = None,
    ) -> ProviderResult:
        del link_id
        if not self.enabled:
            return self.no_verdict("skipped: disabled")

        if self.cache:
            cached = await self.cache.get(url)
            if cached is not None:
                return ProviderResult.from_dict(cached)

        try:
            self.check_and_increment_quota()
        except QuotaExhaustedError as exc:
            return self.no_verdict(f"phishstats_quota_exhausted: {exc}")
        api_url = "https://api.phishstats.info/api/phishing"
        params = {"_where": f"(url,eq,{url})"}

        try:
            async with session.get(api_url, params=params) as response:
                response.raise_for_status()
                data = await response.json()

            result = self.build_result(0.0)
            if isinstance(data, list) and data:
                result = self.build_result(1.0, raw_response=json.dumps(data))

            if self.cache:
                await self.cache.set(url, result.to_dict())

            return result
        except Exception as exc:
            logger.error("%s: request failed: %s", self.name, exc)
            return self.no_verdict(
                f"phishstats_request_failed: {type(exc).__name__}: {exc}",
                raw_response={"error": str(exc)},
            )
