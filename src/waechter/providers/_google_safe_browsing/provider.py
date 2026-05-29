from __future__ import annotations

import json
import logging

import aiohttp

from waechter.providers.base import ProviderResult, QuotaAwareProvider, QuotaExhaustedError
from waechter.providers._google_safe_browsing.config import load_google_safe_browsing_settings
from waechter.providers._shared.redis_cache import UrlJsonRedisCache


logger = logging.getLogger(__name__)


class GoogleSafeBrowsingProvider(QuotaAwareProvider):
    name = "google_safe_browsing"
    weight = 1.0
    daily_limit = 10000
    required_env_vars = ("GSB_API_KEY",)
    optional_env_vars = ("REDIS_ENABLED", "REDIS_URL", "REDIS_TTL_SEC")

    def __init__(self, api_key: str):
        super().__init__()
        self.api_key = api_key
        self.settings = load_google_safe_browsing_settings(api_key)
        self.weight = self.settings.weight
        self.daily_limit = self.settings.daily_limit
        self.client_id = self.settings.client_id
        self.client_version = self.settings.client_version
        self.enabled = self.settings.enabled
        self._masked_key = self.settings.masked_key
        logger.info(
            "google_safe_browsing_init",
            extra={
                "extra_data": {
                    "enabled": self.enabled,
                    "api_key_masked": self._masked_key,
                }
            },
        )

        self.cache: UrlJsonRedisCache | None = None
        self.redis_client = None
        self.redis_ttl = 21600
        try:
            self.cache, cache_settings = UrlJsonRedisCache.from_global_settings(
                provider_name=self.name,
                logger=logger,
                key_prefix="gsb_cache",
            )
            if self.cache:
                self.redis_client = self.cache.client
                self.redis_ttl = cache_settings.ttl
                logger.info(
                    "GoogleSafeBrowsing: Redis cache enabled",
                    extra={
                        "extra_data": {
                            "url": cache_settings.url,
                            "ttl": cache_settings.ttl,
                        }
                    },
                )
        except Exception as exc:
            logger.warning("GoogleSafeBrowsing: Failed to connect to Redis: %s", exc)
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
            cached_value = await self.cache.get(url)
            if cached_value is not None:
                return ProviderResult.from_dict(cached_value)

        try:
            self.check_and_increment_quota()
        except QuotaExhaustedError as exc:
            return self.no_verdict(f"gsb_quota_exhausted: {exc}")
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {
                "clientId": self.client_id,
                "clientVersion": self.client_version,
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with session.post(api_url, json=payload) as response:
                status = response.status
                if status >= 400:
                    body = await response.text()
                    logger.error(
                        "google_safe_browsing_http_error",
                        extra={
                            "extra_data": {
                                "http_status": status,
                                "api_key_masked": self._masked_key,
                                "response_preview": body[:300],
                            }
                        },
                    )
                    return self.no_verdict(
                        f"gsb_http_error: http_{status}",
                        raw_response={"error": f"http_{status}", "response_preview": body[:300]},
                    )

                data = await response.json()
                result = self._build_result(url, data)
                if self.cache:
                    await self.cache.set(url, result.to_dict())
                return result
        except Exception as exc:
            logger.error(
                "google_safe_browsing_request_failed",
                extra={
                    "extra_data": {
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "api_key_masked": self._masked_key,
                    }
                },
            )
            return self.no_verdict(
                f"gsb_request_failed: {type(exc).__name__}: {exc}",
                raw_response={"error": str(exc)},
            )

    def _build_result(self, url: str, data: dict[str, object]) -> ProviderResult:
        matches = data.get("matches") or []
        if matches:
            logger.warning(
                "google_safe_browsing_threat_found",
                extra={
                    "extra_data": {
                        "url": url,
                        "match_count": len(matches),
                        "threat_types": list({match.get("threatType") for match in matches}),
                    }
                },
            )
            return self.build_result(1.0, raw_response=json.dumps(data))

        logger.debug(
            "google_safe_browsing_no_threat",
            extra={"extra_data": {"url": url, "cached": False}},
        )
        return self.build_result(0.0)
