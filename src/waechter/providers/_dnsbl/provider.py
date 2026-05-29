from __future__ import annotations

from typing import Any
import asyncio

import aiohttp

from waechter.logger import get_logger
from waechter.providers.base import ProviderResult, ScanProvider
from waechter.providers._dnsbl.config import load_dnsbl_settings
from waechter.providers._dnsbl.runtime import DnsblRuntime


logger = get_logger()


class DnsblProvider(ScanProvider):
    name = "dnsbl"
    weight = 0.6
    optional_env_vars = (
        "URLCHECK_DNSBL_ENABLED",
        "URLCHECK_DNSBL_REDIS_URL",
        "URLCHECK_DNSBL_REDIS_PASSWORD",
        "URLCHECK_DNSBL_TIMEOUT_MS",
        "URLCHECK_DNSBL_MAX_IPS",
        "URLCHECK_DNSBL_SCORE_LISTED",
        "URLCHECK_DNSBL_USE_SPAMSCORE",
    )

    def __init__(
        self,
        redis_url: str | None = None,
        redis_password: str | None = None,
        timeout_ms: int | None = None,
        max_ips: int | None = None,
        score_listed: float | None = None,
        use_spamscore: bool | None = None,
        enabled: bool | None = None,
        redis_client: Any = None,
    ):
        self.settings = load_dnsbl_settings(
            redis_url=redis_url,
            redis_password=redis_password,
            timeout_ms=timeout_ms,
            max_ips=max_ips,
            score_listed=score_listed,
            use_spamscore=use_spamscore,
            enabled=enabled,
        )
        self.weight = self.settings.weight
        self.enabled = self.settings.enabled
        self.redis_url = self.settings.redis_url
        self.redis_password = self.settings.redis_password
        self.timeout_ms = self.settings.timeout_ms
        self.max_ips = self.settings.max_ips
        self.score_listed = self.settings.score_listed
        self.use_spamscore = self.settings.use_spamscore
        self.runtime = DnsblRuntime(self.settings, redis_client=redis_client)
        self._redis = self.runtime._redis
        self._redis_lock = self.runtime._redis_lock

    async def _get_redis(self):
        client = await self.runtime.get_redis()
        self._redis = self.runtime._redis
        return client

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        link_id: str | None = None,
    ) -> ProviderResult:
        del session, link_id
        if not self.enabled:
            return self.no_verdict("skipped: disabled", raw_response="skipped: disabled")

        try:
            raw_result = await asyncio.wait_for(
                self.runtime.scan_internal(url),
                timeout=self.timeout_ms / 1000.0,
            )
            raw_response = raw_result.get("raw_response")
            raw_score = raw_result.get("raw_score")
            if (
                isinstance(raw_response, dict)
                and raw_response.get("error")
                and raw_score in (0, 0.0, None)
            ):
                return self.no_verdict(
                    f"dnsbl_check_failed: {raw_response['error']}",
                    raw_response=raw_response,
                )
            return self.build_result(raw_score, raw_response=raw_response)
        except asyncio.TimeoutError:
            logger.warning(
                "dnsbl_timeout",
                extra={"extra_data": {"url": url, "timeout_ms": self.timeout_ms}},
            )
            return self.no_verdict("dnsbl_check_failed: timeout", raw_response={"error": "timeout"})
        except Exception as exc:
            logger.error(
                "dnsbl_error",
                extra={"extra_data": {"url": url, "error": str(exc)}},
            )
            return self.no_verdict(
                f"dnsbl_check_failed: {type(exc).__name__}: {exc}",
                raw_response={"error": str(exc)},
            )

    async def aclose(self):
        await self.runtime.close()
        self._redis = self.runtime._redis
