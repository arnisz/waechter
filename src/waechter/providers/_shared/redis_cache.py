from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
import os
from typing import Any

from waechter.config_loader import as_bool, cfg_get

try:
    import redis.asyncio as redis
except ImportError:
    redis = None


@dataclass(frozen=True)
class RedisCacheSettings:
    enabled: bool
    url: str | None
    ttl: int


def load_global_redis_cache_settings() -> RedisCacheSettings:
    redis_cfg = cfg_get("redis", {})
    redis_enabled_env = os.environ.get("REDIS_ENABLED")
    if redis_enabled_env is not None:
        enabled = as_bool(redis_enabled_env)
    else:
        enabled = as_bool(redis_cfg.get("enabled", False))

    url = os.environ.get("REDIS_URL", redis_cfg.get("url"))
    ttl_env = os.environ.get("REDIS_TTL_SEC")
    ttl = int(ttl_env) if ttl_env is not None else int(redis_cfg.get("ttl_sec", 21600))
    return RedisCacheSettings(enabled=enabled, url=url, ttl=ttl)


class UrlJsonRedisCache:
    def __init__(
        self,
        *,
        provider_name: str,
        logger: logging.Logger,
        key_prefix: str,
        client,
        ttl: int,
    ):
        self.provider_name = provider_name
        self.logger = logger
        self.key_prefix = key_prefix
        self.client = client
        self.ttl = ttl

    @classmethod
    def from_global_settings(
        cls,
        *,
        provider_name: str,
        logger: logging.Logger,
        key_prefix: str,
    ) -> tuple["UrlJsonRedisCache | None", RedisCacheSettings]:
        settings = load_global_redis_cache_settings()
        if not redis or not settings.enabled or not settings.url:
            return None, settings

        client = redis.from_url(settings.url, decode_responses=True)
        return (
            cls(
                provider_name=provider_name,
                logger=logger,
                key_prefix=key_prefix,
                client=client,
                ttl=settings.ttl,
            ),
            settings,
        )

    async def get(self, url: str) -> dict[str, Any] | None:
        try:
            cached_value = await self.client.get(self._cache_key(url))
            if cached_value:
                self.logger.debug("%s: cache hit for %s", self.provider_name, url)
                return json.loads(cached_value)
        except Exception as exc:
            self.logger.warning("%s: Redis get error: %s", self.provider_name, exc)
        return None

    async def set(self, url: str, value: dict[str, Any]) -> None:
        try:
            await self.client.set(
                self._cache_key(url),
                json.dumps(value),
                ex=self.ttl,
            )
        except Exception as exc:
            self.logger.warning("%s: Redis set error: %s", self.provider_name, exc)

    def _cache_key(self, url: str) -> str:
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return f"{self.key_prefix}:{url_hash}"
