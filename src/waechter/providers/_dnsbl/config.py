from __future__ import annotations

from dataclasses import dataclass

from waechter.providers._shared.provider_config import (
    load_provider_section,
    resolve_bool,
    resolve_enabled,
    resolve_weight,
)


@dataclass(frozen=True)
class DnsblSettings:
    weight: float
    enabled: bool
    redis_url: str
    redis_password: str | None
    timeout_ms: int
    max_ips: int
    score_listed: float
    use_spamscore: bool


def load_dnsbl_settings(
    *,
    redis_url: str | None = None,
    redis_password: str | None = None,
    timeout_ms: int | None = None,
    max_ips: int | None = None,
    score_listed: float | None = None,
    use_spamscore: bool | None = None,
    enabled: bool | None = None,
) -> DnsblSettings:
    cfg = load_provider_section("dnsbl")
    return DnsblSettings(
        weight=resolve_weight(cfg, 0.6),
        enabled=resolve_enabled(cfg, default=False, override=enabled),
        redis_url=redis_url or cfg.get("redis_url", "redis://localhost:6379/0"),
        redis_password=redis_password or cfg.get("redis_password"),
        timeout_ms=timeout_ms if timeout_ms is not None else int(cfg.get("timeout_ms", 3000)),
        max_ips=max_ips if max_ips is not None else int(cfg.get("max_ips", 8)),
        score_listed=score_listed if score_listed is not None else float(cfg.get("score_listed", 0.6)),
        use_spamscore=use_spamscore if use_spamscore is not None else resolve_bool(
            cfg.get("use_spamscore", False),
            default=False,
        ),
    )
