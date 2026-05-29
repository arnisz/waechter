from __future__ import annotations

from dataclasses import dataclass

from waechter.providers._shared.provider_config import (
    load_provider_section,
    resolve_daily_limit,
    resolve_enabled,
    resolve_weight,
)


@dataclass(frozen=True)
class PhishStatsSettings:
    weight: float
    daily_limit: int
    enabled: bool


def load_phishstats_settings() -> PhishStatsSettings:
    cfg = load_provider_section("phishstats")
    return PhishStatsSettings(
        weight=resolve_weight(cfg, 0.7),
        daily_limit=resolve_daily_limit(cfg, default=10_000),
        enabled=resolve_enabled(cfg, default=True),
    )
