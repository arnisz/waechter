from __future__ import annotations

from dataclasses import dataclass

from waechter.providers._shared.provider_config import (
    load_provider_section,
    resolve_daily_limit,
    resolve_enabled,
    resolve_weight,
)


@dataclass(frozen=True)
class GoogleSafeBrowsingSettings:
    weight: float
    daily_limit: int
    client_id: str
    client_version: str
    enabled: bool
    masked_key: str


def load_google_safe_browsing_settings(api_key: str) -> GoogleSafeBrowsingSettings:
    cfg = load_provider_section("google_safe_browsing")
    api_cfg = cfg.get("api", {}) or {}
    client_cfg = api_cfg.get("client", {}) or {}
    enabled = resolve_enabled(cfg, default=True) and bool(api_key)
    masked_key = (
        api_key[:4] + "…" + api_key[-4:]
        if len(api_key) >= 8
        else ("(not set)" if not api_key else "(too short)")
    )

    return GoogleSafeBrowsingSettings(
        weight=resolve_weight(cfg, 1.0),
        daily_limit=resolve_daily_limit(cfg, default=10000),
        client_id=str(client_cfg.get("id", "urlcheck")),
        client_version=str(client_cfg.get("version", "1.1.0")),
        enabled=enabled,
        masked_key=masked_key,
    )
