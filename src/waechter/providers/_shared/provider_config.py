from __future__ import annotations

from typing import Any

from waechter.config_loader import as_bool, provider_cfg


def load_provider_section(name: str) -> dict[str, Any]:
    cfg = provider_cfg(name)
    return cfg if isinstance(cfg, dict) else {}


def resolve_weight(cfg: dict[str, Any], default: float) -> float:
    return float(cfg.get("weight", default))


def resolve_enabled(
    cfg: dict[str, Any],
    *,
    default: bool,
    override: bool | None = None,
) -> bool:
    if override is not None:
        return override
    return as_bool(cfg.get("enabled", default))


def resolve_daily_limit(
    cfg: dict[str, Any],
    *,
    default: int,
) -> int:
    api_cfg = cfg.get("api", {}) or {}
    return int(api_cfg.get("daily_limit", default))


def resolve_bool(value: Any, *, default: bool = False) -> bool:
    return as_bool(value, default=default)
