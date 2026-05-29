from __future__ import annotations

from waechter.providers._clamav.models import ClamAVSettings
from waechter.providers._shared.provider_config import (
    load_provider_section,
    resolve_enabled,
    resolve_weight,
)


def load_clamav_settings(
    *,
    socket_path: str | None = None,
    max_bytes: int | None = None,
    max_redirects: int | None = None,
    download_timeout_seconds: int | None = None,
    scan_timeout_seconds: int | None = None,
    enabled: bool | None = None,
) -> ClamAVSettings:
    cfg = load_provider_section("clamav")
    connection = cfg.get("connection", {}) or {}
    limits = cfg.get("limits", {}) or {}
    timeouts = cfg.get("timeouts", {}) or {}

    return ClamAVSettings(
        weight=resolve_weight(cfg, 1.0),
        enabled=resolve_enabled(cfg, default=True, override=enabled),
        socket_path=socket_path or connection.get("socket_path", "/var/run/clamav/clamd.ctl"),
        max_bytes=int(max_bytes if max_bytes is not None else limits.get("max_bytes", 5 * 1024 * 1024)),
        max_redirects=int(max_redirects if max_redirects is not None else limits.get("max_redirects", 7)),
        download_timeout_seconds=int(
            download_timeout_seconds
            if download_timeout_seconds is not None
            else timeouts.get("download_sec", 10)
        ),
        scan_timeout_seconds=int(
            scan_timeout_seconds
            if scan_timeout_seconds is not None
            else timeouts.get("scan_sec", 10)
        ),
    )
