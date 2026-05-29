from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from waechter.config_loader import as_bool, provider_cfg


CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class ScreenshotSettings:
    enabled: bool
    enabled_source: str
    screenshot_dir: Path
    timeout_ms: int
    no_sandbox: bool


def load_screenshot_settings() -> ScreenshotSettings:
    cfg = provider_cfg("screenshot")
    env_flag = os.environ.get("SCREENSHOT_ENABLED")
    config_enabled = cfg.get("enabled", True)
    screenshot_dir_value = os.environ.get("SCREENSHOT_DIR") or str(cfg.get("dir", "./screenshots"))
    timeout_value = os.environ.get("SCREENSHOT_TIMEOUT_MS") or str(cfg.get("timeout_ms", 10000))
    no_sandbox_value = os.environ.get("SCREENSHOT_NO_SANDBOX")
    if no_sandbox_value is None:
        no_sandbox_value = cfg.get("no_sandbox", False)

    if env_flag is not None:
        enabled = as_bool(env_flag, default=False)
        enabled_source = "env"
    else:
        enabled = as_bool(config_enabled, default=True)
        enabled_source = "config"

    return ScreenshotSettings(
        enabled=enabled,
        enabled_source=enabled_source,
        screenshot_dir=Path(screenshot_dir_value),
        timeout_ms=int(timeout_value),
        no_sandbox=as_bool(no_sandbox_value, default=False),
    )
