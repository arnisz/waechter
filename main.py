import os
import sys
import asyncio
from typing import List, cast
from dotenv import load_dotenv

from waechter.api import WorkerApi
from waechter import __version__
from waechter.providers import HeuristicProvider, GoogleSafeBrowsingProvider, ClamAVProvider, ScreenshotProvider, ScanProvider
from waechter.loop import pull_loop
from waechter.logger import get_logger
from waechter.config_loader import as_bool, provider_cfg

load_dotenv()
logger = get_logger()

async def main():
    base_url = os.environ.get("WORKER_BASE_URL")
    token = os.environ.get("WAECHTER_TOKEN")

    if not base_url or not token:
        logger.error("WORKER_BASE_URL and WAECHTER_TOKEN must be set")
        sys.exit(1)

    if not base_url.startswith("https://"):
        logger.error(
            f"WORKER_BASE_URL must start with 'https://' (got: {base_url!r}). "
            "A missing or wrong scheme often causes authentication errors."
        )
        sys.exit(1)

    api = WorkerApi(base_url, token)

    providers: List[ScanProvider] = []
    providers.append(cast(ScanProvider, HeuristicProvider()))

    # ClamAV enabled: ENV override takes precedence, else YAML config
    clamav_cfg = provider_cfg("clamav")
    env_flag = os.environ.get("CLAMAV_ENABLED")
    if env_flag is not None:
        clamav_enabled = env_flag.lower() in ("1", "true", "yes")
    else:
        clamav_enabled = as_bool(clamav_cfg.get("enabled", False), default=False)

    if clamav_enabled:
        clamav_socket_path = os.environ.get("CLAMAV_SOCKET_PATH", (clamav_cfg.get("connection", {}) or {}).get("socket_path", "/var/run/clamav/clamd.ctl"))
        providers.append(cast(ScanProvider, ClamAVProvider(socket_path=clamav_socket_path, enabled=True)))

    gsb_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    gsb_cfg = provider_cfg("google_safe_browsing")
    if gsb_key and as_bool(gsb_cfg.get("enabled", True)):
        providers.append(cast(ScanProvider, GoogleSafeBrowsingProvider(gsb_key)))

    # Add ScreenshotProvider last for security reasons (only after other checks)
    screenshot_provider = ScreenshotProvider()
    if screenshot_provider.enabled:
        providers.append(cast(ScanProvider, screenshot_provider))

    logger.info("Starting Waechter daemon", extra={"extra_data": {
        "version": __version__,
        "providers": len(providers),
        "provider_names": [provider.name for provider in providers],
        "clamav_enabled_effective": clamav_enabled,
        "clamav_socket_path": os.environ.get("CLAMAV_SOCKET_PATH", (clamav_cfg.get("connection", {}) or {}).get("socket_path", "/var/run/clamav/clamd.ctl")),
        "screenshot_enabled_effective": screenshot_provider.enabled,
        "screenshot_enabled_source": screenshot_provider.enabled_source,
        "screenshot_disabled_reason": screenshot_provider.disabled_reason,
        "screenshot_dir": str(screenshot_provider.screenshot_dir),
    }})
    await pull_loop(providers, api)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down")
