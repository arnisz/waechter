import os
import sys
import asyncio
from dotenv import load_dotenv

from waechter.api import WorkerApi
from waechter import __version__
from waechter.providers import HeuristicProvider, GoogleSafeBrowsingProvider, ClamAVProvider
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

    api = WorkerApi(base_url, token)

    providers = [HeuristicProvider()]

    # ClamAV enabled: ENV override takes precedence, else YAML config
    clamav_cfg = provider_cfg("clamav")
    env_flag = os.environ.get("CLAMAV_ENABLED")
    if env_flag is not None:
        clamav_enabled = env_flag.lower() in ("1", "true", "yes")
    else:
        clamav_enabled = as_bool(clamav_cfg.get("enabled", False), default=False)

    if clamav_enabled:
        clamav_socket_path = os.environ.get("CLAMAV_SOCKET_PATH", (clamav_cfg.get("connection", {}) or {}).get("socket_path", "/var/run/clamav/clamd.ctl"))
        providers.append(ClamAVProvider(socket_path=clamav_socket_path))

    gsb_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    gsb_cfg = provider_cfg("google_safe_browsing")
    if gsb_key and as_bool(gsb_cfg.get("enabled", True)):
        providers.append(GoogleSafeBrowsingProvider(gsb_key))

    logger.info("Starting Waechter daemon", extra={"extra_data": {
        "version": __version__,
        "providers": len(providers),
        "provider_names": [provider.name for provider in providers],
        "clamav_enabled_effective": clamav_enabled,
        "clamav_socket_path": os.environ.get("CLAMAV_SOCKET_PATH", (clamav_cfg.get("connection", {}) or {}).get("socket_path", "/var/run/clamav/clamd.ctl")),
    }})
    await pull_loop(providers, api)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down")

