import os
import sys
import asyncio
from dotenv import load_dotenv

from src.api import WorkerApi
from src import __version__
from src.providers import HeuristicProvider, GoogleSafeBrowsingProvider, ClamAVProvider
from src.loop import pull_loop
from src.logger import get_logger

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
    if os.environ.get("CLAMAV_ENABLED", "").lower() in ("1", "true", "yes"):
        clamav_socket_path = os.environ.get("CLAMAV_SOCKET_PATH", "/var/run/clamav/clamd.ctl")
        providers.append(ClamAVProvider(clamav_socket_path))

    gsb_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if gsb_key:
        providers.append(GoogleSafeBrowsingProvider(gsb_key))

    logger.info("Starting Waechter daemon", extra={"extra_data": {
        "version": __version__,
        "providers": len(providers),
        "provider_names": [provider.name for provider in providers],
        "clamav_enabled_env": os.environ.get("CLAMAV_ENABLED", ""),
        "clamav_socket_path": os.environ.get("CLAMAV_SOCKET_PATH", "/var/run/clamav/clamd.ctl"),
    }})
    await pull_loop(providers, api)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down")

