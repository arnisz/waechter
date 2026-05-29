from __future__ import annotations

from pathlib import Path

APP_NAME = "waechter"
APP_USER = "waechter"
APP_DIR = Path("/opt/waechter")
ENV_DIR = Path("/etc/waechter")
ENV_FILE = ENV_DIR / "waechter.env"
SCRIPT_INSTALL_PATH = Path("/usr/local/sbin/waechter.sh")
SYSTEMD_DIR = Path("/etc/systemd/system")
SERVICE_UNIT_PATH = SYSTEMD_DIR / f"{APP_NAME}.service"
UPDATE_SERVICE_UNIT_PATH = SYSTEMD_DIR / f"{APP_NAME}-update.service"
UPDATE_TIMER_UNIT_PATH = SYSTEMD_DIR / f"{APP_NAME}-update.timer"
PROJECT_ROOT = Path(__file__).resolve().parents[3]
BOOTSTRAP_SCRIPT_NAME = "install.sh"
REPO_URL = "https://github.com/arnisz/waechter.git"
BRANCH = "master"

ENV_KEYS = [
    "WORKER_BASE_URL",
    "WAECHTER_TOKEN",
    "GOOGLE_SAFE_BROWSING_API_KEY",
    "CLAMAV_ENABLED",
    "CLAMAV_SOCKET_PATH",
    "SCREENSHOT_ENABLED",
    "SCREENSHOT_DIR",
    "SCREENSHOT_TIMEOUT_MS",
    "SCREENSHOT_NO_SANDBOX",
    "SCAN_CONCURRENCY",
    "BATCH_SIZE",
    "MIN_WAIT_MS",
    "MAX_WAIT_MS",
    "LOG_LEVEL",
    "THRESHOLD_WARNING",
    "THRESHOLD_BLOCK",
    "REDIS_ENABLED",
    "REDIS_URL",
    "REDIS_TTL_SEC",
    "DNSBL_ENABLED",
    "DNSBL_REDIS_URL",
    "DNSBL_REDIS_PASSWORD",
    "PHISHSTATS_ENABLED",
]

DEFAULT_ENV_VALUES = {
    "WORKER_BASE_URL": "",
    "WAECHTER_TOKEN": "",
    "GOOGLE_SAFE_BROWSING_API_KEY": "",
    "CLAMAV_ENABLED": "false",
    "CLAMAV_SOCKET_PATH": "",
    "SCREENSHOT_ENABLED": "true",
    "SCREENSHOT_DIR": "./screenshots",
    "SCREENSHOT_TIMEOUT_MS": "10000",
    "SCREENSHOT_NO_SANDBOX": "false",
    "SCAN_CONCURRENCY": "10",
    "BATCH_SIZE": "25",
    "MIN_WAIT_MS": "5000",
    "MAX_WAIT_MS": "60000",
    "LOG_LEVEL": "INFO",
    "THRESHOLD_WARNING": "0.70",
    "THRESHOLD_BLOCK": "0.95",
    "REDIS_ENABLED": "true",
    "REDIS_URL": "redis://localhost:6379/0",
    "REDIS_TTL_SEC": "21600",
    "DNSBL_ENABLED": "false",
    "DNSBL_REDIS_URL": "redis://localhost:6379/0",
    "DNSBL_REDIS_PASSWORD": "",
    "PHISHSTATS_ENABLED": "true",
}

