from __future__ import annotations

import grp
import logging
import time
from pathlib import Path

from waechter.installer.models import InstallerConfig
from waechter.installer.runtime import CommandRunner


logger = logging.getLogger(__name__)


def detect_clamav_socket() -> str:
    clamd_conf = Path("/etc/clamav/clamd.conf")
    if clamd_conf.exists():
        for line in clamd_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0] == "LocalSocket":
                return parts[1]

    for candidate in (Path("/var/run/clamav/clamd.ctl"), Path("/run/clamav/clamd.ctl")):
        if candidate.exists():
            return str(candidate)

    return "/var/run/clamav/clamd.ctl"


def wait_for_clamav_socket(socket_path: str, timeout: int = 10) -> bool:
    socket = Path(socket_path)
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if socket.exists():
            return True
        elapsed = int(time.monotonic() - start)
        if elapsed > 0 and elapsed % 10 == 0:
            logger.info("Waiting for ClamAV socket... (%ss/%ss)", elapsed, timeout)
        time.sleep(1)
    return False


def user_in_group(runner: CommandRunner, user: str, group_name: str) -> bool:
    result = runner.run(["id", "-nG", user], capture_output=True)
    groups = set((result.stdout or "").split())
    return group_name in groups


def ensure_clamav(config: InstallerConfig, runner: CommandRunner) -> bool:
    if not config.clamav_enabled:
        return False

    logger.info("Checking ClamAV integration")
    restart_needed = False
    daemon_installed = runner.run(["dpkg", "-s", "clamav-daemon"], check=False).returncode == 0
    daemon_active = runner.run(["systemctl", "is-active", "--quiet", "clamav-daemon"], check=False).returncode == 0

    if not daemon_installed or not daemon_active:
        logger.info("Installing or repairing ClamAV daemon packages")
        runner.run(["apt-get", "update"])
        runner.run(["apt-get", "install", "-y", "clamav", "clamav-daemon", "clamav-freshclam"])
        runner.run(["systemctl", "daemon-reload"])
        runner.run(["systemctl", "enable", "--now", "clamav-freshclam"])
        runner.run(["systemctl", "enable", "--now", "clamav-daemon"])
        restart_needed = True

    config.clamav_socket_path = detect_clamav_socket()
    timeout = 90 if restart_needed else 10
    if not wait_for_clamav_socket(config.clamav_socket_path, timeout=timeout):
        logger.warning("ClamAV socket (%s) is not ready after %ss", config.clamav_socket_path, timeout)

    try:
        grp.getgrnam("clamav")
    except KeyError:
        return restart_needed

    if not user_in_group(runner, config.app_user, "clamav"):
        logger.info("Adding %s to clamav group", config.app_user)
        runner.run(["usermod", "-aG", "clamav", config.app_user])
        restart_needed = True

    return restart_needed

