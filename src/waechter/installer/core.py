from __future__ import annotations

import logging

from waechter.installer.clamav import ensure_clamav
from waechter.installer.data import ensure_data_and_config
from waechter.installer.env import write_env_file
from waechter.installer.models import InstallerConfig
from waechter.installer.playwright import ensure_screenshot_dir, install_playwright_browser, install_runtime_dependencies
from waechter.installer.runtime import CommandRunner
from waechter.installer.systemd import install_bootstrap_script, install_systemd_units
from waechter.installer.users import ensure_app_dir_ownership, ensure_system_user


logger = logging.getLogger(__name__)


def validate_required_config(config: InstallerConfig) -> None:
    if not config.worker_base_url or not config.waechter_token:
        raise RuntimeError("WORKER_BASE_URL and WAECHTER_TOKEN are required for installation")


def run_install(config: InstallerConfig, runner: CommandRunner) -> None:
    already_installed = config.is_installed

    if already_installed:
        logger.info("Detected existing installation — running in update mode")
        if not config.worker_base_url or not config.waechter_token:
            raise RuntimeError(
                "Update mode detected but configuration in /etc/waechter/waechter.env "
                "is incomplete or missing. Either restore it from backup or run a "
                "fresh install with WORKER_BASE_URL and WAECHTER_TOKEN."
            )
    else:
        logger.info("No existing service unit found — running in fresh install mode")
        validate_required_config(config)

    ensure_system_user(config, runner)
    ensure_app_dir_ownership(config)
    ensure_data_and_config(config)

    install_runtime_dependencies(config, runner)
    clamav_changed = ensure_clamav(config, runner)
    env_changed = write_env_file(config)
    ensure_screenshot_dir(config, runner)
    install_playwright_browser(config, runner)
    bootstrap_changed = install_bootstrap_script(config, runner)
    service_changed, timer_changed = install_systemd_units(config, runner)

    if not already_installed:
        logger.info("Enabling and starting %s.service", config.app_name)
        runner.run(["systemctl", "enable", "--now", f"{config.app_name}.service"])
        return

    runner.run(["systemctl", "enable", f"{config.app_name}.service"], check=False)
    restart_needed = any((config.repo_updated, clamav_changed, env_changed, bootstrap_changed, service_changed, timer_changed))
    if restart_needed:
        logger.info("Restarting %s.service", config.app_name)
        runner.run(["systemctl", "restart", f"{config.app_name}.service"])
    else:
        logger.info("No service restart required")

