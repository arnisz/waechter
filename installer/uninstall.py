from __future__ import annotations

import logging
import pwd
import shutil

from waechter.installer.models import InstallerConfig
from waechter.installer.runtime import CommandRunner


logger = logging.getLogger(__name__)


def perform_uninstall(config: InstallerConfig, runner: CommandRunner) -> None:
    logger.info("Starting uninstallation of %s", config.app_name)

    for unit_name, unit_path in (
        (f"{config.app_name}.service", config.service_unit_path),
        (f"{config.app_name}-update.timer", config.update_timer_unit_path),
        (f"{config.app_name}-update.service", config.update_service_unit_path),
    ):
        if runner.run(["systemctl", "is-active", "--quiet", unit_name], check=False).returncode == 0:
            logger.info("Stopping %s", unit_name)
            runner.run(["systemctl", "stop", unit_name])
        if runner.run(["systemctl", "is-enabled", "--quiet", unit_name], check=False).returncode == 0:
            logger.info("Disabling %s", unit_name)
            runner.run(["systemctl", "disable", unit_name])
        if unit_path.exists():
            unit_path.unlink()

    runner.run(["systemctl", "daemon-reload"], check=False)
    runner.run(["systemctl", "reset-failed"], check=False)

    if config.app_dir.exists():
        shutil.rmtree(config.app_dir)
        logger.info("Removed %s", config.app_dir)

    if config.env_dir.exists():
        shutil.rmtree(config.env_dir)
        logger.info("Removed %s", config.env_dir)

    if config.script_install_path.exists():
        config.script_install_path.unlink()
        logger.info("Removed %s", config.script_install_path)

    try:
        pwd.getpwnam(config.app_user)
    except KeyError:
        return

    runner.run(["userdel", config.app_user])
    logger.info("Removed system user '%s'", config.app_user)

