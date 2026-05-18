from __future__ import annotations

import grp
import logging
import os
import pwd
from pathlib import Path

from waechter.installer.models import InstallerConfig
from waechter.installer.runtime import CommandRunner


logger = logging.getLogger(__name__)


def user_exists(username: str) -> bool:
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def ensure_system_user(config: InstallerConfig, runner: CommandRunner) -> bool:
    if user_exists(config.app_user):
        return False

    logger.info("Creating system user '%s'", config.app_user)
    runner.run(
        [
            "useradd",
            "--system",
            "--home",
            str(config.app_dir),
            "--create-home",
            "--shell",
            "/usr/sbin/nologin",
            config.app_user,
        ]
    )
    return True


def ensure_path_owner(path: Path, username: str, groupname: str, *, recursive: bool = False) -> None:
    if not path.exists():
        return

    uid = pwd.getpwnam(username).pw_uid
    gid = grp.getgrnam(groupname).gr_gid

    def apply(target: Path) -> None:
        os.chown(target, uid, gid)

    apply(path)
    if recursive and path.is_dir():
        for root, dirs, files in os.walk(path):
            root_path = Path(root)
            apply(root_path)
            for entry in dirs:
                apply(root_path / entry)
            for entry in files:
                apply(root_path / entry)


def ensure_app_dir_ownership(config: InstallerConfig) -> None:
    logger.info("Ensuring ownership of %s for %s", config.app_dir, config.app_user)
    ensure_path_owner(config.app_dir, config.app_user, config.app_user, recursive=True)

