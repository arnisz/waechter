from __future__ import annotations

import logging
from pathlib import Path

from waechter.installer.models import InstallerConfig
from waechter.installer.runtime import CommandRunner


logger = logging.getLogger(__name__)


def _write_if_changed(path: Path, content: str, *, mode: int = 0o644) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == content:
        return False
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    return True


def install_bootstrap_script(config: InstallerConfig, runner: CommandRunner) -> bool:
    logger.info("Installing bootstrap launcher to %s", config.script_install_path)
    previous = config.script_install_path.read_bytes() if config.script_install_path.exists() else None
    runner.run(["install", "-m", "0755", str(config.bootstrap_script_path), str(config.script_install_path)])
    current = config.script_install_path.read_bytes()
    return previous != current


def render_service_unit(config: InstallerConfig) -> str:
    read_write_paths = " ".join(path.as_posix() for path in config.read_write_paths)
    return f"""[Unit]
Description=Waechter URL scanning worker
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={config.app_user}
Group={config.app_user}
WorkingDirectory={config.app_dir.as_posix()}
EnvironmentFile={config.env_file.as_posix()}
ExecStart={config.venv_python.as_posix()} {(config.app_dir / 'main.py').as_posix()}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome={config.protect_home_value}
ReadWritePaths={read_write_paths}

[Install]
WantedBy=multi-user.target
"""


def render_update_service_unit(config: InstallerConfig) -> str:
    return f"""[Unit]
Description=Waechter auto-update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={config.script_install_path}
StandardOutput=journal
StandardError=journal
"""


def render_update_timer_unit(config: InstallerConfig) -> str:
    return f"""[Unit]
Description=Daily auto-update timer for {config.app_name}

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
"""


def install_systemd_units(config: InstallerConfig, runner: CommandRunner) -> tuple[bool, bool]:
    logger.info("Installing or updating systemd units")
    service_changed = _write_if_changed(config.service_unit_path, render_service_unit(config))
    update_service_changed = _write_if_changed(config.update_service_unit_path, render_update_service_unit(config))
    update_timer_changed = _write_if_changed(config.update_timer_unit_path, render_update_timer_unit(config))

    if service_changed or update_service_changed or update_timer_changed:
        runner.run(["systemctl", "daemon-reload"])

    runner.run(["systemctl", "enable", "--now", f"{config.app_name}-update.timer"])
    return service_changed, (update_service_changed or update_timer_changed)

