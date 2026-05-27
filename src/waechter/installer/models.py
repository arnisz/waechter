from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from waechter.installer import constants


@dataclass(slots=True)
class InstallerConfig:
    worker_base_url: str
    waechter_token: str
    google_safe_browsing_api_key: str
    clamav_enabled: bool
    clamav_socket_path: str
    screenshot_enabled: bool
    screenshot_dir: str
    screenshot_timeout_ms: str
    screenshot_no_sandbox: bool
    scan_concurrency: str
    batch_size: str
    min_wait_ms: str
    max_wait_ms: str
    log_level: str
    threshold_warning: str
    threshold_block: str
    redis_enabled: bool
    redis_url: str
    redis_ttl_sec: str
    repo_updated: bool = False
    mode: str = "auto"

    @property
    def app_name(self) -> str:
        return constants.APP_NAME

    @property
    def app_user(self) -> str:
        return constants.APP_USER

    @property
    def app_dir(self) -> Path:
        return constants.APP_DIR

    @property
    def env_dir(self) -> Path:
        return constants.ENV_DIR

    @property
    def env_file(self) -> Path:
        return constants.ENV_FILE

    @property
    def script_install_path(self) -> Path:
        return constants.SCRIPT_INSTALL_PATH

    @property
    def service_unit_path(self) -> Path:
        return constants.SERVICE_UNIT_PATH

    @property
    def update_service_unit_path(self) -> Path:
        return constants.UPDATE_SERVICE_UNIT_PATH

    @property
    def update_timer_unit_path(self) -> Path:
        return constants.UPDATE_TIMER_UNIT_PATH

    @property
    def bootstrap_script_path(self) -> Path:
        return constants.PROJECT_ROOT / constants.BOOTSTRAP_SCRIPT_NAME

    @property
    def venv_python(self) -> Path:
        return self.app_dir / ".venv" / "bin" / "python"

    @property
    def is_installed(self) -> bool:
        return self.service_unit_path.exists()

    @property
    def resolved_screenshot_dir(self) -> Path:
        screenshot_dir = self.screenshot_dir or constants.DEFAULT_ENV_VALUES["SCREENSHOT_DIR"]
        raw_path = Path(screenshot_dir)
        if screenshot_dir.startswith(("/", "\\")) or (len(screenshot_dir) >= 2 and screenshot_dir[1] == ":"):
            return raw_path
        stripped = screenshot_dir[2:] if screenshot_dir.startswith("./") else screenshot_dir
        return self.app_dir / stripped

    def _screenshot_dir_is_absolute(self) -> bool:
        screenshot_dir = self.screenshot_dir or constants.DEFAULT_ENV_VALUES["SCREENSHOT_DIR"]
        return screenshot_dir.startswith(("/", "\\")) or (len(screenshot_dir) >= 2 and screenshot_dir[1] == ":")

    @property
    def read_write_paths(self) -> list[Path]:
        paths = [self.app_dir, self.env_dir]
        screenshot_path = self.resolved_screenshot_dir
        if self.screenshot_enabled and self._screenshot_dir_is_absolute() and screenshot_path not in paths:
            paths.append(screenshot_path)
        return paths

    @property
    def protect_home_value(self) -> str:
        screenshot_path = self.resolved_screenshot_dir
        if self.screenshot_enabled and self._screenshot_dir_is_absolute() and screenshot_path.as_posix().startswith("/home/"):
            return "false"
        return "true"

