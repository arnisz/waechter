from __future__ import annotations

import logging
import os
import re
from pathlib import Path

try:
    import grp
except ImportError:  # pragma: no cover - Windows compatibility
    grp = None

from waechter.installer.constants import DEFAULT_ENV_VALUES, ENV_FILE, ENV_KEYS
from waechter.installer.models import InstallerConfig


logger = logging.getLogger(__name__)
ENV_LINE_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")


def strip_optional_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        return stripped[1:-1]
    return stripped


def parse_env_lines(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.replace("\r", "").strip()
        match = ENV_LINE_RE.match(line)
        if not match:
            continue
        key, raw_value = match.groups()
        values[key] = strip_optional_quotes(raw_value)
    return values


def load_env_file(env_file: Path = ENV_FILE) -> dict[str, str]:
    if not env_file.exists():
        return {}
    return parse_env_lines(env_file.read_text(encoding="utf-8").splitlines())


def as_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def build_config(mode: str = "auto", environ: dict[str, str] | None = None) -> InstallerConfig:
    env = dict(os.environ) if environ is None else dict(environ)
    persisted = load_env_file()

    effective = DEFAULT_ENV_VALUES.copy()
    effective.update({key: persisted[key] for key in ENV_KEYS if key in persisted})
    effective.update({key: env[key] for key in ENV_KEYS if key in env and env[key] != ""})

    config = InstallerConfig(
        worker_base_url=effective["WORKER_BASE_URL"],
        waechter_token=effective["WAECHTER_TOKEN"],
        google_safe_browsing_api_key=effective["GOOGLE_SAFE_BROWSING_API_KEY"],
        clamav_enabled=as_bool(effective["CLAMAV_ENABLED"]),
        clamav_socket_path=effective["CLAMAV_SOCKET_PATH"],
        screenshot_enabled=as_bool(effective["SCREENSHOT_ENABLED"], default=True),
        screenshot_dir=effective["SCREENSHOT_DIR"],
        screenshot_timeout_ms=effective["SCREENSHOT_TIMEOUT_MS"],
        screenshot_no_sandbox=as_bool(effective["SCREENSHOT_NO_SANDBOX"]),
        scan_concurrency=effective["SCAN_CONCURRENCY"],
        batch_size=effective["BATCH_SIZE"],
        min_wait_ms=effective["MIN_WAIT_MS"],
        max_wait_ms=effective["MAX_WAIT_MS"],
        log_level=effective["LOG_LEVEL"],
        threshold_warning=effective["THRESHOLD_WARNING"],
        threshold_block=effective["THRESHOLD_BLOCK"],
        redis_enabled=as_bool(effective.get("REDIS_ENABLED", "true")),
        redis_url=effective.get("REDIS_URL", "redis://localhost:6379/0"),
        redis_ttl_sec=effective.get("REDIS_TTL_SEC", "21600"),
        repo_updated=as_bool(env.get("WAECHTER_BOOTSTRAP_REPO_UPDATED"), default=False),
        mode=mode,
    )

    if not config.clamav_socket_path:
        config.clamav_socket_path = DEFAULT_ENV_VALUES["CLAMAV_SOCKET_PATH"]

    return config


def render_env_file(config: InstallerConfig) -> str:
    ordered_values = {
        "WORKER_BASE_URL": config.worker_base_url,
        "WAECHTER_TOKEN": config.waechter_token,
        "GOOGLE_SAFE_BROWSING_API_KEY": config.google_safe_browsing_api_key,
        "CLAMAV_ENABLED": "true" if config.clamav_enabled else "false",
        "CLAMAV_SOCKET_PATH": config.clamav_socket_path,
        "SCREENSHOT_ENABLED": "true" if config.screenshot_enabled else "false",
        "SCREENSHOT_DIR": config.screenshot_dir,
        "SCREENSHOT_TIMEOUT_MS": config.screenshot_timeout_ms,
        "SCREENSHOT_NO_SANDBOX": "true" if config.screenshot_no_sandbox else "false",
        "SCAN_CONCURRENCY": config.scan_concurrency,
        "BATCH_SIZE": config.batch_size,
        "MIN_WAIT_MS": config.min_wait_ms,
        "MAX_WAIT_MS": config.max_wait_ms,
        "LOG_LEVEL": config.log_level,
        "THRESHOLD_WARNING": config.threshold_warning,
        "THRESHOLD_BLOCK": config.threshold_block,
        "REDIS_ENABLED": "true" if config.redis_enabled else "false",
        "REDIS_URL": config.redis_url,
        "REDIS_TTL_SEC": config.redis_ttl_sec,
    }
    return "".join(f"{key}={value}\n" for key, value in ordered_values.items())


def write_env_file(config: InstallerConfig) -> bool:
    logger.info("Writing environment configuration to %s", config.env_file)
    config.env_dir.mkdir(parents=True, exist_ok=True)

    content = render_env_file(config)
    previous_content = config.env_file.read_text(encoding="utf-8") if config.env_file.exists() else None
    if config.env_file.exists():
        backup_path = config.env_file.with_suffix(config.env_file.suffix + ".bak")
        backup_path.write_text(previous_content or "", encoding="utf-8")

    config.env_file.write_text(content, encoding="utf-8")
    os.chmod(config.env_file, 0o640)
    if grp is not None:
        group = grp.getgrnam(config.app_user).gr_gid
        os.chown(config.env_dir, 0, group)
        os.chown(config.env_file, 0, group)
    os.chmod(config.env_dir, 0o750)
    return previous_content != content


