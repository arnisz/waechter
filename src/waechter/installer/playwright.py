from __future__ import annotations

import logging
import os

from waechter.installer.models import InstallerConfig
from waechter.installer.runtime import CommandRunner
from waechter.installer.users import ensure_path_owner


logger = logging.getLogger(__name__)
PACKAGE_CANDIDATES: tuple[tuple[str, ...], ...] = (
    ("libnspr4",),
    ("libnss3",),
    ("libgbm1",),
    ("libasound2t64", "libasound2"),
    ("libatk-bridge2.0-0t64", "libatk-bridge2.0-0"),
    ("libatk1.0-0t64", "libatk1.0-0"),
    ("libcups2t64", "libcups2"),
    ("libdrm2",),
    ("libxkbcommon0",),
    ("libxcomposite1",),
    ("libxdamage1",),
    ("libxfixes3",),
    ("libxrandr2",),
    ("libx11-xcb1",),
    ("libxshmfence1",),
    ("libpango-1.0-0",),
    ("libcairo2",),
    ("libatspi2.0-0t64", "libatspi2.0-0"),
    ("libgtk-3-0t64", "libgtk-3-0"),
)


def apt_package_available(runner: CommandRunner, package: str) -> bool:
    result = runner.run(["apt-cache", "policy", package], check=False, capture_output=True)
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0 and "Candidate: " in output and "Candidate: (none)" not in output


def resolve_apt_package(runner: CommandRunner, *candidates: str) -> str:
    for candidate in candidates:
        if apt_package_available(runner, candidate):
            return candidate
    return candidates[0]


def runtime_dependency_packages(runner: CommandRunner) -> list[str]:
    resolved: list[str] = []
    for candidates in PACKAGE_CANDIDATES:
        package = resolve_apt_package(runner, *candidates)
        if package not in resolved:
            resolved.append(package)
    return resolved


def install_runtime_dependencies(config: InstallerConfig, runner: CommandRunner) -> bool:
    if not config.screenshot_enabled:
        return False

    packages = runtime_dependency_packages(runner)
    missing = [pkg for pkg in packages if runner.run(["dpkg", "-s", pkg], check=False).returncode != 0]
    if not missing:
        return False

    logger.info("Installing Playwright/Chromium runtime dependencies: %s", ", ".join(missing))
    runner.run(["apt-get", "update"])
    runner.run(["apt-get", "install", "-y", *missing])
    return True


def ensure_screenshot_dir(config: InstallerConfig, runner: CommandRunner) -> bool:
    if not config.screenshot_enabled:
        return False

    path = config.resolved_screenshot_dir
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o750)
    ensure_path_owner(path, config.app_user, config.app_user, recursive=False)
    runner.run_as_user(
        config.app_user,
        ["python3", "-c", f"import os; exit(0 if os.access('{path}', os.W_OK) else 1)"],
    )
    return not existed


def install_playwright_browser(config: InstallerConfig, runner: CommandRunner) -> bool:
    if not config.screenshot_enabled:
        return False

    logger.info("Ensuring Playwright Chromium browser is installed")
    runner.run_as_user(
        config.app_user,
        [str(config.venv_python), "-m", "playwright", "install", "chromium"],
        cwd=config.app_dir,
    )
    return True


