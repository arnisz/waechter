from __future__ import annotations

import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from waechter.logger import get_logger


logger = get_logger()


def load_async_playwright():
    from playwright.async_api import async_playwright

    return async_playwright


def playwright_cache_dir() -> str:
    browsers_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if browsers_path and browsers_path != "0":
        return browsers_path

    xdg_cache = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache:
        return str(Path(xdg_cache) / "ms-playwright")

    return str(Path.home() / ".cache" / "ms-playwright")


def extract_missing_executable_path(error_text: str) -> str | None:
    match = re.search(r"Executable doesn't exist at ([^\n\r]+)", error_text)
    if match:
        return match.group(1).strip()
    return None


def extract_missing_shared_library(error_text: str) -> str | None:
    match = re.search(r"error while loading shared libraries: ([^:]+):", error_text)
    if match:
        return match.group(1).strip()
    return None


def linux_package_hint_for_library(library_name: str | None) -> str | None:
    if not library_name:
        return None

    debian_package_map = {
        "libnspr4.so": "libnspr4",
        "libnss3.so": "libnss3",
        "libgbm.so.1": "libgbm1",
        "libatk-1.0.so.0": "libatk1.0-0t64 (Ubuntu 24.04+) or libatk1.0-0",
        "libatk-bridge-2.0.so.0": "libatk-bridge2.0-0t64 (Ubuntu 24.04+) or libatk-bridge2.0-0",
        "libasound.so.2": "libasound2t64 (Ubuntu 24.04+) or libasound2",
        "libcups.so.2": "libcups2t64 (Ubuntu 24.04+) or libcups2",
        "libxdamage.so.1": "libxdamage1",
        "libxrandr.so.2": "libxrandr2",
        "libgtk-3.so.0": "libgtk-3-0t64 (Ubuntu 24.04+) or libgtk-3-0",
    }
    return debian_package_map.get(library_name)


def format_linux_install_hint(linux_package_hint: str | None) -> str:
    if not linux_package_hint:
        return "Install missing system library required by Playwright Chromium"
    if re.fullmatch(r"[A-Za-z0-9.+-]+", linux_package_hint):
        return f"Install missing system library package (Debian/Ubuntu: apt install {linux_package_hint})"
    return f"Install missing system library package (Debian/Ubuntu package hint: {linux_package_hint})"


def classify_critical_error(error_text: str) -> dict[str, Any]:
    lowered = error_text.lower()
    executable_path = extract_missing_executable_path(error_text)
    missing_shared_library = extract_missing_shared_library(error_text)
    linux_package_hint = linux_package_hint_for_library(missing_shared_library)

    if missing_shared_library:
        return {
            "failure_stage": "browser_launch",
            "failure_reason": "playwright_system_library_missing",
            "detected_playwright_installation_issue": True,
            "missing_shared_library": missing_shared_library,
            "linux_package_hint": linux_package_hint,
            "executable_missing_path": executable_path,
            "install_hint": format_linux_install_hint(linux_package_hint),
        }

    if (
        "executable doesn't exist" in lowered
        or "please run the following command to download new browsers" in lowered
        or "playwright install" in lowered
    ):
        return {
            "failure_stage": "browser_launch",
            "failure_reason": "playwright_browser_binary_missing",
            "detected_playwright_installation_issue": True,
            "executable_missing_path": executable_path,
            "install_hint": "python -m playwright install chromium",
        }

    return {
        "failure_stage": "browser_runtime",
        "failure_reason": "unknown_browser_error",
        "detected_playwright_installation_issue": False,
        "missing_shared_library": missing_shared_library,
        "linux_package_hint": linux_package_hint,
        "executable_missing_path": executable_path,
        "install_hint": None,
    }


async def wait_for_page_stability(page, timeout_ms: int, provider_name: str) -> None:
    try:
        await page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 3000))
    except Exception as exc:
        logger.debug(
            "screenshot_wait_for_networkidle_skipped",
            extra={
                "extra_data": {
                    "provider": provider_name,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            },
        )


def log_screenshot_dir_failure(provider_name: str, screenshot_dir: Path, exc: Exception) -> None:
    under_home = screenshot_dir.as_posix().startswith("/home/")
    nearest = next((item for item in [screenshot_dir, *screenshot_dir.parents] if item.exists()), Path("/"))
    nearest_display = nearest.as_posix()
    if under_home and nearest_display in {"/", "\\"}:
        nearest_display = str(PurePosixPath("/home"))

    logger.error(
        "screenshot_provider_init_failed",
        extra={
            "extra_data": {
                "provider": provider_name,
                "dir": str(screenshot_dir),
                "error_type": type(exc).__name__,
                "error": str(exc),
                "path_is_under_home": under_home,
                "nearest_existing_parent": nearest_display,
                "install_hint": "Prefer a directory under /opt/urlcheck (e.g. /opt/urlcheck/screenshots) to avoid permission issues.",
            }
        },
    )


def log_critical_browser_error(
    *,
    provider_name: str,
    link_id: str,
    url: str,
    output_path: Path,
    browser_args: list[str],
    timeout_ms: int,
    screenshot_dir: Path,
    error: Exception,
) -> None:
    error_text = str(error)
    classification = classify_critical_error(error_text)
    logger.error(
        "screenshot_provider_critical_error",
        extra={
            "extra_data": {
                "provider": provider_name,
                "link_id": link_id,
                "url": url,
                "path": str(output_path),
                "browser_engine": "chromium",
                "headless": True,
                "browser_args": browser_args,
                "timeout_ms": timeout_ms,
                "screenshot_dir": str(screenshot_dir),
                "playwright_cache_dir": playwright_cache_dir(),
                "playwright_browsers_path": os.environ.get("PLAYWRIGHT_BROWSERS_PATH"),
                "python_executable": sys.executable,
                "python_version": sys.version.split()[0],
                "error_type": type(error).__name__,
                "error": error_text,
                **classification,
            }
        },
    )
