import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict
import aiohttp

from waechter.providers.base import ScanProvider
from waechter.config_loader import as_bool, provider_cfg
from waechter.logger import get_logger

logger = get_logger()

CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class ScreenshotProvider(ScanProvider):
    name = "screenshot"
    weight = 0.0  # Screenshots don't contribute to the score directly

    def __init__(self):
        cfg = provider_cfg(self.name)
        env_flag = os.environ.get("SCREENSHOT_ENABLED")
        config_enabled = cfg.get("enabled", True)
        screenshot_dir_value = os.environ.get("SCREENSHOT_DIR") or str(cfg.get("dir", "./screenshots"))
        timeout_value = os.environ.get("SCREENSHOT_TIMEOUT_MS") or str(cfg.get("timeout_ms", 10000))
        no_sandbox_value = os.environ.get("SCREENSHOT_NO_SANDBOX")
        if no_sandbox_value is None:
            no_sandbox_value = cfg.get("no_sandbox", False)

        if env_flag is not None:
            self.enabled = as_bool(env_flag, default=False)
            self.enabled_source = "env"
        else:
            self.enabled = as_bool(config_enabled, default=True)
            self.enabled_source = "config"

        self.screenshot_dir = Path(screenshot_dir_value)
        self.timeout_ms = int(timeout_value)
        self.no_sandbox = as_bool(no_sandbox_value, default=False)
        self.disabled_reason: str | None = None
        self._async_playwright = None

        if not self.enabled:
            self.disabled_reason = "disabled_by_config"
            return

        try:
            self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.enabled = False
            self.disabled_reason = "screenshot_dir_unavailable"
            p = self.screenshot_dir
            under_home = p.as_posix().startswith("/home/")
            nearest = next((a for a in [p, *p.parents] if a.exists()), Path("/"))
            nearest_display = nearest.as_posix()
            if under_home and nearest_display in {"/", "\\"}:
                nearest_display = str(PurePosixPath("/home"))
            logger.error("screenshot_provider_init_failed", extra={"extra_data": {
                "provider": self.name,
                "dir": str(p),
                "error_type": type(e).__name__,
                "error": str(e),
                "path_is_under_home": under_home,
                "nearest_existing_parent": nearest_display,
                "install_hint": "Prefer a directory under /opt/waechter (e.g. /opt/waechter/screenshots) to avoid permission issues.",
            }})
            return

        try:
            self._async_playwright = self._load_async_playwright()
        except ImportError:
            self.enabled = False
            self.disabled_reason = "playwright_not_installed"
            logger.error(
                "screenshot_provider_dependency_missing",
                extra={"extra_data": {
                    "provider": self.name,
                    "error": "playwright not installed; install package and run 'playwright install chromium'",
                }},
            )

    def _load_async_playwright(self):
        from playwright.async_api import async_playwright

        return async_playwright

    def _playwright_cache_dir(self) -> str:
        browsers_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
        if browsers_path and browsers_path != "0":
            return browsers_path

        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        if xdg_cache:
            return str(Path(xdg_cache) / "ms-playwright")

        return str(Path.home() / ".cache" / "ms-playwright")

    def _extract_missing_executable_path(self, error_text: str) -> str | None:
        match = re.search(r"Executable doesn't exist at ([^\n\r]+)", error_text)
        if match:
            return match.group(1).strip()
        return None

    def _extract_missing_shared_library(self, error_text: str) -> str | None:
        match = re.search(r"error while loading shared libraries: ([^:]+):", error_text)
        if match:
            return match.group(1).strip()
        return None

    def _linux_package_hint_for_library(self, library_name: str | None) -> str | None:
        if not library_name:
            return None

        debian_package_map = {
            "libnspr4.so": "libnspr4",
            "libnss3.so": "libnss3",
            "libgbm.so.1": "libgbm1",
            "libatk-1.0.so.0": "libatk1.0-0t64 (Ubuntu 24.04+) oder libatk1.0-0",
            "libatk-bridge-2.0.so.0": "libatk-bridge2.0-0t64 (Ubuntu 24.04+) oder libatk-bridge2.0-0",
            "libasound.so.2": "libasound2t64 (Ubuntu 24.04+) oder libasound2",
            "libcups.so.2": "libcups2t64 (Ubuntu 24.04+) oder libcups2",
            "libxdamage.so.1": "libxdamage1",
            "libxrandr.so.2": "libxrandr2",
            "libgtk-3.so.0": "libgtk-3-0t64 (Ubuntu 24.04+) oder libgtk-3-0",
        }
        return debian_package_map.get(library_name)

    def _format_linux_install_hint(self, linux_package_hint: str | None) -> str:
        if not linux_package_hint:
            return "Install missing system library required by Playwright Chromium"

        if re.fullmatch(r"[A-Za-z0-9.+-]+", linux_package_hint):
            return f"Install missing system library package (Debian/Ubuntu: apt install {linux_package_hint})"

        return (
            "Install missing system library package "
            f"(Debian/Ubuntu package hint: {linux_package_hint})"
        )

    def _classify_critical_error(self, error_text: str) -> Dict[str, Any]:
        lowered = error_text.lower()
        executable_path = self._extract_missing_executable_path(error_text)
        missing_shared_library = self._extract_missing_shared_library(error_text)
        linux_package_hint = self._linux_package_hint_for_library(missing_shared_library)

        if missing_shared_library:
            return {
                "failure_stage": "browser_launch",
                "failure_reason": "playwright_system_library_missing",
                "detected_playwright_installation_issue": True,
                "missing_shared_library": missing_shared_library,
                "linux_package_hint": linux_package_hint,
                "executable_missing_path": executable_path,
                "install_hint": self._format_linux_install_hint(linux_package_hint),
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

    async def _wait_for_page_stability(self, page) -> None:
        try:
            await page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 3000))
        except Exception as e:
            logger.debug("screenshot_wait_for_networkidle_skipped", extra={"extra_data": {
                "provider": self.name,
                "error_type": type(e).__name__,
                "error": str(e),
            }})

    async def scan(self, url: str, session: aiohttp.ClientSession, link_id: str | None = None) -> Dict[str, Any]:
        if not self.enabled or self._async_playwright is None:
            return {"raw_score": 0.0}

        if not link_id:
            logger.warning("screenshot_provider_no_link_id", extra={"extra_data": {
                "provider": self.name,
                "url": url,
            }})
            return {"raw_score": 0.0}

        if not url.startswith(("http://", "https://")):
            logger.warning("screenshot_skipped_unsupported_scheme", extra={"extra_data": {
                "provider": self.name,
                "link_id": link_id,
                "url": url,
            }})
            return {"raw_score": 0.0}

        output_path = self.screenshot_dir / f"{link_id}.png"
        browser = None
        context = None
        browser_args: list[str] = []

        try:
            async with self._async_playwright() as p:
                if self.no_sandbox:
                    browser_args.append("--no-sandbox")

                browser = await p.chromium.launch(headless=True, args=browser_args)
                viewport = {"width": 1024, "height": 768}
                context_options: Dict[str, Any] = {
                    "viewport": viewport,
                    "screen": viewport,
                    "user_agent": CHROME_USER_AGENT,
                }
                context = await browser.new_context(**context_options)
                page = await context.new_page()
                try:
                    await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                    await self._wait_for_page_stability(page)
                    await page.screenshot(path=str(output_path), type="png", full_page=False)
                    logger.info("screenshot_saved", extra={"extra_data": {
                        "provider": self.name,
                        "link_id": link_id,
                        "url": url,
                        "path": str(output_path),
                        "viewport": {"width": 1024, "height": 768},
                        "browser_engine": "chromium",
                        "headless": True,
                    }})
                except Exception as e:
                    logger.warning("screenshot_failed", extra={"extra_data": {
                        "provider": self.name,
                        "link_id": link_id,
                        "url": url,
                        "path": str(output_path),
                        "failure_stage": "page_interaction",
                        "browser_engine": "chromium",
                        "headless": True,
                        "browser_args": browser_args,
                        "timeout_ms": self.timeout_ms,
                        "error_type": type(e).__name__,
                        "error": str(e),
                    }})
                finally:
                    await context.close()
        except Exception as e:
            error_text = str(e)
            classification = self._classify_critical_error(error_text)
            logger.error("screenshot_provider_critical_error", extra={"extra_data": {
                "provider": self.name,
                "link_id": link_id,
                "url": url,
                "path": str(output_path),
                "browser_engine": "chromium",
                "headless": True,
                "browser_args": browser_args,
                "timeout_ms": self.timeout_ms,
                "screenshot_dir": str(self.screenshot_dir),
                "playwright_cache_dir": self._playwright_cache_dir(),
                "playwright_browsers_path": os.environ.get("PLAYWRIGHT_BROWSERS_PATH"),
                "python_executable": sys.executable,
                "python_version": sys.version.split()[0],
                "error_type": type(e).__name__,
                "error": error_text,
                **classification,
            }})
        finally:
            if browser is not None:
                await browser.close()

        return {"raw_score": 0.0}

