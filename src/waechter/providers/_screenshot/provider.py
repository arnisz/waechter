from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import aiohttp

from waechter.logger import get_logger
from waechter.providers.base import ProviderResult, ScanProvider
from waechter.providers._screenshot.browser import (
    load_async_playwright,
    log_critical_browser_error,
    log_screenshot_dir_failure,
    wait_for_page_stability,
)
from waechter.providers._screenshot.config import CHROME_USER_AGENT, load_screenshot_settings


logger = get_logger()


class ScreenshotProvider(ScanProvider):
    name = "screenshot"
    weight = 0.0
    optional_env_vars = (
        "SCREENSHOT_ENABLED",
        "SCREENSHOT_DIR",
        "SCREENSHOT_TIMEOUT_MS",
        "SCREENSHOT_NO_SANDBOX",
        "PLAYWRIGHT_BROWSERS_PATH",
        "XDG_CACHE_HOME",
    )

    def __init__(self):
        self.settings = load_screenshot_settings()
        self.enabled = self.settings.enabled
        self.enabled_source = self.settings.enabled_source
        self.screenshot_dir = self.settings.screenshot_dir
        self.timeout_ms = self.settings.timeout_ms
        self.no_sandbox = self.settings.no_sandbox
        self.disabled_reason: str | None = None
        self._async_playwright = None

        if not self.enabled:
            self.disabled_reason = "disabled_by_config"
            return

        try:
            self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            self.enabled = False
            self.disabled_reason = "screenshot_dir_unavailable"
            log_screenshot_dir_failure(self.name, self.screenshot_dir, exc)
            return

        try:
            self._async_playwright = load_async_playwright()
        except ImportError:
            self.enabled = False
            self.disabled_reason = "playwright_not_installed"
            logger.error(
                "screenshot_provider_dependency_missing",
                extra={
                    "extra_data": {
                        "provider": self.name,
                        "error": "playwright not installed; install package and run 'playwright install chromium'",
                    }
                },
            )

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        link_id: str | None = None,
    ) -> ProviderResult:
        del session
        if not self.enabled or self._async_playwright is None:
            return self.no_verdict(
                self.disabled_reason or "screenshot provider unavailable",
            )

        if not link_id:
            logger.warning(
                "screenshot_provider_no_link_id",
                extra={"extra_data": {"provider": self.name, "url": url}},
            )
            return self.no_verdict("screenshot missing link_id")

        if not url.startswith(("http://", "https://")):
            logger.warning(
                "screenshot_skipped_unsupported_scheme",
                extra={"extra_data": {"provider": self.name, "link_id": link_id, "url": url}},
            )
            return self.build_result(0.0, raw_response="skipped: unsupported_scheme")

        output_path = self.screenshot_dir / f"{link_id}.png"
        browser = None
        context = None
        browser_args: list[str] = []

        try:
            async with self._async_playwright() as playwright:
                if self.no_sandbox:
                    browser_args.append("--no-sandbox")

                browser = await playwright.chromium.launch(headless=True, args=browser_args)
                viewport = {"width": 1024, "height": 768}
                context = await browser.new_context(
                    viewport=viewport,
                    screen=viewport,
                    user_agent=CHROME_USER_AGENT,
                )
                page = await context.new_page()
                try:
                    await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                    await wait_for_page_stability(page, self.timeout_ms, self.name)
                    await page.screenshot(path=str(output_path), type="png", full_page=False)
                    logger.info(
                        "screenshot_saved",
                        extra={
                            "extra_data": {
                                "provider": self.name,
                                "link_id": link_id,
                                "url": url,
                                "path": str(output_path),
                                "viewport": viewport,
                                "browser_engine": "chromium",
                                "headless": True,
                            }
                        },
                    )
                except Exception as exc:
                    logger.warning(
                        "screenshot_failed",
                        extra={
                            "extra_data": {
                                "provider": self.name,
                                "link_id": link_id,
                                "url": url,
                                "path": str(output_path),
                                "failure_stage": "page_interaction",
                                "browser_engine": "chromium",
                                "headless": True,
                                "browser_args": browser_args,
                                "timeout_ms": self.timeout_ms,
                                "error_type": type(exc).__name__,
                                "error": str(exc),
                            }
                        },
                    )
                finally:
                    await context.close()
        except Exception as exc:
            log_critical_browser_error(
                provider_name=self.name,
                link_id=link_id,
                url=url,
                output_path=output_path,
                browser_args=browser_args,
                timeout_ms=self.timeout_ms,
                screenshot_dir=self.screenshot_dir,
                error=exc,
            )
        finally:
            if browser is not None:
                await browser.close()

        return self.build_result(0.0, raw_response={"path": str(output_path)})
