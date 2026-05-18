import aiohttp
import pytest
from unittest.mock import patch

from waechter.providers.screenshot import ScreenshotProvider
import waechter.providers.screenshot as screenshot_module


class _FakePage:
    def __init__(self):
        self.goto_calls = []
        self.wait_calls = []
        self.screenshot_calls = []

    async def goto(self, url, timeout, wait_until):
        self.goto_calls.append({"url": url, "timeout": timeout, "wait_until": wait_until})

    async def wait_for_load_state(self, state, timeout):
        self.wait_calls.append({"state": state, "timeout": timeout})

    async def screenshot(self, path, type, full_page):
        self.screenshot_calls.append({"path": path, "type": type, "full_page": full_page})
        with open(path, "wb") as f:
            f.write(b"fake-png")


class _FakeContext:
    def __init__(self, page):
        self.page = page
        self.closed = False
        self.new_page_called = False

    async def new_page(self):
        self.new_page_called = True
        return self.page

    async def close(self):
        self.closed = True


class _FakeBrowser:
    def __init__(self, context):
        self.context = context
        self.closed = False
        self.new_context_kwargs = None

    async def new_context(self, **kwargs):
        self.new_context_kwargs = kwargs
        return self.context

    async def close(self):
        self.closed = True


class _FakeChromium:
    def __init__(self, browser):
        self.browser = browser
        self.launch_calls = []

    async def launch(self, headless, args):
        self.launch_calls.append({"headless": headless, "args": args})
        return self.browser


class _FakePlaywright:
    def __init__(self, chromium):
        self.chromium = chromium


class _FakeAsyncPlaywrightContext:
    def __init__(self, playwright):
        self.playwright = playwright

    async def __aenter__(self):
        return self.playwright

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_screenshot_provider_saves_png(monkeypatch, tmp_path):
    monkeypatch.setenv("SCREENSHOT_DIR", str(tmp_path))
    monkeypatch.setenv("SCREENSHOT_ENABLED", "true")

    page = _FakePage()
    context = _FakeContext(page)
    browser = _FakeBrowser(context)
    chromium = _FakeChromium(browser)
    playwright = _FakePlaywright(chromium)

    monkeypatch.setattr(
        ScreenshotProvider,
        "_load_async_playwright",
        lambda self: (lambda: _FakeAsyncPlaywrightContext(playwright)),
    )

    provider = ScreenshotProvider()

    async with aiohttp.ClientSession() as session:
        result = await provider.scan("https://example.org", session, link_id="abc123")

    assert provider.enabled is True
    assert result == {"raw_score": 0.0}
    assert (tmp_path / "abc123.png").exists()
    assert page.goto_calls[0]["wait_until"] == "domcontentloaded"
    assert page.wait_calls[0]["state"] == "networkidle"
    assert page.screenshot_calls[0]["full_page"] is False
    assert browser.new_context_kwargs["viewport"] == {"width": 1024, "height": 768}
    assert browser.new_context_kwargs["screen"] == {"width": 1024, "height": 768}
    assert "Chrome/124.0.0.0" in browser.new_context_kwargs["user_agent"]
    assert context.closed is True
    assert browser.closed is True


def test_screenshot_provider_enabled_from_yaml(monkeypatch, tmp_path):
    monkeypatch.delenv("SCREENSHOT_ENABLED", raising=False)
    monkeypatch.setenv("SCREENSHOT_DIR", str(tmp_path))
    monkeypatch.setattr(
        ScreenshotProvider,
        "_load_async_playwright",
        lambda self: object(),
    )

    provider = ScreenshotProvider()

    assert provider.enabled is True
    assert provider.enabled_source == "config"
    assert provider.disabled_reason is None


def test_screenshot_provider_disables_when_dependency_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("SCREENSHOT_ENABLED", "true")
    monkeypatch.setenv("SCREENSHOT_DIR", str(tmp_path))

    def _raise_import_error(self):
        raise ImportError("playwright missing")

    monkeypatch.setattr(ScreenshotProvider, "_load_async_playwright", _raise_import_error)

    provider = ScreenshotProvider()

    assert provider.enabled is False
    assert provider.disabled_reason == "playwright_not_installed"


def test_screenshot_provider_logs_detailed_directory_diagnostics(monkeypatch):
    monkeypatch.setenv("SCREENSHOT_ENABLED", "true")
    monkeypatch.setenv("SCREENSHOT_DIR", "/home/example/screenshots")

    def _raise_permission_error(self, parents=False, exist_ok=False):
        raise PermissionError("[Errno 13] Permission denied: '/home/example'")

    monkeypatch.setattr("pathlib.Path.mkdir", _raise_permission_error)

    with patch.object(screenshot_module.logger, "error") as log_error:
        provider = ScreenshotProvider()

    assert provider.enabled is False
    assert provider.disabled_reason == "screenshot_dir_unavailable"
    log_error.assert_called_once()
    extra_data = log_error.call_args.kwargs["extra"]["extra_data"]
    assert extra_data["path_is_under_home"] is True
    assert extra_data["nearest_existing_parent"] == "/home"
    assert "Prefer a directory under /opt/waechter" in extra_data["install_hint"]


@pytest.mark.asyncio
async def test_screenshot_provider_logs_structured_launch_error_for_missing_browser_binary(monkeypatch, tmp_path):
    monkeypatch.setenv("SCREENSHOT_DIR", str(tmp_path))
    monkeypatch.setenv("SCREENSHOT_ENABLED", "true")

    class _LaunchFailChromium:
        async def launch(self, headless, args):
            raise Exception(
                "BrowserType.launch: Executable doesn't exist at "
                "/home/test/.cache/ms-playwright/chromium_headless_shell-1223/chrome-headless-shell\n"
                "Please run the following command to download new browsers:\n"
                "playwright install"
            )

    class _LaunchFailPlaywright:
        def __init__(self):
            self.chromium = _LaunchFailChromium()

    monkeypatch.setattr(
        ScreenshotProvider,
        "_load_async_playwright",
        lambda self: (lambda: _FakeAsyncPlaywrightContext(_LaunchFailPlaywright())),
    )

    provider = ScreenshotProvider()

    async with aiohttp.ClientSession() as session:
        with patch.object(screenshot_module.logger, "error") as log_error:
            result = await provider.scan("https://example.org", session, link_id="launchfail")

    assert result == {"raw_score": 0.0}
    log_error.assert_called_once()

    _, kwargs = log_error.call_args
    extra_data = kwargs["extra"]["extra_data"]

    assert extra_data["provider"] == "screenshot"
    assert extra_data["failure_stage"] == "browser_launch"
    assert extra_data["failure_reason"] == "playwright_browser_binary_missing"
    assert extra_data["detected_playwright_installation_issue"] is True
    assert extra_data["install_hint"] == "python -m playwright install chromium"
    assert extra_data["executable_missing_path"] == "/home/test/.cache/ms-playwright/chromium_headless_shell-1223/chrome-headless-shell"
    assert extra_data["browser_engine"] == "chromium"
    assert extra_data["headless"] is True
    assert extra_data["browser_args"] == []


def test_screenshot_provider_classifies_missing_shared_library():
    provider = ScreenshotProvider.__new__(ScreenshotProvider)

    classification = provider._classify_critical_error(
        "BrowserType.launch: Target page, context or browser has been closed\n"
        "[pid=123][err] chrome-headless-shell: error while loading shared libraries: "
        "libnspr4.so: cannot open shared object file: No such file or directory"
    )

    assert classification["failure_stage"] == "browser_launch"
    assert classification["failure_reason"] == "playwright_system_library_missing"
    assert classification["detected_playwright_installation_issue"] is True
    assert classification["missing_shared_library"] == "libnspr4.so"
    assert classification["linux_package_hint"] == "libnspr4"
    assert "apt install libnspr4" in classification["install_hint"]


def test_screenshot_provider_classifies_missing_shared_library_with_ubuntu_24_04_package_hint():
    provider = ScreenshotProvider.__new__(ScreenshotProvider)

    classification = provider._classify_critical_error(
        "BrowserType.launch: Target page, context or browser has been closed\n"
        "[pid=123][err] chrome-headless-shell: error while loading shared libraries: "
        "libasound.so.2: cannot open shared object file: No such file or directory"
    )

    assert classification["failure_reason"] == "playwright_system_library_missing"
    assert classification["missing_shared_library"] == "libasound.so.2"
    assert classification["linux_package_hint"] == "libasound2t64 (Ubuntu 24.04+) oder libasound2"
    assert "Ubuntu 24.04+" in classification["install_hint"]


