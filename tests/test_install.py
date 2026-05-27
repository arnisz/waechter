from pathlib import Path
from unittest.mock import patch

import install


def test_default_config_yaml_contains_screenshot_provider_block():
    assert "screenshot:" in install.DEFAULT_CONFIG_YAML
    assert 'enabled: true' in install.DEFAULT_CONFIG_YAML
    assert 'dir: "./screenshots"' in install.DEFAULT_CONFIG_YAML
    assert 'timeout_ms: 10000' in install.DEFAULT_CONFIG_YAML


@patch("install.subprocess.check_call")
@patch("install.prompt_bool", return_value=True)
def test_maybe_install_playwright_browser_runs_expected_command(mock_prompt_bool, mock_check_call):
    python_bin = Path("/tmp/fake-python")

    install.maybe_install_playwright_browser(python_bin, screenshot_enabled=True)

    mock_check_call.assert_called_once_with(
        [str(python_bin), "-m", "playwright", "install", "chromium"],
        cwd=str(install.PROJECT_ROOT),
    )


@patch("install.subprocess.check_call")
def test_maybe_install_playwright_browser_skips_when_screenshot_disabled(mock_check_call):
    python_bin = Path("/tmp/fake-python")

    install.maybe_install_playwright_browser(python_bin, screenshot_enabled=False)

    mock_check_call.assert_not_called()


def test_shell_installer_contains_ubuntu_24_04_playwright_package_fallbacks():
    bootstrap_installer = (install.PROJECT_ROOT / "install.sh").read_text(encoding="utf-8")
    compatibility_wrapper = (install.PROJECT_ROOT / "waechter-installsh.sh").read_text(encoding="utf-8")

    assert "git clone --branch \"${BRANCH}\" \"${REPO_URL}\" \"${APP_DIR}\"" in bootstrap_installer
    assert "git -C \"${APP_DIR}\" fetch origin \"${BRANCH}\"" in bootstrap_installer
    assert "-m waechter.installer" in bootstrap_installer
    assert "install -m 0755 \"${repo_bootstrap}\" \"${SCRIPT_INSTALL_PATH}\"" in bootstrap_installer
    assert 'if [[ "${WAECHTER_BOOTSTRAP_REPO_UPDATED:-0}" == "1" ]]; then' in bootstrap_installer
    assert 'if ! "${python_bin}" -c "import waechter.installer" >/dev/null 2>&1; then' in bootstrap_installer
    assert 'exec bash "${BOOTSTRAP_SCRIPT}" "$@"' in compatibility_wrapper


