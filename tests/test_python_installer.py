import subprocess

import pytest

from waechter.installer import env
from waechter.installer.models import InstallerConfig
from waechter.installer.playwright import ensure_screenshot_dir, runtime_dependency_packages
from waechter.installer.runtime import CommandRunner
from waechter.installer.systemd import render_service_unit


def build_config(**overrides) -> InstallerConfig:
    base = dict(
        worker_base_url="https://example.test",
        waechter_token="token",
        google_safe_browsing_api_key="",
        clamav_enabled=False,
        clamav_socket_path="",
        screenshot_enabled=True,
        screenshot_dir="./screenshots",
        screenshot_timeout_ms="10000",
        screenshot_no_sandbox=False,
        scan_concurrency="10",
        batch_size="25",
        min_wait_ms="5000",
        max_wait_ms="60000",
        log_level="INFO",
        threshold_warning="0.70",
        threshold_block="0.95",
        redis_enabled=False,
        redis_url="",
        redis_ttl_sec="300",
        repo_updated=False,
        mode="auto",
    )
    base.update(overrides)
    return InstallerConfig(**base)


def test_parse_env_lines_strips_quotes_and_windows_line_endings():
    values = env.parse_env_lines(
        [
            'WAECHTER_TOKEN="secret"\r',
            "SCREENSHOT_ENABLED='true'\r",
            "NOT_A_MATCH",
        ]
    )

    assert values["WAECHTER_TOKEN"] == "secret"
    assert values["SCREENSHOT_ENABLED"] == "true"
    assert "NOT_A_MATCH" not in values


def test_build_config_prefers_process_environment_over_env_file(monkeypatch):
    monkeypatch.setattr(env, "load_env_file", lambda env_file=env.ENV_FILE: {"SCREENSHOT_ENABLED": "false", "BATCH_SIZE": "25"})

    config = env.build_config(environ={"SCREENSHOT_ENABLED": "true", "BATCH_SIZE": "50"})

    assert config.screenshot_enabled is True
    assert config.batch_size == "50"


def test_runtime_dependency_packages_resolve_noble_t64_fallbacks(monkeypatch):
    monkeypatch.setattr(
        "waechter.installer.playwright.apt_package_available",
        lambda runner, package: package.endswith("t64") or package in {"libnspr4", "libnss3", "libgbm1", "libdrm2", "libxkbcommon0", "libxcomposite1", "libxdamage1", "libxfixes3", "libxrandr2", "libx11-xcb1", "libxshmfence1", "libpango-1.0-0", "libcairo2"},
    )

    packages = runtime_dependency_packages(runner=None)  # type: ignore[arg-type]

    assert "libasound2t64" in packages
    assert "libatk-bridge2.0-0t64" in packages
    assert "libgtk-3-0t64" in packages


def test_render_service_unit_keeps_expected_paths_for_external_screenshot_dir():
    config = build_config(screenshot_dir="/srv/waechter-shots")

    unit = render_service_unit(config)

    assert "WorkingDirectory=/opt/waechter" in unit
    assert "EnvironmentFile=/etc/waechter/waechter.env" in unit
    assert "ExecStart=/opt/waechter/.venv/bin/python /opt/waechter/main.py" in unit
    assert "ReadWritePaths=/opt/waechter /etc/waechter /srv/waechter-shots" in unit
    assert "ProtectHome=true" in unit


def test_render_service_unit_disables_protect_home_for_home_screenshot_dir():
    config = build_config(screenshot_dir="/home/shared/waechter-shots")

    unit = render_service_unit(config)

    assert "ProtectHome=false" in unit
    assert "ReadWritePaths=/opt/waechter /etc/waechter /home/shared/waechter-shots" in unit


def test_run_as_user_prefers_su_before_sudo(monkeypatch):
    runner = CommandRunner()
    seen: list[list[str]] = []

    monkeypatch.setattr(runner, "command_exists", lambda name: name in {"su", "sudo"})

    def fake_run(args, **kwargs):
        seen.append(list(args))
        return subprocess.CompletedProcess(list(args), 0, stdout="", stderr="")

    monkeypatch.setattr(runner, "run", fake_run)

    runner.run_as_user("waechter", ["python", "-V"])

    assert seen == [["su", "-s", "/bin/sh", "-c", "python -V", "waechter"]]


def test_command_runner_logs_stdout_stderr_on_failure(monkeypatch, caplog, capsys):
    runner = CommandRunner()

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(list(args[0]), 7, stdout="apt out\n", stderr="apt err\n"),
    )

    with caplog.at_level("ERROR"):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            runner.run(["apt-get", "install", "foo"])

    captured = capsys.readouterr()
    assert exc_info.value.returncode == 7
    assert exc_info.value.stderr == "apt err\n"
    assert "apt out\n" in captured.out
    assert "apt err\n" in captured.err
    assert any(record.msg == "command_failed" for record in caplog.records)


def test_ensure_screenshot_dir_verifies_writability_with_runner(monkeypatch, tmp_path):
    config = build_config(screenshot_dir=str(tmp_path / "shots"))
    runner = CommandRunner()
    calls: list[list[str]] = []

    monkeypatch.setattr(
        "waechter.installer.playwright.ensure_path_owner",
        lambda path, username, groupname, recursive=False: None,
    )

    def fake_run_as_user(user, args, **kwargs):
        calls.append(list(args))
        return subprocess.CompletedProcess(list(args), 0, stdout="", stderr="")

    monkeypatch.setattr(runner, "run_as_user", fake_run_as_user)

    created = ensure_screenshot_dir(config, runner)

    assert created is True
    assert calls
    assert calls[0][0] == "python3"


