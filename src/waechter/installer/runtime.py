from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence


logger = logging.getLogger(__name__)


class CommandRunner:
    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        capture_output: bool = False,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = list(args)
        logger.debug("run_command", extra={"args": command, "cwd": str(cwd) if cwd else None})
        completed = subprocess.run(
            list(args),
            check=False,
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=True,
        )

        if not capture_output:
            if completed.stdout:
                sys.stdout.write(completed.stdout)
            if completed.stderr:
                sys.stderr.write(completed.stderr)

        if check and completed.returncode != 0:
            logger.error(
                "command_failed",
                extra={
                    "extra_data": {
                        "args": command,
                        "cwd": str(cwd) if cwd else None,
                        "returncode": completed.returncode,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }
                },
            )
            raise subprocess.CalledProcessError(
                completed.returncode,
                command,
                output=completed.stdout,
                stderr=completed.stderr,
            )

        return completed

    def command_exists(self, name: str) -> bool:
        command = str(name)
        return shutil.which(command) is not None

    def run_as_user(
        self,
        user: str,
        args: Sequence[str],
        *,
        check: bool = True,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = list(args)
        if self.command_exists("runuser"):
            return self.run(["runuser", "-u", user, "--", *command], check=check, cwd=cwd)
        if self.command_exists("su"):
            shell_command = shlex.join(command)
            return self.run(["su", "-s", "/bin/sh", "-c", shell_command, user], check=check, cwd=cwd)
        if self.command_exists("sudo"):
            return self.run(["sudo", "-u", user, *command], check=check, cwd=cwd)
        raise RuntimeError("Neither runuser, su nor sudo is available to drop privileges")


