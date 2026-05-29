from __future__ import annotations

import argparse
import logging
import os
import sys

from waechter.installer.core import run_install
from waechter.installer.env import build_config
from waechter.installer.runtime import CommandRunner
from waechter.installer.uninstall import perform_uninstall


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Waechter system installer")
    parser.add_argument("mode", nargs="?", default="auto", choices=["auto", "uninstall"])
    return parser.parse_args(argv)


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(name)s: %(message)s",
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging()

    if os.geteuid() != 0:
        print("ERROR: This installer must be run as root.", file=sys.stderr)
        return 1

    config = build_config(mode=args.mode)
    runner = CommandRunner()

    if args.mode == "uninstall":
        perform_uninstall(config, runner)
        return 0

    run_install(config, runner)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

