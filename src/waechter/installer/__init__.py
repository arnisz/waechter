from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
	from waechter.installer.__main__ import main as _main

	return _main(argv)

__all__ = ["main"]


