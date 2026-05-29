from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ClamAVSettings:
    weight: float
    enabled: bool
    socket_path: str
    max_bytes: int
    max_redirects: int
    download_timeout_seconds: int
    scan_timeout_seconds: int


class ClamAVDownloadError(Exception):
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.details = details or {}
