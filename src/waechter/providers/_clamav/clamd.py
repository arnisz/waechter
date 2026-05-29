from __future__ import annotations

import socket
import struct
import logging

from waechter.providers._clamav.models import ClamAVSettings


logger = logging.getLogger(__name__)


def scan_bytes_with_clamd(settings: ClamAVSettings, data: bytes) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(settings.scan_timeout_seconds)
        logger.debug(
            "clamav_socket_connect",
            extra={
                "extra_data": {
                    "socket_path": settings.socket_path,
                    "bytes_to_scan": len(data),
                }
            },
        )
        sock.connect(settings.socket_path)
        sock.sendall(b"zINSTREAM\0")

        chunk_size = 8192
        for index in range(0, len(data), chunk_size):
            chunk = data[index:index + chunk_size]
            sock.sendall(struct.pack("!I", len(chunk)))
            sock.sendall(chunk)

        sock.sendall(struct.pack("!I", 0))
        return sock.recv(4096).decode("utf-8", errors="replace")
