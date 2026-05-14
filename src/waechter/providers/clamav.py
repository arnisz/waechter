from typing import Any, Dict
import asyncio
import socket
import struct
import urllib.parse

import aiohttp

from waechter.logger import get_logger
from waechter.providers.base import RedirectLimitExceededError, ScanProvider
from waechter.config_loader import as_bool, provider_cfg


logger = get_logger()


class ClamAVProvider(ScanProvider):
    name = "clamav"
    weight = 1.0
    enabled = True

    def __init__(
        self,
        socket_path: str | None = None,
        max_bytes: int | None = None,
        max_redirects: int | None = None,
        download_timeout_seconds: int | None = None,
        scan_timeout_seconds: int | None = None,
    ):
        cfg = provider_cfg(self.name)
        self.weight = float(cfg.get("weight", 1.0))
        self.enabled = as_bool(cfg.get("enabled", True))

        conn = (cfg.get("connection", {}) or {})
        limits = (cfg.get("limits", {}) or {})
        timeouts = (cfg.get("timeouts", {}) or {})

        # Apply config defaults, then override with provided args if given
        self.socket_path = socket_path or conn.get("socket_path", "/var/run/clamav/clamd.ctl")
        self.max_bytes = int(max_bytes if max_bytes is not None else limits.get("max_bytes", 5 * 1024 * 1024))
        self.max_redirects = int(max_redirects if max_redirects is not None else limits.get("max_redirects", 7))
        self.download_timeout_seconds = int(download_timeout_seconds if download_timeout_seconds is not None else timeouts.get("download_sec", 10))
        self.scan_timeout_seconds = int(scan_timeout_seconds if scan_timeout_seconds is not None else timeouts.get("scan_sec", 10))

    async def scan(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            logger.debug("clamav_skipped_unsupported_scheme", extra={"extra_data": {
                "url": url,
                "scheme": parsed.scheme,
            }})
            return {"raw_score": 0.0, "raw_response": "skipped: unsupported_scheme"}

        try:
            data, truncated, download_info = await self._download_limited(url, session)
        except (aiohttp.TooManyRedirects, RedirectLimitExceededError):
            logger.debug("clamav_skipped_too_many_redirects", extra={"extra_data": {
                "url": url,
                "max_redirects": self.max_redirects,
            }})
            return {"raw_score": 0.9, "raw_response": f"skipped: more_than_{self.max_redirects}_redirects"}

        logger.debug("clamav_download_complete", extra={"extra_data": {
            "url": url,
            "downloaded_bytes": len(data),
            "truncated": truncated,
            "max_bytes": self.max_bytes,
            **download_info,
        }})
        result = await asyncio.to_thread(self._scan_bytes_with_clamd, data)
        logger.debug("clamav_scan_response", extra={"extra_data": {
            "url": url,
            "downloaded_bytes": len(data),
            "socket_path": self.socket_path,
            "clamav_response": result,
        }})

        if "FOUND" in result:
            return {"raw_score": 1.0, "raw_response": result}
        if truncated:
            return {"raw_score": 0.1, "raw_response": f"partial_scan: first_{self.max_bytes}_bytes; clamav={result}"}
        return {"raw_score": 0.0, "raw_response": result}

    async def _download_limited(self, url: str, session: aiohttp.ClientSession) -> tuple[bytes, bool, Dict[str, Any]]:
        timeout = aiohttp.ClientTimeout(total=self.download_timeout_seconds)
        data = bytearray()
        truncated = False

        async with session.get(
            url,
            allow_redirects=True,
            max_redirects=self.max_redirects,
            timeout=timeout,
        ) as resp:
            if len(resp.history) > self.max_redirects:
                raise RedirectLimitExceededError()
            download_info = {
                "http_status": resp.status,
                "final_url": str(resp.url),
                "redirect_count": len(resp.history),
                "content_type": resp.headers.get("Content-Type"),
                "content_length": resp.headers.get("Content-Length"),
            }
            resp.raise_for_status()
            async for chunk in resp.content.iter_chunked(8192):
                remaining = self.max_bytes - len(data)
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    data.extend(chunk[:remaining])
                    truncated = True
                    break
                data.extend(chunk)

        return bytes(data), truncated, download_info

    def _scan_bytes_with_clamd(self, data: bytes) -> str:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.scan_timeout_seconds)
            logger.debug("clamav_socket_connect", extra={"extra_data": {
                "socket_path": self.socket_path,
                "bytes_to_scan": len(data),
            }})
            sock.connect(self.socket_path)
            sock.sendall(b"zINSTREAM\0")

            chunk_size = 8192
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                sock.sendall(struct.pack("!I", len(chunk)))
                sock.sendall(chunk)

            sock.sendall(struct.pack("!I", 0))
            return sock.recv(4096).decode("utf-8", errors="replace")
