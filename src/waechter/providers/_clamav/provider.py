from __future__ import annotations

from typing import Any
import asyncio
import logging
import urllib.parse

import aiohttp

from waechter.logger import get_logger
from waechter.providers.base import ProviderResult, RedirectLimitExceededError, ScanProvider
from waechter.providers._clamav.clamd import scan_bytes_with_clamd
from waechter.providers._clamav.config import load_clamav_settings
from waechter.providers._clamav.downloader import ClamAVDownloader
from waechter.providers._clamav.models import ClamAVDownloadError


logger = get_logger()


class ClamAVProvider(ScanProvider):
    name = "clamav"
    weight = 1.0
    enabled = True
    optional_env_vars = (
        "URLCHECK_CLAMAV_ENABLED",
        "URLCHECK_CLAMAV_CONNECTION_SOCKET_PATH",
        "URLCHECK_CLAMAV_LIMITS_MAX_BYTES",
        "URLCHECK_CLAMAV_LIMITS_MAX_REDIRECTS",
        "URLCHECK_CLAMAV_TIMEOUTS_DOWNLOAD_SEC",
        "URLCHECK_CLAMAV_TIMEOUTS_SCAN_SEC",
    )

    def __init__(
        self,
        socket_path: str | None = None,
        max_bytes: int | None = None,
        max_redirects: int | None = None,
        download_timeout_seconds: int | None = None,
        scan_timeout_seconds: int | None = None,
        enabled: bool | None = None,
    ):
        self.settings = load_clamav_settings(
            socket_path=socket_path,
            max_bytes=max_bytes,
            max_redirects=max_redirects,
            download_timeout_seconds=download_timeout_seconds,
            scan_timeout_seconds=scan_timeout_seconds,
            enabled=enabled,
        )
        self.weight = self.settings.weight
        self.enabled = self.settings.enabled
        self.socket_path = self.settings.socket_path
        self.max_bytes = self.settings.max_bytes
        self.max_redirects = self.settings.max_redirects
        self.download_timeout_seconds = self.settings.download_timeout_seconds
        self.scan_timeout_seconds = self.settings.scan_timeout_seconds
        self.downloader = ClamAVDownloader(self.settings)

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        link_id: str | None = None,
    ) -> ProviderResult:
        log_context = {"provider": self.name, "link_id": link_id, "url": url}
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            logger.debug(
                "clamav_skipped_unsupported_scheme",
                extra={"extra_data": {**log_context, "scheme": parsed.scheme}},
            )
            return self.build_result(0.0, raw_response="skipped: unsupported_scheme")

        try:
            data, truncated, download_info = await self.downloader.download_limited(
                url,
                session,
            )
        except (aiohttp.TooManyRedirects, RedirectLimitExceededError) as exc:
            logger.warning(
                "clamav_skipped_too_many_redirects",
                extra={
                    "extra_data": {
                        **log_context,
                        "max_redirects": self.max_redirects,
                        "error_type": type(exc).__name__,
                    }
                },
            )
            return self.build_result(
                0.9,
                raw_response=f"skipped: more_than_{self.max_redirects}_redirects",
            )
        except ClamAVDownloadError as exc:
            logger.error(
                "clamav_download_http_error",
                extra={"extra_data": {**log_context, **exc.details}},
            )
            return self.no_verdict(str(exc), raw_response=exc.details)
        except Exception as exc:
            logger.error(
                "clamav_download_error",
                extra={
                    "extra_data": {
                        **log_context,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }
                },
            )
            return self.no_verdict(
                f"download_failed: {type(exc).__name__}: {exc}",
                raw_response={"error": str(exc)},
            )

        logger.debug(
            "clamav_download_complete",
            extra={
                "extra_data": {
                    **log_context,
                    "downloaded_bytes": len(data),
                    "truncated": truncated,
                    "max_bytes": self.max_bytes,
                    **download_info,
                }
            },
        )

        try:
            result = await asyncio.to_thread(scan_bytes_with_clamd, self.settings, data)
        except Exception as exc:
            logger.error(
                "clamav_scan_error",
                extra={
                    "extra_data": {
                        **log_context,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }
                },
            )
            return self.no_verdict(
                f"scan_failed: {type(exc).__name__}: {exc}",
                raw_response={"error": str(exc)},
            )

        logger.debug(
            "clamav_scan_response",
            extra={
                "extra_data": {
                    **log_context,
                    "downloaded_bytes": len(data),
                    "socket_path": self.socket_path,
                    "clamav_response": result,
                }
            },
        )

        if "FOUND" in result:
            return self.build_result(1.0, raw_response=result)
        if truncated:
            return self.build_result(
                0.1,
                raw_response=f"partial_scan: first_{self.max_bytes}_bytes; clamav={result}",
            )
        return self.build_result(0.0, raw_response=result)
