from __future__ import annotations

from typing import Any

import aiohttp

from waechter.providers.base import RedirectLimitExceededError
from waechter.providers._clamav.models import ClamAVDownloadError, ClamAVSettings


class ClamAVDownloader:
    def __init__(self, settings: ClamAVSettings):
        self.settings = settings

    async def download_limited(
        self,
        url: str,
        session: aiohttp.ClientSession,
    ) -> tuple[bytes, bool, dict[str, Any]]:
        timeout = aiohttp.ClientTimeout(total=self.settings.download_timeout_seconds)
        data = bytearray()
        truncated = False

        async with session.get(
            url,
            allow_redirects=True,
            max_redirects=self.settings.max_redirects,
            timeout=timeout,
        ) as response:
            if len(response.history) > self.settings.max_redirects:
                raise RedirectLimitExceededError()

            download_info = {
                "http_status": response.status,
                "final_url": str(response.url),
                "redirect_count": len(response.history),
                "history_urls": [str(item.url) for item in response.history],
                "content_type": response.headers.get("Content-Type"),
                "content_length": response.headers.get("Content-Length"),
            }

            if response.status >= 400:
                preview_bytes = await response.content.read(512)
                response_preview = self.sanitize_response_preview(preview_bytes)
                block_hint = self.classify_http_failure(
                    response.status,
                    response.headers,
                    response_preview,
                )
                raise ClamAVDownloadError(
                    "clamav download failed "
                    f"(http_status={response.status}, reason={response.reason!r}, final_url={response.url}, "
                    f"redirect_count={len(response.history)}, block_hint={block_hint})",
                    details={
                        **download_info,
                        "reason": response.reason,
                        "server": response.headers.get("Server"),
                        "retry_after": response.headers.get("Retry-After"),
                        "block_hint": block_hint,
                        "response_preview": response_preview,
                    },
                )

            async for chunk in response.content.iter_chunked(8192):
                remaining = self.settings.max_bytes - len(data)
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    data.extend(chunk[:remaining])
                    truncated = True
                    break
                data.extend(chunk)

        return bytes(data), truncated, download_info

    def sanitize_response_preview(self, data: bytes, limit: int = 240) -> str:
        text = data.decode("utf-8", errors="replace")
        compact = " ".join(text.split())
        if len(compact) > limit:
            return compact[:limit] + "…"
        return compact

    def classify_http_failure(
        self,
        status: int,
        headers: aiohttp.typedefs.LooseHeaders,
        response_preview: str,
    ) -> str:
        server = str(headers.get("Server", ""))
        via = str(headers.get("Via", ""))
        header_blob = f"{server} {via}".lower()
        preview_blob = response_preview.lower()
        combined = f"{header_blob} {preview_blob}"

        bot_indicators = (
            "access denied",
            "forbidden",
            "captcha",
            "bot",
            "robot",
            "automated",
            "cloudflare",
            "akamai",
            "incapsula",
            "perimeterx",
            "datadome",
        )

        if status == 429:
            return "rate_limited"
        if status in {401, 403} and any(indicator in combined for indicator in bot_indicators):
            return "possible_bot_protection_or_access_denied"
        if status in {401, 403}:
            return "access_denied"
        if 500 <= status < 600:
            return "upstream_server_error"
        return "unexpected_http_error"
