from typing import Any, Dict
import asyncio
import ipaddress
import urllib.parse

import aiohttp

from src.providers.base import ScanProvider


class HeuristicProvider(ScanProvider):
    name = "heuristic"
    weight = 0.6
    enabled = True
    redirect_warning_threshold = 3
    redirect_high_threshold = 5
    redirect_max = 10

    async def scan(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        score = 0.0
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""

            # IP address check
            if self._is_ip_address(hostname):
                score += 0.6

            # Suspicious TLDs
            suspicious_tlds = ('.tk', '.ml', '.ga', '.cf')
            if hostname.endswith(suspicious_tlds):
                score += 0.5

            # Long URLs
            if len(url) > 500:
                score += 0.4

            score += await self._redirect_score(url, parsed, session)
        except Exception:
            score += 0.8 # Parsing failed, slightly suspicious

        return {"raw_score": min(score, 1.0)}

    def _is_ip_address(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            return True
        except ValueError:
            return False

    async def _redirect_score(self, url: str, parsed: urllib.parse.ParseResult, session: aiohttp.ClientSession) -> float:
        if parsed.scheme not in ("http", "https"):
            return 0.0

        original_hostname = parsed.hostname or ""
        timeout = aiohttp.ClientTimeout(total=5)
        score = 0.0

        try:
            async with session.get(
                url,
                allow_redirects=True,
                max_redirects=self.redirect_max,
                timeout=timeout,
            ) as resp:
                redirect_count = len(resp.history)
                redirect_urls = [str(history.url) for history in resp.history] + [str(resp.url)]
        except aiohttp.TooManyRedirects as e:
            redirect_count = len(e.history)
            redirect_urls = [str(history.url) for history in e.history]
            score += 0.8
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return 0.0

        if redirect_count > self.redirect_high_threshold:
            score += 0.5
        elif redirect_count > self.redirect_warning_threshold:
            score += 0.2

        for redirect_url in redirect_urls[1:]:
            redirect_hostname = urllib.parse.urlparse(redirect_url).hostname or ""
            if redirect_hostname != original_hostname and self._is_ip_address(redirect_hostname):
                score += 0.7
                break

        return score
