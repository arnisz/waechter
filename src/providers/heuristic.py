from typing import Any, Dict
import asyncio
import ipaddress
import urllib.parse
import re
import logging
from datetime import datetime, timezone

import aiohttp
import whois

from src.providers.base import ScanProvider

logger = logging.getLogger(__name__)

class HeuristicProvider(ScanProvider):
    name = "heuristic"
    weight = 0.6
    enabled = True
    redirect_warning_threshold = 3
    redirect_high_threshold = 5
    redirect_max = 10

    BRAND_KEYWORDS = {
        "disney": 0.8, "netflix": 0.8, "paypal": 0.8, "apple": 0.8,
        "microsoft": 0.8, "bank": 0.7, "gov": 0.6, "support": 0.4,
        "verify": 0.5, "secure": 0.5, "login": 0.5, "account": 0.5, "billing": 0.5
    }
    PATH_KEYWORDS = {"/login", "/verify", "/account", "/secure", "/update", "/signin", "/auth"}
    URL_KEYWORDS = {"verify", "support", "secure", "billing", "update", "identity", "unlock", "confirm"}

    async def scan(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        signals = {}

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""

            # 1. IP address check
            if self._is_ip_address(hostname):
                self._add_signal(signals, "ip_address", 0.6)

            # 2. Suspicious TLDs
            suspicious_tlds = ('.tk', '.ml', '.ga', '.cf')
            if hostname.endswith(suspicious_tlds):
                self._add_signal(signals, "suspicious_tld", 0.5)

            # 3. Long URLs
            if len(url) > 500:
                self._add_signal(signals, "long_url", 0.4)

            # 4. Brand Impersonation
            brand_score = self._check_brand_impersonation(hostname)
            if brand_score > 0:
                self._add_signal(signals, "brand_impersonation", brand_score)

            # 5. Path Heuristics
            path_score = self._check_path_heuristics(parsed.path)
            if path_score > 0:
                self._add_signal(signals, "suspicious_path", path_score)

            # 6. AWS Lambda Phishing
            if re.search(r'\.lambda-url\..*\.on\.aws$', hostname, re.IGNORECASE):
                self._add_signal(signals, "aws_lambda_phishing", 0.8)

            # 7. URL Keywords
            url_kw_score = self._check_url_keywords(url)
            if url_kw_score > 0:
                self._add_signal(signals, "suspicious_url_keywords", url_kw_score)

            # 8. Domain Age (WHOIS)
            if not self._is_ip_address(hostname):
                whois_score = await self._check_whois_age(hostname)
                if whois_score > 0:
                    self._add_signal(signals, "whois_age_suspicious", whois_score)

            # 9. Redirects & Mismatch
            redirect_score = await self._redirect_score(url, parsed, session, signals)
            if redirect_score > 0:
                self._add_signal(signals, "redirect_suspicious", redirect_score)

            # 10. HTML Content
            html_score = await self._analyze_html_content(url, session)
            if html_score > 0:
                self._add_signal(signals, "malicious_html_content", html_score)

        except Exception as e:
            logger.warning(f"Error analyzing URL {url}: {e}")
            self._add_signal(signals, "parsing_failed", 0.8)

        total_score = min(sum(signals.values()), 1.0)
        return {"raw_score": total_score, "signals": signals}

    def _add_signal(self, signals: Dict[str, float], name: str, value: float):
        if value > 0:
            signals[name] = max(signals.get(name, 0.0), value)
            logger.info(f"Signal detected: {name} (+{value})")

    def _is_ip_address(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            return True
        except ValueError:
            return False

    def _check_brand_impersonation(self, hostname: str) -> float:
        hostname_lower = hostname.lower()
        max_score = 0.0
        for keyword, score in self.BRAND_KEYWORDS.items():
            if keyword in hostname_lower:
                max_score = max(max_score, score)
        return max_score

    def _check_path_heuristics(self, path: str) -> float:
        path_lower = path.lower()
        if any(kw in path_lower for kw in self.PATH_KEYWORDS):
            return 0.3
        return 0.0

    def _check_url_keywords(self, url: str) -> float:
        url_lower = url.lower()
        if any(kw in url_lower for kw in self.URL_KEYWORDS):
            return 0.4
        return 0.0

    async def _check_whois_age(self, hostname: str) -> float:
        def fetch_whois():
            try:
                domain_parts = hostname.split('.')
                domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
                return whois.whois(domain)
            except Exception:
                return None

        try:
            w = await asyncio.to_thread(fetch_whois)
            if not w or not w.creation_date:
                return 0.5

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if hasattr(creation_date, 'replace'):
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (datetime.utcnow() - creation_date).days
            if age_days < 7:
                return 1.0
            elif age_days < 30:
                return 0.7
        except Exception as e:
            logger.debug(f"WHOIS fail for {hostname}: {e}")
            return 0.5

        return 0.0

    async def _redirect_score(self, url: str, parsed: urllib.parse.ParseResult, session: aiohttp.ClientSession, signals: Dict[str, float]) -> float:
        if parsed.scheme not in ("http", "https"):
            return 0.0

        original_hostname = parsed.hostname or ""
        timeout = aiohttp.ClientTimeout(total=5)
        score = 0.0

        try:
            async with session.head(
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

        if len(redirect_urls) > 1:
            final_redirect_hostname = urllib.parse.urlparse(redirect_urls[-1]).hostname or ""
            if final_redirect_hostname != original_hostname:
                if self._get_base_domain(final_redirect_hostname) != self._get_base_domain(original_hostname):
                    self._add_signal(signals, "redirect_domain_mismatch", 0.5)

            for redirect_url in redirect_urls[1:]:
                redirect_hostname = urllib.parse.urlparse(redirect_url).hostname or ""
                if redirect_hostname != original_hostname and self._is_ip_address(redirect_hostname):
                    score += 0.7
                    break

        return score

    async def _analyze_html_content(self, url: str, session: aiohttp.ClientSession) -> float:
        score = 0.0
        timeout = aiohttp.ClientTimeout(total=5)
        try:
            async with session.get(url, timeout=timeout) as resp:
                if resp.status != 200 or "text/html" not in resp.headers.get("Content-Type", ""):
                    return 0.0

                content = await resp.content.read(200 * 1024)
                html = content.decode('utf-8', errors='ignore').lower()

                has_form = "<form" in html
                has_pwd = 'type="password"' in html
                has_email_user = 'name="email"' in html or 'type="email"' in html or 'name="username"' in html

                if has_form and has_pwd:
                    score = max(score, 1.0)
                elif has_form and has_email_user:
                    score = max(score, 0.7)

                if "fetch(" in html or "xmlhttprequest" in html:
                    score = max(score, 0.5)

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        return score

    def _get_base_domain(self, hostname: str) -> str:
        parts = hostname.split('.')
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
