from typing import Any, Dict, List
import asyncio
import ipaddress
import urllib.parse
import re
import logging
from datetime import datetime, timezone

import aiohttp
import whois

from src.providers.base import ScanProvider
from src.config_loader import cfg_get, provider_cfg, load_brand_keywords, load_keywords_list

logger = logging.getLogger(__name__)

class HeuristicProvider(ScanProvider):
    name = "heuristic"
    # Default values mirror the previous hard-coded behavior, used if config is absent
    def __init__(self):
        cfg = provider_cfg(self.name)

        self.weight = float(cfg.get("weight", 0.6))
        self.enabled = bool(cfg.get("enabled", True))

        thresholds = cfg.get("thresholds", {}) or {}
        redir = (thresholds.get("redirect", {}) or {})
        self.redirect_warning_threshold = int(redir.get("warning", 3))
        self.redirect_high_threshold = int(redir.get("high", 5))
        self.redirect_max = int(redir.get("max", 10))
        self.long_url_chars = int(thresholds.get("long_url_chars", 500))

        scores = cfg.get("scores", {}) or {}
        whois_scores = (scores.get("whois", {}) or {})
        redirect_scores = (scores.get("redirects", {}) or {})
        html_scores = (scores.get("html", {}) or {})

        # leaf scores
        self.sc_ip_address = float(scores.get("ip_address", 0.6))
        self.sc_suspicious_tld = float(scores.get("suspicious_tld", 0.5))
        self.sc_long_url = float(scores.get("long_url", 0.4))
        self.sc_aws_lambda = float(scores.get("aws_lambda_phishing", 0.8))
        self.sc_url_keywords = float(scores.get("url_keywords", 0.4))
        self.sc_path_keywords = float(scores.get("path_keywords", 0.3))
        self.sc_parsing_failed = float(scores.get("parsing_failed", 0.8))

        # whois
        self.whois_missing_creation = float(whois_scores.get("missing_creation", 0.5))
        self.whois_age_lt_7d = float(whois_scores.get("age_lt_7d", 1.0))
        self.whois_age_lt_30d = float(whois_scores.get("age_lt_30d", 0.7))
        self.whois_fail_default = float(whois_scores.get("fail_default", 0.5))

        # redirects
        self.redir_too_many = float(redirect_scores.get("too_many", 0.8))
        self.redir_many = float(redirect_scores.get("many", 0.5))
        self.redir_warning = float(redirect_scores.get("warning", 0.2))
        self.redir_domain_mismatch = float(redirect_scores.get("domain_mismatch", 0.5))
        self.redir_to_ip = float(redirect_scores.get("to_ip", 0.7))

        # html
        self.html_form_and_password = float(html_scores.get("form_and_password", 1.0))
        self.html_form_and_email = float(html_scores.get("form_and_email", 0.7))
        self.html_xhr_or_fetch = float(html_scores.get("xhr_or_fetch", 0.5))

        # lists / keyword files
        lists_section = cfg.get("lists", {}) or {}
        self.suspicious_tlds: List[str] = list(lists_section.get("suspicious_tlds", [".tk", ".ml", ".ga", ".cf"]))

        kw_files = cfg.get("keyword_files", {}) or {}
        brand_fp = kw_files.get("brand", "data/keywords/heuristic/brand_keywords.csv")
        path_fp = kw_files.get("path", "data/keywords/heuristic/path_keywords.csv")
        url_fp = kw_files.get("url", "data/keywords/heuristic/url_keywords.csv")

        self.brand_keywords = load_brand_keywords(brand_fp)
        self.path_keywords = set(load_keywords_list(path_fp))
        self.url_keywords = set(load_keywords_list(url_fp))

    async def scan(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        signals = {}

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""

            # 1. IP address check
            if self._is_ip_address(hostname):
                self._add_signal(signals, "ip_address", self.sc_ip_address)

            # 2. Suspicious TLDs
            if any(hostname.endswith(tld) for tld in self.suspicious_tlds):
                self._add_signal(signals, "suspicious_tld", self.sc_suspicious_tld)

            # 3. Long URLs
            if len(url) > self.long_url_chars:
                self._add_signal(signals, "long_url", self.sc_long_url)

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
                self._add_signal(signals, "aws_lambda_phishing", self.sc_aws_lambda)

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
            self._add_signal(signals, "parsing_failed", self.sc_parsing_failed)

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
        for keyword, score in self.brand_keywords.items():
            if keyword in hostname_lower:
                max_score = max(max_score, score)
        return max_score

    def _check_path_heuristics(self, path: str) -> float:
        path_lower = path.lower()
        if any(kw in path_lower for kw in self.path_keywords):
            return self.sc_path_keywords
        return 0.0

    def _check_url_keywords(self, url: str) -> float:
        url_lower = url.lower()
        if any(kw in url_lower for kw in self.url_keywords):
            return self.sc_url_keywords
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
                return self.whois_missing_creation

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if hasattr(creation_date, 'replace'):
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (datetime.utcnow() - creation_date).days
            if age_days < 7:
                return self.whois_age_lt_7d
            elif age_days < 30:
                return self.whois_age_lt_30d
        except Exception as e:
            logger.debug(f"WHOIS fail for {hostname}: {e}")
            return self.whois_fail_default

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
            score += self.redir_too_many
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return 0.0

        if redirect_count > self.redirect_high_threshold:
            score += self.redir_many
        elif redirect_count > self.redirect_warning_threshold:
            score += self.redir_warning

        if len(redirect_urls) > 1:
            final_redirect_hostname = urllib.parse.urlparse(redirect_urls[-1]).hostname or ""
            if final_redirect_hostname != original_hostname:
                if self._get_base_domain(final_redirect_hostname) != self._get_base_domain(original_hostname):
                    self._add_signal(signals, "redirect_domain_mismatch", self.redir_domain_mismatch)

            for redirect_url in redirect_urls[1:]:
                redirect_hostname = urllib.parse.urlparse(redirect_url).hostname or ""
                if redirect_hostname != original_hostname and self._is_ip_address(redirect_hostname):
                    score += self.redir_to_ip
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
                    score = max(score, self.html_form_and_password)
                elif has_form and has_email_user:
                    score = max(score, self.html_form_and_email)

                if "fetch(" in html or "xmlhttprequest" in html:
                    score = max(score, self.html_xhr_or_fetch)

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        return score

    def _get_base_domain(self, hostname: str) -> str:
        parts = hostname.split('.')
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
