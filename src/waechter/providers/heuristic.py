from typing import Any, Dict, List, Tuple
import asyncio
import ipaddress
import urllib.parse
import re
import logging
from datetime import datetime, timezone

import aiohttp
import idna
import tldextract
import whois

from waechter.providers.base import ScanProvider
from waechter.config_loader import (
    as_bool,
    load_brand_domains,
    load_brand_keywords,
    load_keywords_list,
    provider_cfg,
)

logger = logging.getLogger(__name__)
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)

class HeuristicProvider(ScanProvider):
    name = "heuristic"
    # Default values mirror the previous hard-coded behavior, used if config is absent
    def __init__(self):
        cfg = provider_cfg(self.name)

        self.weight = float(cfg.get("weight", 0.6))
        self.enabled = as_bool(cfg.get("enabled", True))

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

        self.whois_age_lt_3d = float(whois_scores.get("age_lt_3d", 1.5))
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
        self.html_form_and_password = float(html_scores.get("form_and_password", 0.8))
        self.html_form_and_email = float(html_scores.get("form_and_email", 0.5))
        self.html_xhr_or_fetch = float(html_scores.get("xhr_or_fetch", 0.3))
        self.html_same_domain_multiplier = float(html_scores.get("same_domain_multiplier", 0.5))
        self.html_cross_domain_multiplier = float(html_scores.get("cross_domain_multiplier", 1.0))
        self.html_official_domain_multiplier = float(html_scores.get("official_domain_multiplier", 0.1))

        # lists / keyword files
        lists_section = cfg.get("lists", {}) or {}
        self.suspicious_tlds: List[str] = list(lists_section.get("suspicious_tlds", [".tk", ".ml", ".ga", ".cf"]))

        kw_files = cfg.get("keyword_files", {}) or {}
        brand_fp = kw_files.get("brand", "data/keywords/heuristic/brand_keywords.csv")
        brand_domains_fp = kw_files.get("brand_domains", "data/keywords/heuristic/brand_domains.csv")
        path_fp = kw_files.get("path", "data/keywords/heuristic/path_keywords.csv")
        url_fp = kw_files.get("url", "data/keywords/heuristic/url_keywords.csv")

        self.brand_keywords = load_brand_keywords(brand_fp)
        self.brand_domains = load_brand_domains(brand_domains_fp)
        self.path_keywords = set(load_keywords_list(path_fp))
        self.url_keywords = set(load_keywords_list(url_fp))

    async def scan(self, url: str, session: aiohttp.ClientSession, link_id: str | None = None) -> Dict[str, Any]:
        signals = {}

        try:
            parsed = urllib.parse.urlparse(url)
            raw_hostname = (parsed.hostname or "").strip().strip(".").lower()
            hostname = self._normalize_hostname(raw_hostname)
            brand_ctx = self._brand_context(hostname)
            official_brand_domain = bool(brand_ctx["official"])

            if parsed.username or parsed.password:
                self._add_signal(signals, "url_userinfo_present", 0.8)

            if "xn--" in raw_hostname or "xn--" in hostname:
                self._add_signal(signals, "punycode_hostname", 0.5)

            # 1. IP address check
            if self._is_ip_address(hostname):
                self._add_signal(signals, "ip_address", self.sc_ip_address)

            # 2. Suspicious TLDs
            if any(hostname.endswith(tld) for tld in self.suspicious_tlds):
                if not official_brand_domain:
                    self._add_signal(signals, "suspicious_tld", self.sc_suspicious_tld)

            # 3. Long URLs
            if len(url) > self.long_url_chars:
                self._add_signal(signals, "long_url", self.sc_long_url)

            # 4. Brand Impersonation
            brand_score = float(brand_ctx["impersonation_score"])
            if brand_score > 0:
                self._add_signal(signals, "brand_impersonation", brand_score)

            # 5. Path Heuristics
            path_score = self._check_path_heuristics(parsed.path)
            if official_brand_domain:
                path_score *= 0.1
            if path_score > 0:
                self._add_signal(signals, "suspicious_path", path_score)

            # 5b. Subdomain Heuristics
            subdomain_score = self._check_subdomain_heuristics(hostname)
            if official_brand_domain:
                subdomain_score *= 0.1
            if subdomain_score > 0:
                self._add_signal(signals, "suspicious_subdomain", subdomain_score)

            # 6. AWS Lambda Phishing
            if re.search(r'\.lambda-url\..*\.on\.aws$', hostname, re.IGNORECASE):
                self._add_signal(signals, "aws_lambda_phishing", self.sc_aws_lambda)

            # 7. URL Keywords
            url_kw_score = self._check_url_keywords(url)
            if official_brand_domain:
                url_kw_score *= 0.1
            if url_kw_score > 0:
                self._add_signal(signals, "suspicious_url_keywords", url_kw_score)

            # 8. Domain Age (WHOIS)
            if not official_brand_domain and not self._is_ip_address(hostname):
                whois_score = await self._check_whois_age(hostname)
                if whois_score > 0:
                    self._add_signal(signals, "whois_age_suspicious", whois_score)

            # 9. Redirects & Mismatch
            redirect_score = await self._redirect_score(url, parsed, session, signals)
            if official_brand_domain:
                redirect_score *= 0.3
            if redirect_score > 0:
                self._add_signal(signals, "redirect_suspicious", redirect_score)

            # 10. HTML Content
            html_score = await self._analyze_html_content(url, session, official_brand_domain=official_brand_domain, matched_brands=brand_ctx.get("brands", []))
            if official_brand_domain:
                html_score *= 0.1
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

    def _normalize_hostname(self, hostname: str) -> str:
        hostname = hostname.strip().strip(".").lower()

        try:
            return idna.decode(hostname.encode("ascii")).lower()
        except Exception:
            return hostname

    def _get_registrable_domain(self, hostname: str) -> str:
        hostname = self._normalize_hostname(hostname)
        ext = _TLD_EXTRACT(hostname)

        if not ext.domain or not ext.suffix:
            return hostname

        return f"{ext.domain}.{ext.suffix}".lower()

    def _is_official_brand_domain(self, brand: str, hostname: str) -> bool:
        hostname = self._normalize_hostname(hostname)
        registrable_domain = self._get_registrable_domain(hostname)

        for entry in self.brand_domains.get(brand, []):
            domain = entry.domain.lower()

            if entry.match_mode == "etld1" and registrable_domain == domain:
                return True
            if entry.match_mode == "exact" and hostname == domain:
                return True

        return False

    def _brand_context(self, hostname: str) -> Dict[str, Any]:
        hostname_lower = self._normalize_hostname(hostname)
        # Each entry: (keyword, brand_name, score)
        # brand_name may be empty for generic keywords (e.g. "login", "secure")
        matched_brands: List[Tuple[str, float]] = []
        matched_brand_names: List[str] = []  # brand_name for official-domain lookup

        for keyword, (brand_name, score) in self.brand_keywords.items():
            keyword = keyword.lower().strip()
            if keyword and keyword in hostname_lower:
                matched_brands.append((keyword, float(score)))
                matched_brand_names.append(brand_name)

        if not matched_brands:
            return {
                "matched": False,
                "official": False,
                "impersonation_score": 0.0,
                "brands": [],
            }

        # Check which brand names (not keywords) are official for this hostname.
        # Generic keywords with no brand affiliation (brand_name == "") are never official.
        official_brands: set = set()
        for keyword, brand_name in zip([kw for kw, _ in matched_brands], matched_brand_names):
            if brand_name and self._is_official_brand_domain(brand_name, hostname_lower):
                official_brands.add(keyword)

        # Bug fix #2: official flag depends ONLY on whether we found an official brand,
        # NOT on whether generic keywords also have a non-zero score.
        is_official = bool(official_brands)

        # Bug fix #3: if the domain IS official, impersonation score must be 0 –
        # generic keywords like "secure" or "login" in a subdomain of an official
        # domain must not be counted as impersonation.
        if is_official:
            max_impersonation_score = 0.0
        else:
            max_impersonation_score = max(
                (
                    score
                    for (keyword, score), brand_name in zip(matched_brands, matched_brand_names)
                    if brand_name  # only count keywords that have a brand affiliation
                ),
                default=0.0,
            )

        return {
            "matched": True,
            "official": is_official,
            "impersonation_score": max_impersonation_score,
            "brands": [kw for kw, _ in matched_brands],
        }

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
                domain = self._get_registrable_domain(hostname)
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

            age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - creation_date).days
            if age_days < 3:
                return self.whois_age_lt_3d
            elif age_days < 7:
                return  self.whois_age_lt_7d
            elif age_days < 30:
                return self.whois_age_lt_30d
        except Exception as e:
            logger.debug(f"WHOIS fail for {hostname}: {e}")
            return self.whois_fail_default

        return 0.0

    async def _redirect_score(self, url: str, parsed: urllib.parse.ParseResult, session: aiohttp.ClientSession, signals: Dict[str, float]) -> float:
        if parsed.scheme not in ("http", "https"):
            return 0.0

        original_hostname = self._normalize_hostname(parsed.hostname or "")
        original_brand_ctx = self._brand_context(original_hostname)
        matched_brands = list(original_brand_ctx.get("brands", []))
        timeout = aiohttp.ClientTimeout(total=5)
        score = 0.0

        redirect_count = 0
        redirect_urls = [url]
        current_url = url

        try:
            while True:
                async with session.request(
                    "HEAD",
                    current_url,
                    allow_redirects=False,
                    timeout=timeout,
                ) as resp:
                    if resp.status < 300 or resp.status >= 400:
                        break

                    location = resp.headers.get("Location")
                    if not location:
                        break

                    redirect_count += 1
                    current_url = urllib.parse.urljoin(current_url, location)
                    redirect_urls.append(current_url)

                    if redirect_count > self.redirect_max:
                        score += self.redir_too_many
                        break
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return 0.0

        if redirect_count > self.redirect_high_threshold:
            score += self.redir_many
        elif redirect_count > self.redirect_warning_threshold:
            score += self.redir_warning

        if len(redirect_urls) > 1:
            final_redirect_hostname = self._normalize_hostname(urllib.parse.urlparse(redirect_urls[-1]).hostname or "")
            if final_redirect_hostname != original_hostname:
                final_is_same_brand_family = self._hostname_belongs_to_any_matched_brand(
                    final_redirect_hostname,
                    matched_brands,
                )
                if (
                    not final_is_same_brand_family
                    and self._get_registrable_domain(final_redirect_hostname)
                    != self._get_registrable_domain(original_hostname)
                ):
                    self._add_signal(signals, "redirect_domain_mismatch", self.redir_domain_mismatch)

            for redirect_url in redirect_urls[1:]:
                redirect_hostname = self._normalize_hostname(urllib.parse.urlparse(redirect_url).hostname or "")
                if redirect_hostname != original_hostname and self._is_ip_address(redirect_hostname):
                    score += self.redir_to_ip
                    break

        return score

    async def _analyze_html_content(self, url: str, session: aiohttp.ClientSession, official_brand_domain: bool = False, matched_brands: List[str] = None) -> float:
        score = 0.0
        timeout = aiohttp.ClientTimeout(total=5)
        try:
            async with session.get(url, timeout=timeout) as resp:
                if resp.status != 200 or "text/html" not in resp.headers.get("Content-Type", ""):
                    return 0.0

                content = await resp.content.read(200 * 1024)
                html = content.decode('utf-8', errors='ignore').lower()

                has_pwd = 'type="password"' in html
                has_email_user = 'name="email"' in html or 'type="email"' in html or 'name="username"' in html

                # Identify forms and their actions
                # Simple regex for forms: <form ... action="..." ...>
                forms = re.findall(r'<form[^>]*>', html)

                form_multiplier = 1.0
                if forms:
                    # Check the action of forms to see if they are internal or external.
                    # Phishing forms often have no action (submits to self) or a cross-domain action.
                    # Legitimate forms on official domains are usually fine.

                    if official_brand_domain:
                        form_multiplier = self.html_official_domain_multiplier
                    else:
                        parsed_url = urllib.parse.urlparse(url)
                        current_hostname = (parsed_url.hostname or "").lower()
                        current_domain = self._get_registrable_domain(current_hostname)

                        cross_domain_action = False
                        for form in forms:
                            action_match = re.search(r'action=["\']([^"\']+)["\']', form)
                            if action_match:
                                action = action_match.group(1).strip()
                                if action and not action.startswith(("/", "#", "javascript:")):
                                    try:
                                        action_url = urllib.parse.urljoin(url, action)
                                        action_hostname = (urllib.parse.urlparse(action_url).hostname or "").lower()
                                        action_domain = self._get_registrable_domain(action_hostname)

                                        if action_domain and action_domain != current_domain:
                                            # Cross-domain action is suspicious
                                            cross_domain_action = True
                                            break
                                    except Exception:
                                        pass

                        if cross_domain_action:
                            form_multiplier = self.html_cross_domain_multiplier
                        else:
                            # Same domain or no external action -> reduce score
                            form_multiplier = self.html_same_domain_multiplier

                if has_pwd:
                    score = max(score, self.html_form_and_password * form_multiplier)
                elif has_email_user:
                    score = max(score, self.html_form_and_email * form_multiplier)

                if "fetch(" in html or "xmlhttprequest" in html:
                    # XHR/Fetch also affected by brand status, but less by form action context
                    xhr_multiplier = self.html_official_domain_multiplier if official_brand_domain else 1.0
                    score = max(score, self.html_xhr_or_fetch * xhr_multiplier)

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        return score

    def _hostname_belongs_to_any_matched_brand(self, hostname: str, brands: List[str]) -> bool:
        for brand in brands:
            if self._is_official_brand_domain(brand, hostname):
                return True
        return False

    def _check_subdomain_heuristics(self, hostname: str) -> float:
        ext = _TLD_EXTRACT(hostname)
        subdomain = ext.subdomain
        if not subdomain:
            return 0.0
            
        score = 0.0
        if len(subdomain) > 10:
            score = 0.2
            # Check for special characters (not letters or digits)
            # We use isalnum() but we must consider that a subdomain can have dots 
            # if it has multiple levels. However, tldextract gives the full subdomain part.
            # If the user says "special characters", typically non-alphanumeric.
            if not subdomain.replace(".", "").isalnum():
                score = 0.4
        return score
