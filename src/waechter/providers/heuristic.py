"""
Heuristic phishing/abuse scoring provider.

Improvements over the previous version (referenced inline by number):

  #1  Decoupled official-domain recognition – any hostname whose
      registrable domain (or exact name, or parent) is listed in
      brand_domains.csv is treated as "officially recognised" even if no
      brand keyword appears in the name. Protects domains like
      *.googleapis.com that wouldn't match a keyword.

  #2  Global trusted-domain allow-list (list_files.trusted_domains / legacy
      lists.trusted_domains). Matching
      hostnames short-circuit to score 0 without any further checks.

  #3  Subdomain heuristic now uses pattern + entropy detection for
      random-looking labels in addition to a length check. Meaningful
      long subdomains (docs.integration.service…) no longer trigger the
      strong signal.

  #4  HTML form-action analysis tolerates known identity providers
      (login.microsoftonline.com, accounts.google.com, auth0.com, ...)
      by applying a low multiplier instead of treating them as
      suspicious cross-domain submissions.

  #5  Bug fix: redirect_domain_mismatch was previously written directly
      into the signals dict from inside _redirect_score(), bypassing the
      official_brand_domain multiplier applied by the caller. The
      function now returns extras for the caller to apply multipliers
      to in a single place.

  #6  Added subdomain_of match mode for brand_domains entries: any
      hostname that is the domain itself or a subdomain of it is
      treated as official.

  #8  Skip WHOIS lookup for known hosting platforms (godaddysites.com,
      vercel.app, *.workers.dev, …) – the platform's etld+1 is years
      old but the user-controlled subdomain may have been spun up
      minutes ago. The subdomain heuristic handles those cases.

  #9  Result now includes a `reasons` field with human-readable
      explanations alongside the numeric signals.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple, NamedTuple, Optional
from collections import Counter
import asyncio
import ipaddress
import math
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


# ---------------------------------------------------------------------------
# Default data file paths. List content is kept in CSV files for testability
# and operational tuning without code edits.
# ---------------------------------------------------------------------------

_DEFAULT_SUSPICIOUS_TLDS_FILE = "data/keywords/heuristic/suspicious_tlds.csv"
_DEFAULT_TRUSTED_DOMAINS_FILE = "data/keywords/heuristic/trusted_domains.csv"
_DEFAULT_IDENTITY_PROVIDERS_FILE = "data/keywords/heuristic/identity_providers.csv"
_DEFAULT_HOSTING_PLATFORMS_FILE = "data/keywords/heuristic/hosting_platforms.csv"


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class _BrandMatch(NamedTuple):
    keyword: str
    brand_name: str
    score: float


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_random(label: str) -> bool:
    """Heuristic for machine-generated subdomain labels.

    Returns True for typical phishing-kit patterns: hex blobs, strongly
    consonant-skewed strings, or mixed-alnum strings with high entropy.
    Meaningful English/German labels like "documentation" or
    "integration" should NOT trigger.
    """
    if len(label) < 8:
        return False

    # Pure hex blobs (hashes, uuid fragments)
    if re.fullmatch(r"[0-9a-f]{8,}", label):
        return True

    letters = [c for c in label if c.isalpha()]
    if len(letters) >= 6:
        vowels = sum(1 for c in letters if c in "aeiou")
        if vowels / len(letters) < 0.15:
            return True

    # Mixed-alnum label with high entropy is suspicious; meaningful words
    # rarely combine letters and digits at length >= 10.
    if (len(label) >= 10
            and any(c.isdigit() for c in label)
            and any(c.isalpha() for c in label)
            and _shannon_entropy(label) >= 3.5):
        return True

    return False


def _match_domain(hostname: str, registrable: str, entry: str) -> bool:
    """Generic 'hostname matches list entry' check used for trusted /
    identity-provider / hosting-platform lookups. An entry matches if it
    equals the hostname, the registrable domain, or is a parent of the
    hostname."""
    entry = entry.lower().strip(".")
    if not entry:
        return False
    if hostname == entry or registrable == entry:
        return True
    if hostname.endswith("." + entry):
        return True
    return False


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

class HeuristicProvider(ScanProvider):
    name = "heuristic"

    def __init__(self):
        cfg = provider_cfg(self.name)

        self.weight = float(cfg.get("weight", 0.6))
        self.enabled = as_bool(cfg.get("enabled", True))

        # ----- thresholds -----
        thresholds = cfg.get("thresholds", {}) or {}
        redir = thresholds.get("redirect", {}) or {}
        self.redirect_warning_threshold = int(redir.get("warning", 3))
        self.redirect_high_threshold = int(redir.get("high", 5))
        self.redirect_max = int(redir.get("max", 10))
        self.long_url_chars = int(thresholds.get("long_url_chars", 500))

        sub = thresholds.get("subdomain", {}) or {}
        self.subdomain_long_chars = int(sub.get("long_chars", 25))
        self.subdomain_deep_levels = int(sub.get("deep_levels", 4))

        # ----- scores -----
        scores = cfg.get("scores", {}) or {}
        whois_scores = scores.get("whois", {}) or {}
        redirect_scores = scores.get("redirects", {}) or {}
        html_scores = scores.get("html", {}) or {}
        sub_scores = scores.get("subdomain", {}) or {}

        self.sc_ip_address = float(scores.get("ip_address", 0.6))
        self.sc_suspicious_tld = float(scores.get("suspicious_tld", 0.5))
        self.sc_long_url = float(scores.get("long_url", 0.4))
        self.sc_aws_lambda = float(scores.get("aws_lambda_phishing", 0.8))
        self.sc_url_keywords = float(scores.get("url_keywords", 0.4))
        self.sc_path_keywords = float(scores.get("path_keywords", 0.3))
        self.sc_parsing_failed = float(scores.get("parsing_failed", 0.8))
        self.sc_userinfo_present = float(scores.get("userinfo_present", 0.8))
        self.sc_punycode = float(scores.get("punycode_hostname", 0.5))

        self.whois_missing_creation = float(whois_scores.get("missing_creation", 0.5))
        self.whois_age_lt_3d = float(whois_scores.get("age_lt_3d", 1.5))
        self.whois_age_lt_7d = float(whois_scores.get("age_lt_7d", 1.0))
        self.whois_age_lt_30d = float(whois_scores.get("age_lt_30d", 0.7))
        self.whois_fail_default = float(whois_scores.get("fail_default", 0.5))

        self.redir_too_many = float(redirect_scores.get("too_many", 0.8))
        self.redir_many = float(redirect_scores.get("many", 0.5))
        self.redir_warning = float(redirect_scores.get("warning", 0.2))
        self.redir_domain_mismatch = float(redirect_scores.get("domain_mismatch", 0.5))
        self.redir_to_ip = float(redirect_scores.get("to_ip", 0.7))

        self.html_form_and_password = float(html_scores.get("form_and_password", 0.8))
        self.html_form_and_email = float(html_scores.get("form_and_email", 0.5))
        self.html_xhr_or_fetch = float(html_scores.get("xhr_or_fetch", 0.3))
        self.html_same_domain_multiplier = float(html_scores.get("same_domain_multiplier", 0.5))
        self.html_cross_domain_multiplier = float(html_scores.get("cross_domain_multiplier", 1.0))
        self.html_idp_multiplier = float(html_scores.get("idp_multiplier", 0.15))
        self.html_official_domain_multiplier = float(html_scores.get("official_domain_multiplier", 0.1))

        self.sub_long = float(sub_scores.get("long", 0.15))
        self.sub_random = float(sub_scores.get("random", 0.4))
        self.sub_special_chars = float(sub_scores.get("special_chars", 0.4))

        # ----- multipliers applied when domain is officially recognised -----
        multipliers = cfg.get("official_multipliers", {}) or {}
        self.m_path = float(multipliers.get("path", 0.1))
        self.m_subdomain = float(multipliers.get("subdomain", 0.1))
        self.m_url_keywords = float(multipliers.get("url_keywords", 0.1))
        self.m_redirect = float(multipliers.get("redirect", 0.3))
        self.m_html = float(multipliers.get("html", 0.1))
        # 0.0 = redirect_domain_mismatch is fully suppressed for official
        # domains. Raise to a small value (e.g. 0.2) if you want a residual.
        self.m_redir_mismatch = float(multipliers.get("redirect_mismatch", 0.0))

        # ----- keyword and list files -----
        kw_files = cfg.get("keyword_files", {}) or {}
        list_files = cfg.get("list_files", {}) or {}
        # Legacy inline lists are still supported for backward compatibility.
        lists_section = cfg.get("lists", {}) or {}

        def _get_list_items(name: str, default_file: str) -> List[str]:
            if name in lists_section:
                raw_values = lists_section.get(name, []) or []
                return [str(v).strip().lower() for v in raw_values if str(v).strip()]
            file_path = list_files.get(name, default_file)
            return [v.strip().lower() for v in load_keywords_list(file_path) if v.strip()]

        self.suspicious_tlds: List[str] = _get_list_items(
            "suspicious_tlds",
            _DEFAULT_SUSPICIOUS_TLDS_FILE,
        )
        self.trusted_domains: List[str] = [
            d.lstrip(".")
            for d in _get_list_items("trusted_domains", _DEFAULT_TRUSTED_DOMAINS_FILE)
        ]
        self.identity_providers: List[str] = [
            d.lstrip(".")
            for d in _get_list_items("identity_providers", _DEFAULT_IDENTITY_PROVIDERS_FILE)
        ]
        self.hosting_platforms: List[str] = [
            d.lstrip(".")
            for d in _get_list_items("hosting_platforms", _DEFAULT_HOSTING_PLATFORMS_FILE)
        ]

        brand_fp = kw_files.get("brand", "data/keywords/heuristic/brand_keywords.csv")
        brand_domains_fp = kw_files.get("brand_domains", "data/keywords/heuristic/brand_domains.csv")
        path_fp = kw_files.get("path", "data/keywords/heuristic/path_keywords.csv")
        url_fp = kw_files.get("url", "data/keywords/heuristic/url_keywords.csv")

        self.brand_keywords = load_brand_keywords(brand_fp)
        self.brand_domains = load_brand_domains(brand_domains_fp)
        self.path_keywords = set(load_keywords_list(path_fp))
        self.url_keywords = set(load_keywords_list(url_fp))

        # Flattened entries across all brands for the decoupled lookup
        # (improvement #1). Each item: (domain, match_mode).
        self._all_official_entries: List[Tuple[str, str]] = []
        for entries in self.brand_domains.values():
            for entry in entries:
                self._all_official_entries.append(
                    (entry.domain.lower(), entry.match_mode)
                )

    # ------------------------------------------------------------------ scan

    async def scan(self, url: str, session: aiohttp.ClientSession, link_id: str | None = None) -> Dict[str, Any]:
        signals: Dict[str, float] = {}
        reasons: List[str] = []

        try:
            parsed = urllib.parse.urlparse(url)
            raw_hostname = (parsed.hostname or "").strip().strip(".").lower()
            hostname = self._normalize_hostname(raw_hostname)

            # ---- improvement #2: trusted-domain short-circuit ----
            if hostname and self._is_trusted_domain(hostname):
                logger.info(f"Trusted domain {hostname} – skipping heuristic checks")
                return {
                    "raw_score": 0.0,
                    "signals": {},
                    "reasons": [f"trusted domain ({hostname})"],
                }

            brand_ctx = self._brand_context(hostname)

            # ---- improvement #1: decoupled official-domain recognition ----
            is_official_domain = bool(
                brand_ctx["official"]
                or self._is_recognized_official_domain(hostname)
            )
            matched_brand_keywords: List[str] = list(brand_ctx.get("brands", []))

            # ---- 0. URL userinfo + IDN punycode (not multiplied) ----
            if parsed.username or parsed.password:
                self._add_signal(signals, "url_userinfo_present",
                                 self.sc_userinfo_present, reasons,
                                 "user:pass embedded in URL")

            if "xn--" in raw_hostname or "xn--" in hostname:
                self._add_signal(signals, "punycode_hostname",
                                 self.sc_punycode, reasons,
                                 "punycode (IDN) hostname")

            # ---- 1. Raw IP host ----
            if self._is_ip_address(hostname):
                self._add_signal(signals, "ip_address",
                                 self.sc_ip_address, reasons,
                                 "raw IP in URL")

            # ---- 2. Suspicious TLD ----
            if any(hostname.endswith(tld) for tld in self.suspicious_tlds):
                if not is_official_domain:
                    self._add_signal(signals, "suspicious_tld",
                                     self.sc_suspicious_tld, reasons,
                                     "suspicious TLD")

            # ---- 3. Long URL ----
            if len(url) > self.long_url_chars:
                self._add_signal(signals, "long_url",
                                 self.sc_long_url, reasons,
                                 "very long URL")

            # ---- 4. Brand impersonation (keyword based) ----
            brand_score = float(brand_ctx["impersonation_score"])
            if is_official_domain:
                # Registry-recognised – any keyword overlap is not impersonation.
                brand_score = 0.0
            if brand_score > 0:
                self._add_signal(signals, "brand_impersonation",
                                 brand_score, reasons,
                                 f"brand impersonation ({', '.join(matched_brand_keywords)})")

            # ---- 5. Path keywords ----
            path_score = self._check_path_heuristics(parsed.path)
            if is_official_domain:
                path_score *= self.m_path
            if path_score > 0:
                self._add_signal(signals, "suspicious_path",
                                 path_score, reasons,
                                 "suspicious path keywords")

            # ---- 5b. Subdomain (improvement #3) ----
            sub_score, sub_reason = self._check_subdomain_heuristics(hostname)
            if is_official_domain:
                sub_score *= self.m_subdomain
            if sub_score > 0:
                self._add_signal(signals, "suspicious_subdomain",
                                 sub_score, reasons, sub_reason)

            # ---- 6. AWS Lambda phishing pattern ----
            if re.search(r"\.lambda-url\..*\.on\.aws$", hostname, re.IGNORECASE):
                self._add_signal(signals, "aws_lambda_phishing",
                                 self.sc_aws_lambda, reasons,
                                 "AWS Lambda URL")

            # ---- 7. URL keywords ----
            url_kw_score = self._check_url_keywords(url)
            if is_official_domain:
                url_kw_score *= self.m_url_keywords
            if url_kw_score > 0:
                self._add_signal(signals, "suspicious_url_keywords",
                                 url_kw_score, reasons,
                                 "suspicious URL keywords")

            # ---- 8. WHOIS age (skip official + IP + hosting platforms, #8) ----
            if (not is_official_domain
                    and not self._is_ip_address(hostname)
                    and not self._is_hosting_platform(hostname)):
                whois_score = await self._check_whois_age(hostname)
                if whois_score > 0:
                    self._add_signal(signals, "whois_age_suspicious",
                                     whois_score, reasons,
                                     "recently registered or unknown age")

            # ---- 9. Redirects (#5 bug fixed) ----
            redirect_score, redirect_extras = await self._redirect_score(
                url, parsed, session, matched_brand_keywords
            )
            if is_official_domain:
                redirect_score *= self.m_redirect
            if redirect_score > 0:
                self._add_signal(signals, "redirect_suspicious",
                                 redirect_score, reasons,
                                 "many redirects")

            for name, value, why in redirect_extras:
                if is_official_domain and name == "redirect_domain_mismatch":
                    value *= self.m_redir_mismatch
                if value > 0:
                    self._add_signal(signals, name, value, reasons, why)

            # ---- 10. HTML content ----
            html_score, html_reason = await self._analyze_html_content(
                url, session,
                official_brand_domain=is_official_domain,
                matched_brands=matched_brand_keywords,
            )
            if is_official_domain:
                html_score *= self.m_html
            if html_score > 0:
                self._add_signal(signals, "malicious_html_content",
                                 html_score, reasons, html_reason)

        except Exception as e:
            logger.warning(f"Error analyzing URL {url}: {e}")
            self._add_signal(signals, "parsing_failed",
                             self.sc_parsing_failed, reasons,
                             f"parser exception: {e}")

        total_score = min(sum(signals.values()), 1.0)
        return {
            "raw_score": total_score,
            "signals": signals,
            "reasons": reasons,
        }

    # -------------------------------------------------------- signal helper

    def _add_signal(self, signals: Dict[str, float], name: str, value: float,
                    reasons: List[str], reason: str = ""):
        if value <= 0:
            return
        # Keep the strongest occurrence of a given signal
        if name not in signals or value > signals[name]:
            signals[name] = value
        if reason:
            entry = f"{reason} (+{value:.2f})"
            if entry not in reasons:
                reasons.append(entry)
        logger.info(f"Signal detected: {name} (+{value})")

    # ------------------------------------------------------- domain helpers

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

    def _is_trusted_domain(self, hostname: str) -> bool:
        """Improvement #2 – global hard allow-list."""
        if not self.trusted_domains:
            return False
        hostname = hostname.lower().strip(".")
        registrable = self._get_registrable_domain(hostname)
        return any(
            _match_domain(hostname, registrable, entry)
            for entry in self.trusted_domains
        )

    def _is_hosting_platform(self, hostname: str) -> bool:
        """Improvement #8 – WHOIS would be misleading on these etld+1s."""
        if not self.hosting_platforms:
            return False
        hostname = hostname.lower().strip(".")
        registrable = self._get_registrable_domain(hostname)
        return any(
            _match_domain(hostname, registrable, entry)
            for entry in self.hosting_platforms
        )

    def _is_identity_provider(self, hostname: str) -> bool:
        """Improvement #4 – tolerated targets for cross-domain form actions."""
        if not self.identity_providers or not hostname:
            return False
        hostname = hostname.lower().strip(".")
        registrable = self._get_registrable_domain(hostname)
        return any(
            _match_domain(hostname, registrable, entry)
            for entry in self.identity_providers
        )

    def _is_recognized_official_domain(self, hostname: str) -> bool:
        """Improvement #1 – check hostname against ALL configured brand
        domains regardless of brand. Also handles the new subdomain_of
        match mode (improvement #6)."""
        if not self._all_official_entries:
            return False
        hostname = self._normalize_hostname(hostname)
        registrable = self._get_registrable_domain(hostname)
        for domain, mode in self._all_official_entries:
            if mode == "etld1" and registrable == domain:
                return True
            if mode == "exact" and hostname == domain:
                return True
            if mode == "subdomain_of" and (
                hostname == domain or hostname.endswith("." + domain)
            ):
                return True
        return False

    def _is_official_brand_domain(self, brand: str, hostname: str) -> bool:
        """Per-brand official-domain check (used by impersonation logic).
        Extended with subdomain_of (#6)."""
        hostname = self._normalize_hostname(hostname)
        registrable = self._get_registrable_domain(hostname)
        for entry in self.brand_domains.get(brand, []):
            domain = entry.domain.lower()
            mode = entry.match_mode
            if mode == "etld1" and registrable == domain:
                return True
            if mode == "exact" and hostname == domain:
                return True
            if mode == "subdomain_of" and (
                hostname == domain or hostname.endswith("." + domain)
            ):
                return True
        return False

    def _brand_context(self, hostname: str) -> Dict[str, Any]:
        hostname = self._normalize_hostname(hostname)
        matches: List[_BrandMatch] = []
        for keyword, (brand_name, score) in self.brand_keywords.items():
            kw = keyword.lower().strip()
            if kw and kw in hostname:
                matches.append(_BrandMatch(kw, brand_name, float(score)))

        if not matches:
            return {
                "matched": False,
                "official": False,
                "impersonation_score": 0.0,
                "brands": [],
            }

        is_official_via_keyword = any(
            m.brand_name and self._is_official_brand_domain(m.brand_name, hostname)
            for m in matches
        )

        if is_official_via_keyword:
            impersonation_score = 0.0
        else:
            impersonation_score = max(
                (m.score for m in matches if m.brand_name),
                default=0.0,
            )

        return {
            "matched": True,
            "official": is_official_via_keyword,
            "impersonation_score": impersonation_score,
            "brands": [m.keyword for m in matches],
        }

    # ------------------------------------------------------ feature checks

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

    def _check_subdomain_heuristics(self, hostname: str) -> Tuple[float, str]:
        """Improvement #3 – pattern + entropy + length, returning a reason."""
        ext = _TLD_EXTRACT(hostname)
        subdomain = ext.subdomain
        if not subdomain:
            return 0.0, ""

        labels = subdomain.split(".")

        # Strongest signal: a label that looks machine-generated
        for label in labels:
            if _looks_random(label):
                return self.sub_random, f"random-looking subdomain label '{label}'"

        # Unexpected characters after IDNA normalisation
        if re.search(r"[^a-z0-9.\-]", subdomain):
            return self.sub_special_chars, "non-alphanumeric chars in subdomain"

        # Weaker signal: very long or deeply nested but otherwise meaningful
        if (len(subdomain) > self.subdomain_long_chars
                or len(labels) >= self.subdomain_deep_levels):
            return self.sub_long, "unusually long/deep subdomain"

        return 0.0, ""

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

            if hasattr(creation_date, "replace"):
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - creation_date).days
            if age_days < 3:
                return self.whois_age_lt_3d
            elif age_days < 7:
                return self.whois_age_lt_7d
            elif age_days < 30:
                return self.whois_age_lt_30d
        except Exception as e:
            logger.debug(f"WHOIS fail for {hostname}: {e}")
            return self.whois_fail_default

        return 0.0

    async def _redirect_score(
        self,
        url: str,
        parsed: urllib.parse.ParseResult,
        session: aiohttp.ClientSession,
        matched_brands: List[str],
    ) -> Tuple[float, List[Tuple[str, float, str]]]:
        """Returns (numeric_redirect_score, extras).

        `extras` is a list of (signal_name, value, reason) so the caller can
        apply the official-domain multiplier in one place. This is the
        fix for bug #5: previously these signals were written directly to
        the signals dict from here and skipped the multiplier.
        """
        if parsed.scheme not in ("http", "https"):
            return 0.0, []

        original_hostname = self._normalize_hostname(parsed.hostname or "")
        timeout = aiohttp.ClientTimeout(total=5)
        score = 0.0
        extras: List[Tuple[str, float, str]] = []

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
            return 0.0, []

        if redirect_count > self.redirect_high_threshold:
            score += self.redir_many
        elif redirect_count > self.redirect_warning_threshold:
            score += self.redir_warning

        if len(redirect_urls) > 1:
            final_hostname = self._normalize_hostname(
                urllib.parse.urlparse(redirect_urls[-1]).hostname or ""
            )
            if final_hostname and final_hostname != original_hostname:
                final_is_brand_family = self._hostname_belongs_to_any_matched_brand(
                    final_hostname, matched_brands
                )
                final_is_officially_recognised = self._is_recognized_official_domain(
                    final_hostname
                )
                final_is_idp = self._is_identity_provider(final_hostname)
                same_registrable = (
                    self._get_registrable_domain(final_hostname)
                    == self._get_registrable_domain(original_hostname)
                )

                # Don't flag a mismatch when:
                # - same registrable domain (subdomain transitions)
                # - final destination is part of the same brand family
                # - final destination is itself an officially recognised domain
                # - final destination is a known identity provider
                if not (final_is_brand_family
                        or final_is_officially_recognised
                        or final_is_idp
                        or same_registrable):
                    extras.append((
                        "redirect_domain_mismatch",
                        self.redir_domain_mismatch,
                        f"redirect to unrelated domain '{final_hostname}'",
                    ))

            # Redirect through a raw IP at any hop is a hard signal.
            for redirect_url in redirect_urls[1:]:
                hop_host = self._normalize_hostname(
                    urllib.parse.urlparse(redirect_url).hostname or ""
                )
                if (hop_host
                        and hop_host != original_hostname
                        and self._is_ip_address(hop_host)):
                    score += self.redir_to_ip
                    break

        return score, extras

    async def _analyze_html_content(
        self,
        url: str,
        session: aiohttp.ClientSession,
        official_brand_domain: bool = False,
        matched_brands: Optional[List[str]] = None,
    ) -> Tuple[float, str]:
        score = 0.0
        reason = ""
        timeout = aiohttp.ClientTimeout(total=5)
        try:
            async with session.get(url, timeout=timeout) as resp:
                if (resp.status != 200
                        or "text/html" not in resp.headers.get("Content-Type", "")):
                    return 0.0, ""

                content = await resp.content.read(200 * 1024)
                html = content.decode("utf-8", errors="ignore").lower()

                has_pwd = 'type="password"' in html
                has_email_user = (
                    'name="email"' in html
                    or 'type="email"' in html
                    or 'name="username"' in html
                )

                forms = re.findall(r"<form[^>]*>", html)

                # ---- Form-action analysis with IDP tolerance (#4) ----
                # "worst-of" semantics: same < idp < cross
                form_action_kind = "same"
                if forms:
                    if official_brand_domain:
                        form_multiplier = self.html_official_domain_multiplier
                    else:
                        parsed_url = urllib.parse.urlparse(url)
                        current_hostname = (parsed_url.hostname or "").lower()
                        current_domain = self._get_registrable_domain(current_hostname)

                        for form in forms:
                            action_match = re.search(r'action=["\']([^"\']+)["\']', form)
                            if not action_match:
                                continue
                            action = action_match.group(1).strip()
                            if not action or action.startswith(("/", "#", "javascript:")):
                                continue
                            try:
                                action_url = urllib.parse.urljoin(url, action)
                                action_hostname = (
                                    urllib.parse.urlparse(action_url).hostname or ""
                                ).lower()
                                action_domain = self._get_registrable_domain(action_hostname)
                                if not action_domain or action_domain == current_domain:
                                    continue
                                # Cross-domain action below this point
                                if self._is_identity_provider(action_hostname):
                                    if form_action_kind == "same":
                                        form_action_kind = "idp"
                                else:
                                    form_action_kind = "cross"
                                    break
                            except Exception:
                                pass

                        if form_action_kind == "cross":
                            form_multiplier = self.html_cross_domain_multiplier
                        elif form_action_kind == "idp":
                            form_multiplier = self.html_idp_multiplier
                        else:
                            form_multiplier = self.html_same_domain_multiplier
                else:
                    form_multiplier = self.html_same_domain_multiplier

                if has_pwd:
                    candidate = self.html_form_and_password * form_multiplier
                    if candidate > score:
                        score = candidate
                        reason = f"password form ({form_action_kind} action)"
                elif has_email_user:
                    candidate = self.html_form_and_email * form_multiplier
                    if candidate > score:
                        score = candidate
                        reason = f"login form ({form_action_kind} action)"

                if "fetch(" in html or "xmlhttprequest" in html:
                    xhr_multiplier = (
                        self.html_official_domain_multiplier
                        if official_brand_domain else 1.0
                    )
                    xhr_score = self.html_xhr_or_fetch * xhr_multiplier
                    if xhr_score > score:
                        score = xhr_score
                        reason = "dynamic XHR/fetch content"

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        return score, reason

    def _hostname_belongs_to_any_matched_brand(self, hostname: str, brands: List[str]) -> bool:
        for brand in brands:
            if self._is_official_brand_domain(brand, hostname):
                return True
        return False
