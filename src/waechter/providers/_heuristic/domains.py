from __future__ import annotations

from collections import Counter
import ipaddress
import math
import re

import idna
import tldextract

from waechter.providers._heuristic.models import BrandContext, BrandMatch, HeuristicConfig


_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_random(label: str) -> bool:
    if len(label) < 8:
        return False

    if re.fullmatch(r"[0-9a-f]{8,}", label):
        return True

    letters = [char for char in label if char.isalpha()]
    if len(letters) >= 6:
        vowels = sum(1 for char in letters if char in "aeiou")
        if vowels / len(letters) < 0.15:
            return True

    if (
        len(label) >= 10
        and any(char.isdigit() for char in label)
        and any(char.isalpha() for char in label)
        and _shannon_entropy(label) >= 3.5
    ):
        return True

    return False


def _match_domain(hostname: str, registrable: str, entry: str) -> bool:
    entry = entry.lower().strip(".")
    if not entry:
        return False
    if hostname == entry or registrable == entry:
        return True
    return hostname.endswith("." + entry)


class DomainInspector:
    def __init__(self, config: HeuristicConfig):
        self.config = config

    def is_ip_address(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            return True
        except ValueError:
            return False

    def normalize_hostname(self, hostname: str) -> str:
        hostname = hostname.strip().strip(".").lower()
        try:
            return idna.decode(hostname.encode("ascii")).lower()
        except Exception:
            return hostname

    def get_registrable_domain(self, hostname: str) -> str:
        hostname = self.normalize_hostname(hostname)
        ext = _TLD_EXTRACT(hostname)
        if not ext.domain or not ext.suffix:
            return hostname
        return f"{ext.domain}.{ext.suffix}".lower()

    def is_trusted_domain(self, hostname: str) -> bool:
        return self._matches_list_entries(hostname, self.config.lists.trusted_domains)

    def is_hosting_platform(self, hostname: str) -> bool:
        return self._matches_list_entries(hostname, self.config.lists.hosting_platforms)

    def is_identity_provider(self, hostname: str) -> bool:
        return self._matches_list_entries(hostname, self.config.lists.identity_providers)

    def is_recognized_official_domain(self, hostname: str) -> bool:
        hostname = self.normalize_hostname(hostname)
        registrable = self.get_registrable_domain(hostname)
        for domain, mode in self.config.lists.official_entries:
            if mode == "etld1" and registrable == domain:
                return True
            if mode == "exact" and hostname == domain:
                return True
            if mode == "subdomain_of" and (
                hostname == domain or hostname.endswith("." + domain)
            ):
                return True
        return False

    def is_official_brand_domain(self, brand: str, hostname: str) -> bool:
        hostname = self.normalize_hostname(hostname)
        registrable = self.get_registrable_domain(hostname)

        for entry in self.config.lists.brand_domains.get(brand, []):
            domain = entry.domain.lower()
            if entry.match_mode == "etld1" and registrable == domain:
                return True
            if entry.match_mode == "exact" and hostname == domain:
                return True
            if entry.match_mode == "subdomain_of" and (
                hostname == domain or hostname.endswith("." + domain)
            ):
                return True

        return False

    def brand_context(self, hostname: str) -> BrandContext:
        hostname = self.normalize_hostname(hostname)
        matches: list[BrandMatch] = []

        for keyword, (brand_name, score) in self.config.lists.brand_keywords.items():
            normalized_keyword = keyword.lower().strip()
            if normalized_keyword and normalized_keyword in hostname:
                matches.append(
                    BrandMatch(
                        keyword=normalized_keyword,
                        brand_name=brand_name,
                        score=float(score),
                    )
                )

        if not matches:
            return BrandContext(
                matched=False,
                official=False,
                impersonation_score=0.0,
                brands=(),
            )

        is_official_via_keyword = any(
            match.brand_name and self.is_official_brand_domain(match.brand_name, hostname)
            for match in matches
        )
        impersonation_score = 0.0
        if not is_official_via_keyword:
            impersonation_score = max(
                (match.score for match in matches if match.brand_name),
                default=0.0,
            )

        return BrandContext(
            matched=True,
            official=is_official_via_keyword,
            impersonation_score=impersonation_score,
            brands=tuple(match.keyword for match in matches),
        )

    def hostname_belongs_to_any_matched_brand(
        self,
        hostname: str,
        brands: list[str] | tuple[str, ...],
    ) -> bool:
        return any(self.is_official_brand_domain(brand, hostname) for brand in brands)

    def check_subdomain_heuristics(self, hostname: str) -> tuple[float, str]:
        ext = _TLD_EXTRACT(hostname)
        subdomain = ext.subdomain
        if not subdomain:
            return 0.0, ""

        labels = subdomain.split(".")
        for label in labels:
            if _looks_random(label):
                return (
                    self.config.scores.subdomain_random,
                    f"random-looking subdomain label '{label}'",
                )

        if re.search(r"[^a-z0-9.\-]", subdomain):
            return (
                self.config.scores.subdomain_special_chars,
                "non-alphanumeric chars in subdomain",
            )

        if (
            len(subdomain) > self.config.thresholds.subdomain_long_chars
            or len(labels) >= self.config.thresholds.subdomain_deep_levels
        ):
            return (
                self.config.scores.subdomain_long,
                "unusually long/deep subdomain",
            )

        return 0.0, ""

    def _matches_list_entries(
        self,
        hostname: str,
        entries: tuple[str, ...],
    ) -> bool:
        if not entries or not hostname:
            return False

        hostname = hostname.lower().strip(".")
        registrable = self.get_registrable_domain(hostname)
        return any(_match_domain(hostname, registrable, entry) for entry in entries)
