from __future__ import annotations

from dataclasses import dataclass

from waechter.config_loader import BrandDomain


BrandKeywordMap = dict[str, tuple[str, float]]
BrandDomainMap = dict[str, list[BrandDomain]]
SignalExtra = tuple[str, float, str]


@dataclass(frozen=True)
class HeuristicThresholds:
    redirect_warning: int
    redirect_high: int
    redirect_max: int
    long_url_chars: int
    subdomain_long_chars: int
    subdomain_deep_levels: int


@dataclass(frozen=True)
class HeuristicScores:
    ip_address: float
    suspicious_tld: float
    long_url: float
    aws_lambda: float
    url_keywords: float
    path_keywords: float
    parsing_failed: float
    userinfo_present: float
    punycode: float
    whois_missing_creation: float
    whois_age_lt_3d: float
    whois_age_lt_7d: float
    whois_age_lt_30d: float
    whois_fail_default: float
    redirect_too_many: float
    redirect_many: float
    redirect_warning: float
    redirect_domain_mismatch: float
    redirect_to_ip: float
    html_form_and_password: float
    html_form_and_email: float
    html_xhr_or_fetch: float
    html_same_domain_multiplier: float
    html_cross_domain_multiplier: float
    html_idp_multiplier: float
    html_official_domain_multiplier: float
    subdomain_long: float
    subdomain_random: float
    subdomain_special_chars: float
    official_path_multiplier: float
    official_subdomain_multiplier: float
    official_url_keywords_multiplier: float
    official_redirect_multiplier: float


@dataclass(frozen=True)
class HeuristicLists:
    suspicious_tlds: tuple[str, ...]
    trusted_domains: tuple[str, ...]
    identity_providers: tuple[str, ...]
    hosting_platforms: tuple[str, ...]
    brand_keywords: BrandKeywordMap
    brand_domains: BrandDomainMap
    path_keywords: frozenset[str]
    url_keywords: frozenset[str]
    official_entries: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class HeuristicConfig:
    weight: float
    enabled: bool
    thresholds: HeuristicThresholds
    scores: HeuristicScores
    lists: HeuristicLists


@dataclass(frozen=True)
class BrandMatch:
    keyword: str
    brand_name: str
    score: float


@dataclass(frozen=True)
class BrandContext:
    matched: bool
    official: bool
    impersonation_score: float
    brands: tuple[str, ...]


@dataclass(frozen=True)
class RedirectOutcome:
    score: float
    extras: tuple[SignalExtra, ...]
    final_hostname: str
    error: str | None = None


@dataclass(frozen=True)
class HtmlAnalysis:
    score: float
    reason: str
    error: str | None = None
