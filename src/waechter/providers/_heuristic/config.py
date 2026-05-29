from __future__ import annotations

from typing import Any

from waechter.config_loader import (
    as_bool,
    load_brand_domains,
    load_brand_keywords,
    load_keywords_list,
    provider_cfg,
)
from waechter.providers._heuristic.models import (
    HeuristicConfig,
    HeuristicLists,
    HeuristicScores,
    HeuristicThresholds,
)


DEFAULT_SUSPICIOUS_TLDS_FILE = "data/keywords/heuristic/suspicious_tlds.csv"
DEFAULT_TRUSTED_DOMAINS_FILE = "data/keywords/heuristic/trusted_domains.csv"
DEFAULT_IDENTITY_PROVIDERS_FILE = "data/keywords/heuristic/identity_providers.csv"
DEFAULT_HOSTING_PLATFORMS_FILE = "data/keywords/heuristic/hosting_platforms.csv"


def _load_list_items(
    name: str,
    default_file: str,
    list_files: dict[str, Any],
    legacy_lists: dict[str, Any],
) -> list[str]:
    if name in legacy_lists:
        raw_values = legacy_lists.get(name, []) or []
        return [str(value).strip().lower() for value in raw_values if str(value).strip()]

    file_path = list_files.get(name, default_file)
    return [value.strip().lower() for value in load_keywords_list(file_path) if value.strip()]


def load_heuristic_config() -> HeuristicConfig:
    cfg = provider_cfg("heuristic")

    thresholds = cfg.get("thresholds", {}) or {}
    redirect_thresholds = thresholds.get("redirect", {}) or {}
    subdomain_thresholds = thresholds.get("subdomain", {}) or {}

    scores = cfg.get("scores", {}) or {}
    whois_scores = scores.get("whois", {}) or {}
    redirect_scores = scores.get("redirects", {}) or {}
    html_scores = scores.get("html", {}) or {}
    subdomain_scores = scores.get("subdomain", {}) or {}
    official_multipliers = cfg.get("official_multipliers", {}) or {}

    keyword_files = cfg.get("keyword_files", {}) or {}
    list_files = cfg.get("list_files", {}) or {}
    legacy_lists = cfg.get("lists", {}) or {}

    suspicious_tlds = tuple(
        _load_list_items(
            "suspicious_tlds",
            DEFAULT_SUSPICIOUS_TLDS_FILE,
            list_files,
            legacy_lists,
        )
    )
    trusted_domains = tuple(
        entry.lstrip(".")
        for entry in _load_list_items(
            "trusted_domains",
            DEFAULT_TRUSTED_DOMAINS_FILE,
            list_files,
            legacy_lists,
        )
    )
    identity_providers = tuple(
        entry.lstrip(".")
        for entry in _load_list_items(
            "identity_providers",
            DEFAULT_IDENTITY_PROVIDERS_FILE,
            list_files,
            legacy_lists,
        )
    )
    hosting_platforms = tuple(
        entry.lstrip(".")
        for entry in _load_list_items(
            "hosting_platforms",
            DEFAULT_HOSTING_PLATFORMS_FILE,
            list_files,
            legacy_lists,
        )
    )

    brand_keywords = load_brand_keywords(
        keyword_files.get("brand", "data/keywords/heuristic/brand_keywords.csv")
    )
    brand_domains = load_brand_domains(
        keyword_files.get("brand_domains", "data/keywords/heuristic/brand_domains.csv")
    )
    path_keywords = frozenset(
        load_keywords_list(
            keyword_files.get("path", "data/keywords/heuristic/path_keywords.csv")
        )
    )
    url_keywords = frozenset(
        load_keywords_list(
            keyword_files.get("url", "data/keywords/heuristic/url_keywords.csv")
        )
    )
    official_entries = tuple(
        (entry.domain.lower(), entry.match_mode)
        for entries in brand_domains.values()
        for entry in entries
    )

    return HeuristicConfig(
        weight=float(cfg.get("weight", 0.6)),
        enabled=as_bool(cfg.get("enabled", True)),
        thresholds=HeuristicThresholds(
            redirect_warning=int(redirect_thresholds.get("warning", 3)),
            redirect_high=int(redirect_thresholds.get("high", 5)),
            redirect_max=int(redirect_thresholds.get("max", 10)),
            long_url_chars=int(thresholds.get("long_url_chars", 500)),
            subdomain_long_chars=int(subdomain_thresholds.get("long_chars", 25)),
            subdomain_deep_levels=int(subdomain_thresholds.get("deep_levels", 4)),
        ),
        scores=HeuristicScores(
            ip_address=float(scores.get("ip_address", 0.6)),
            suspicious_tld=float(scores.get("suspicious_tld", 0.5)),
            long_url=float(scores.get("long_url", 0.4)),
            aws_lambda=float(scores.get("aws_lambda_phishing", 0.8)),
            url_keywords=float(scores.get("url_keywords", 0.4)),
            path_keywords=float(scores.get("path_keywords", 0.3)),
            parsing_failed=float(scores.get("parsing_failed", 0.8)),
            userinfo_present=float(scores.get("userinfo_present", 0.8)),
            punycode=float(scores.get("punycode_hostname", 0.5)),
            whois_missing_creation=float(whois_scores.get("missing_creation", 0.5)),
            whois_age_lt_3d=float(whois_scores.get("age_lt_3d", 1.5)),
            whois_age_lt_7d=float(whois_scores.get("age_lt_7d", 1.0)),
            whois_age_lt_30d=float(whois_scores.get("age_lt_30d", 0.7)),
            whois_fail_default=float(whois_scores.get("fail_default", 0.5)),
            redirect_too_many=float(redirect_scores.get("too_many", 0.8)),
            redirect_many=float(redirect_scores.get("many", 0.5)),
            redirect_warning=float(redirect_scores.get("warning", 0.2)),
            redirect_domain_mismatch=float(redirect_scores.get("domain_mismatch", 0.5)),
            redirect_to_ip=float(redirect_scores.get("to_ip", 0.7)),
            html_form_and_password=float(html_scores.get("form_and_password", 0.8)),
            html_form_and_email=float(html_scores.get("form_and_email", 0.5)),
            html_xhr_or_fetch=float(html_scores.get("xhr_or_fetch", 0.3)),
            html_same_domain_multiplier=float(html_scores.get("same_domain_multiplier", 0.5)),
            html_cross_domain_multiplier=float(html_scores.get("cross_domain_multiplier", 1.0)),
            html_idp_multiplier=float(html_scores.get("idp_multiplier", 0.15)),
            html_official_domain_multiplier=float(
                html_scores.get("official_domain_multiplier", 0.1)
            ),
            subdomain_long=float(subdomain_scores.get("long", 0.15)),
            subdomain_random=float(subdomain_scores.get("random", 0.4)),
            subdomain_special_chars=float(subdomain_scores.get("special_chars", 0.4)),
            official_path_multiplier=float(official_multipliers.get("path", 0.1)),
            official_subdomain_multiplier=float(official_multipliers.get("subdomain", 0.1)),
            official_url_keywords_multiplier=float(
                official_multipliers.get("url_keywords", 0.1)
            ),
            official_redirect_multiplier=float(official_multipliers.get("redirect", 0.3)),
        ),
        lists=HeuristicLists(
            suspicious_tlds=suspicious_tlds,
            trusted_domains=trusted_domains,
            identity_providers=identity_providers,
            hosting_platforms=hosting_platforms,
            brand_keywords=brand_keywords,
            brand_domains=brand_domains,
            path_keywords=path_keywords,
            url_keywords=url_keywords,
            official_entries=official_entries,
        ),
    )
