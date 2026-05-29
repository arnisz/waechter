from __future__ import annotations

from typing import Any
import logging
import re
import urllib.parse

import aiohttp

from waechter.providers.base import ProviderResult, ScanProvider
from waechter.providers._heuristic.analyzer import HeuristicAnalyzer
from waechter.providers._heuristic.config import load_heuristic_config
from waechter.providers._heuristic.domains import DomainInspector


logger = logging.getLogger(__name__)


class HeuristicProvider(ScanProvider):
    """URL-only phishing/abuse scoring provider with optional web-content checks."""

    name = "heuristic"

    def __init__(self):
        self.config = load_heuristic_config()
        self.weight = self.config.weight
        self.enabled = self.config.enabled
        self.domains = DomainInspector(self.config)
        self.analyzer = HeuristicAnalyzer(self.config, self.domains)

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        link_id: str | None = None,
    ) -> ProviderResult:
        del link_id

        signals: dict[str, float] = {}
        reasons: list[str] = []
        check_errors: list[str] = []

        try:
            parsed = urllib.parse.urlparse(url)
            raw_hostname = (parsed.hostname or "").strip().strip(".").lower()
            hostname = self.domains.normalize_hostname(raw_hostname)

            if hostname and self.domains.is_trusted_domain(hostname):
                logger.info("Trusted domain %s - skipping heuristic checks", hostname)
                return self.build_result(
                    0.0,
                    signals={},
                    reasons=[f"trusted domain ({hostname})"],
                    errors=[],
                )

            brand_ctx = self.domains.brand_context(hostname)
            is_official_domain = bool(
                brand_ctx.official or self.domains.is_recognized_official_domain(hostname)
            )
            matched_brand_keywords = list(brand_ctx.brands)

            self._apply_url_structure_checks(
                url=url,
                parsed=parsed,
                raw_hostname=raw_hostname,
                hostname=hostname,
                is_official_domain=is_official_domain,
                matched_brand_keywords=matched_brand_keywords,
                signals=signals,
                reasons=reasons,
                brand_impersonation_score=brand_ctx.impersonation_score,
            )

            if (
                not is_official_domain
                and not self.domains.is_ip_address(hostname)
                and not self.domains.is_hosting_platform(hostname)
            ):
                whois_score = await self.analyzer.check_whois_age(hostname)
                if whois_score > 0:
                    self._add_signal(
                        signals,
                        "whois_age_suspicious",
                        whois_score,
                        reasons,
                        "recently registered or unknown age",
                    )

            redirect_outcome = await self.analyzer.redirect_score(
                url,
                parsed,
                session,
                matched_brand_keywords,
            )
            if redirect_outcome.error:
                check_errors.append(redirect_outcome.error)

            redirect_score = redirect_outcome.score
            if is_official_domain:
                redirect_score *= self.config.scores.official_redirect_multiplier
            if redirect_score > 0:
                self._add_signal(
                    signals,
                    "redirect_suspicious",
                    redirect_score,
                    reasons,
                    "many redirects",
                )

            for name, value, reason in redirect_outcome.extras:
                self._add_signal(signals, name, value, reasons, reason)

            html_analysis = await self.analyzer.analyze_html_content(url, session)
            if html_analysis.error:
                target_hostname = redirect_outcome.final_hostname or hostname or "unknown"
                check_errors.append(
                    f"{html_analysis.error} (landing_host={target_hostname})"
                )
            if html_analysis.score > 0:
                self._add_signal(
                    signals,
                    "malicious_html_content",
                    html_analysis.score,
                    reasons,
                    html_analysis.reason,
                )

        except Exception as exc:
            logger.warning("Error analyzing URL %s: %s", url, exc)
            check_errors.append(f"heuristic_scan_failed: {exc}")
            self._add_signal(
                signals,
                "parsing_failed",
                self.config.scores.parsing_failed,
                reasons,
                f"parser exception: {exc}",
            )

        total_score = min(sum(signals.values()), 1.0)
        return self.build_result(
            total_score,
            signals=signals,
            reasons=reasons,
            errors=check_errors,
        )

    def _apply_url_structure_checks(
        self,
        *,
        url: str,
        parsed: urllib.parse.ParseResult,
        raw_hostname: str,
        hostname: str,
        is_official_domain: bool,
        matched_brand_keywords: list[str],
        signals: dict[str, float],
        reasons: list[str],
        brand_impersonation_score: float,
    ) -> None:
        if parsed.username or parsed.password:
            self._add_signal(
                signals,
                "url_userinfo_present",
                self.config.scores.userinfo_present,
                reasons,
                "user:pass embedded in URL",
            )

        if "xn--" in raw_hostname or "xn--" in hostname:
            self._add_signal(
                signals,
                "punycode_hostname",
                self.config.scores.punycode,
                reasons,
                "punycode (IDN) hostname",
            )

        if self.domains.is_ip_address(hostname):
            self._add_signal(
                signals,
                "ip_address",
                self.config.scores.ip_address,
                reasons,
                "raw IP in URL",
            )

        if any(hostname.endswith(tld) for tld in self.config.lists.suspicious_tlds):
            if not is_official_domain:
                self._add_signal(
                    signals,
                    "suspicious_tld",
                    self.config.scores.suspicious_tld,
                    reasons,
                    "suspicious TLD",
                )

        if len(url) > self.config.thresholds.long_url_chars:
            self._add_signal(
                signals,
                "long_url",
                self.config.scores.long_url,
                reasons,
                "very long URL",
            )

        effective_brand_score = 0.0 if is_official_domain else brand_impersonation_score
        if effective_brand_score > 0:
            self._add_signal(
                signals,
                "brand_impersonation",
                effective_brand_score,
                reasons,
                f"brand impersonation ({', '.join(matched_brand_keywords)})",
            )

        path_score = self.analyzer.check_path_heuristics(parsed.path)
        if is_official_domain:
            path_score *= self.config.scores.official_path_multiplier
        if path_score > 0:
            self._add_signal(
                signals,
                "suspicious_path",
                path_score,
                reasons,
                "suspicious path keywords",
            )

        sub_score, sub_reason = self.domains.check_subdomain_heuristics(hostname)
        if is_official_domain:
            sub_score *= self.config.scores.official_subdomain_multiplier
        if sub_score > 0:
            self._add_signal(signals, "suspicious_subdomain", sub_score, reasons, sub_reason)

        if re.search(r"\.lambda-url\..*\.on\.aws$", hostname, re.IGNORECASE):
            self._add_signal(
                signals,
                "aws_lambda_phishing",
                self.config.scores.aws_lambda,
                reasons,
                "AWS Lambda URL",
            )

        url_keyword_score = self.analyzer.check_url_keywords(url)
        if is_official_domain:
            url_keyword_score *= self.config.scores.official_url_keywords_multiplier
        if url_keyword_score > 0:
            self._add_signal(
                signals,
                "suspicious_url_keywords",
                url_keyword_score,
                reasons,
                "suspicious URL keywords",
            )

    def _add_signal(
        self,
        signals: dict[str, float],
        name: str,
        value: float,
        reasons: list[str],
        reason: str = "",
    ) -> None:
        if value <= 0:
            return

        if name not in signals or value > signals[name]:
            signals[name] = value

        if reason:
            entry = f"{reason} (+{value:.2f})"
            if entry not in reasons:
                reasons.append(entry)

        logger.info("Signal detected: %s (+%s)", name, value)
