from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import re
import urllib.parse

import aiohttp
import whois

from waechter.providers._heuristic.domains import DomainInspector
from waechter.providers._heuristic.models import HeuristicConfig, HtmlAnalysis, RedirectOutcome


logger = logging.getLogger(__name__)


class HeuristicAnalyzer:
    def __init__(self, config: HeuristicConfig, domains: DomainInspector):
        self.config = config
        self.domains = domains

    def check_path_heuristics(self, path: str) -> float:
        if any(keyword in path.lower() for keyword in self.config.lists.path_keywords):
            return self.config.scores.path_keywords
        return 0.0

    def check_url_keywords(self, url: str) -> float:
        if any(keyword in url.lower() for keyword in self.config.lists.url_keywords):
            return self.config.scores.url_keywords
        return 0.0

    async def check_whois_age(self, hostname: str) -> float:
        def fetch_whois():
            try:
                domain = self.domains.get_registrable_domain(hostname)
                return whois.whois(domain)
            except Exception:
                return None

        try:
            whois_result = await asyncio.to_thread(fetch_whois)
            if not whois_result or not whois_result.creation_date:
                return self.config.scores.whois_missing_creation

            creation_date = whois_result.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if hasattr(creation_date, "replace"):
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (
                datetime.now(timezone.utc).replace(tzinfo=None) - creation_date
            ).days
            if age_days < 3:
                return self.config.scores.whois_age_lt_3d
            if age_days < 7:
                return self.config.scores.whois_age_lt_7d
            if age_days < 30:
                return self.config.scores.whois_age_lt_30d
        except Exception as exc:
            logger.debug("WHOIS fail for %s: %s", hostname, exc)
            return self.config.scores.whois_fail_default

        return 0.0

    async def redirect_score(
        self,
        url: str,
        parsed: urllib.parse.ParseResult,
        session: aiohttp.ClientSession,
        matched_brands: list[str],
    ) -> RedirectOutcome:
        original_hostname = self.domains.normalize_hostname(parsed.hostname or "")
        if parsed.scheme not in ("http", "https"):
            return RedirectOutcome(
                score=0.0,
                extras=(),
                final_hostname=original_hostname,
            )

        timeout = aiohttp.ClientTimeout(total=5)
        score = 0.0
        extras: list[tuple[str, float, str]] = []
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
                ) as response:
                    if response.status < 300 or response.status >= 400:
                        break

                    location = response.headers.get("Location")
                    if not location:
                        break

                    redirect_count += 1
                    current_url = urllib.parse.urljoin(current_url, location)
                    redirect_urls.append(current_url)

                    if redirect_count > self.config.thresholds.redirect_max:
                        score += self.config.scores.redirect_too_many
                        break
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return RedirectOutcome(
                score=0.0,
                extras=(),
                final_hostname=original_hostname,
                error=f"redirect_check_failed: {type(exc).__name__}: {exc}",
            )

        if redirect_count > self.config.thresholds.redirect_high:
            score += self.config.scores.redirect_many
        elif redirect_count > self.config.thresholds.redirect_warning:
            score += self.config.scores.redirect_warning

        final_hostname = self.domains.normalize_hostname(
            urllib.parse.urlparse(redirect_urls[-1]).hostname or ""
        ) or original_hostname

        if len(redirect_urls) > 1:
            score, extras = self._analyze_redirect_targets(
                score=score,
                original_hostname=original_hostname,
                final_hostname=final_hostname,
                redirect_urls=redirect_urls,
                matched_brands=matched_brands,
                extras=extras,
            )

        return RedirectOutcome(
            score=score,
            extras=tuple(extras),
            final_hostname=final_hostname,
        )

    async def analyze_html_content(
        self,
        url: str,
        session: aiohttp.ClientSession,
    ) -> HtmlAnalysis:
        timeout = aiohttp.ClientTimeout(total=5)

        try:
            async with session.get(url, timeout=timeout) as response:
                if (
                    response.status != 200
                    or "text/html" not in response.headers.get("Content-Type", "")
                ):
                    return HtmlAnalysis(score=0.0, reason="")

                final_host = self.domains.normalize_hostname(
                    (response.url.host or "").lower()
                )
                landing_is_official = (
                    self.domains.is_recognized_official_domain(final_host)
                    or self.domains.is_trusted_domain(final_host)
                )

                content = await response.content.read(200 * 1024)
                html = content.decode("utf-8", errors="ignore").lower()

                form_multiplier, form_action_kind = self._determine_form_multiplier(
                    html=html,
                    response_url=str(response.url),
                    final_host=final_host,
                    landing_is_official=landing_is_official,
                )

                score = 0.0
                reason = ""
                if 'type="password"' in html:
                    score = self.config.scores.html_form_and_password * form_multiplier
                    reason = f"password form ({form_action_kind} action)"
                elif (
                    'name="email"' in html
                    or 'type="email"' in html
                    or 'name="username"' in html
                ):
                    score = self.config.scores.html_form_and_email * form_multiplier
                    reason = f"login form ({form_action_kind} action)"

                if "fetch(" in html or "xmlhttprequest" in html:
                    xhr_multiplier = (
                        self.config.scores.html_official_domain_multiplier
                        if landing_is_official
                        else 1.0
                    )
                    xhr_score = self.config.scores.html_xhr_or_fetch * xhr_multiplier
                    if xhr_score > score:
                        score = xhr_score
                        reason = "dynamic XHR/fetch content"

                return HtmlAnalysis(score=score, reason=reason)
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return HtmlAnalysis(
                score=0.0,
                reason="",
                error=f"html_check_failed: {type(exc).__name__}: {exc}",
            )

    def _analyze_redirect_targets(
        self,
        *,
        score: float,
        original_hostname: str,
        final_hostname: str,
        redirect_urls: list[str],
        matched_brands: list[str],
        extras: list[tuple[str, float, str]],
    ) -> tuple[float, list[tuple[str, float, str]]]:
        if final_hostname and final_hostname != original_hostname:
            final_is_brand_family = self.domains.hostname_belongs_to_any_matched_brand(
                final_hostname,
                matched_brands,
            )
            final_is_officially_recognized = self.domains.is_recognized_official_domain(
                final_hostname
            )
            final_is_idp = self.domains.is_identity_provider(final_hostname)
            same_registrable = (
                self.domains.get_registrable_domain(final_hostname)
                == self.domains.get_registrable_domain(original_hostname)
            )

            if not (
                final_is_brand_family
                or final_is_officially_recognized
                or final_is_idp
                or same_registrable
            ):
                extras.append(
                    (
                        "redirect_domain_mismatch",
                        self.config.scores.redirect_domain_mismatch,
                        f"redirect to unrelated domain '{final_hostname}'",
                    )
                )

        for redirect_url in redirect_urls[1:]:
            hop_host = self.domains.normalize_hostname(
                urllib.parse.urlparse(redirect_url).hostname or ""
            )
            if (
                hop_host
                and hop_host != original_hostname
                and self.domains.is_ip_address(hop_host)
            ):
                score += self.config.scores.redirect_to_ip
                break

        return score, extras

    def _determine_form_multiplier(
        self,
        *,
        html: str,
        response_url: str,
        final_host: str,
        landing_is_official: bool,
    ) -> tuple[float, str]:
        forms = re.findall(r"<form[^>]*>", html)
        form_action_kind = "same"

        if not forms:
            return self.config.scores.html_same_domain_multiplier, form_action_kind

        if landing_is_official:
            return self.config.scores.html_official_domain_multiplier, form_action_kind

        current_domain = self.domains.get_registrable_domain(final_host)
        for form in forms:
            action_match = re.search(r'action=["\']([^"\']+)["\']', form)
            if not action_match:
                continue

            action = action_match.group(1).strip()
            if not action or action.startswith(("/", "#", "javascript:")):
                continue

            try:
                action_url = urllib.parse.urljoin(response_url, action)
                action_hostname = (
                    urllib.parse.urlparse(action_url).hostname or ""
                ).lower()
                action_domain = self.domains.get_registrable_domain(action_hostname)
                if not action_domain or action_domain == current_domain:
                    continue
                if self.domains.is_identity_provider(action_hostname):
                    if form_action_kind == "same":
                        form_action_kind = "idp"
                else:
                    form_action_kind = "cross"
                    break
            except Exception:
                continue

        if form_action_kind == "cross":
            return self.config.scores.html_cross_domain_multiplier, form_action_kind
        if form_action_kind == "idp":
            return self.config.scores.html_idp_multiplier, form_action_kind
        return self.config.scores.html_same_domain_multiplier, form_action_kind
