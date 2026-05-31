from dataclasses import replace as dc_replace
from datetime import datetime
import pytest
import aiohttp
from waechter.providers import HeuristicProvider, GoogleSafeBrowsingProvider, ClamAVProvider, ProviderResult
from aioresponses import aioresponses
from unittest.mock import patch

import waechter.providers._clamav.provider as clamav_module


async def _no_whois_score(hostname):
    return 0.0


def _update_provider_lists(provider, **kwargs):
    """Update HeuristicProvider config lists (frozen dataclass workaround)."""
    new_lists = dc_replace(provider.config.lists, **kwargs)
    new_config = dc_replace(provider.config, lists=new_lists)
    provider.config = new_config
    provider.domains.config = new_config
    provider.analyzer.config = new_config


@pytest.mark.asyncio
async def test_heuristic_provider():
    provider = HeuristicProvider()
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            # IP test
            m.get("http://192.168.0.1/path", status=200)
            res = await provider.scan("http://192.168.0.1/path", session)
            assert res.raw_score >= 0.6

        with aioresponses() as m:
            # Suspicious TLD
            m.get("http://example.tk", status=200)
            res2 = await provider.scan("http://example.tk", session)
            assert res2.raw_score >= 0.5


@pytest.mark.asyncio
async def test_heuristic_provider_scores_long_redirect_chain():
    provider = HeuristicProvider()
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head("http://example.com/start", status=301, headers={"Location": "http://example.com/r1"})
            m.head("http://example.com/r1", status=301, headers={"Location": "http://example.com/r2"})
            m.head("http://example.com/r2", status=301, headers={"Location": "http://example.com/r3"})
            m.head("http://example.com/r3", status=301, headers={"Location": "http://example.com/r4"})
            m.head("http://example.com/r4", status=200)

            res = await provider.scan("http://example.com/start", session)
            assert res.raw_score >= 0.2


@pytest.mark.asyncio
async def test_heuristic_provider_scores_redirect_to_raw_ip():
    provider = HeuristicProvider()
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head("http://example.com/start", status=301, headers={"Location": "http://203.0.113.10/final"})
            m.head("http://203.0.113.10/final", status=200)

            res = await provider.scan("http://example.com/start", session)
            assert res.raw_score >= 0.7


def test_heuristic_provider_extracts_registrable_domain():
    provider = HeuristicProvider()

    assert provider.domains.get_registrable_domain("www.amazon.de") == "amazon.de"
    assert provider.domains.get_registrable_domain("login.amazon.co.uk") == "amazon.co.uk"
    assert provider.domains.get_registrable_domain("amazon.de.evil.com") == "evil.com"


@pytest.mark.asyncio
async def test_heuristic_provider_treats_official_amazon_payment_url_as_low_risk(monkeypatch):
    provider = HeuristicProvider()
    url = "https://www.amazon.de/manage-monthly-payments?state=active"

    async def fail_if_called(hostname):
        raise AssertionError("WHOIS should be skipped for official brand domains")

    monkeypatch.setattr(provider.analyzer, "check_whois_age", fail_if_called)

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(
                url,
                status=200,
                headers={"Content-Type": "text/html"},
                body='<form><input type="password" name="password"></form>',
            )

            res = await provider.scan(url, session)

    assert res.raw_score < 0.3
    assert "brand_impersonation" not in res.signals
    assert res.signals.get("suspicious_url_keywords", 0.0) <= 0.05
    assert res.signals.get("malicious_html_content", 0.0) <= 0.1


@pytest.mark.asyncio
async def test_heuristic_provider_scores_amazon_impersonation_as_high_risk(monkeypatch):
    provider = HeuristicProvider()
    monkeypatch.setattr(provider.analyzer, "check_whois_age", _no_whois_score)
    url = "https://amazon.manage-monthly-payments.example.top/login"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, headers={"Content-Type": "text/plain"}, body="")

            res = await provider.scan(url, session)

    assert res.raw_score >= 0.95
    assert res.signals["brand_impersonation"] >= 0.5
    assert res.signals["suspicious_path"] >= 0.3
    assert res.signals["suspicious_url_keywords"] >= 0.4


@pytest.mark.asyncio
async def test_heuristic_provider_scores_userinfo_trick(monkeypatch):
    provider = HeuristicProvider()
    monkeypatch.setattr(provider.analyzer, "check_whois_age", _no_whois_score)
    url = "https://www.amazon.de@evil.com/login"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, headers={"Content-Type": "text/plain"}, body="")

            res = await provider.scan(url, session)

    assert res.signals["url_userinfo_present"] == 0.8


@pytest.mark.asyncio
async def test_heuristic_provider_scores_punycode_hostname(monkeypatch):
    provider = HeuristicProvider()
    monkeypatch.setattr(provider.analyzer, "check_whois_age", _no_whois_score)
    url = "https://xn--amazn-mra.de/login"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, headers={"Content-Type": "text/plain"}, body="")

            res = await provider.scan(url, session)

    assert res.signals["punycode_hostname"] == 0.5


@pytest.mark.asyncio
async def test_heuristic_provider_scores_whois_age_less_than_3_days(monkeypatch):
    provider = HeuristicProvider()
    url = "https://new-domain.com"

    async def mock_check_whois_age(hostname):
        return provider.config.scores.whois_age_lt_3d

    monkeypatch.setattr(provider.analyzer, "check_whois_age", mock_check_whois_age)

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, headers={"Content-Type": "text/plain"}, body="")

            res = await provider.scan(url, session)

    assert res.signals["whois_age_suspicious"] == 1.5
    assert res.raw_score == 1.0


@pytest.mark.asyncio
async def test_heuristic_provider_keeps_walbusch_product_url_below_threshold(monkeypatch):
    provider = HeuristicProvider()
    monkeypatch.setattr(provider.analyzer, "check_whois_age", _no_whois_score)

    url = (
        "https://www.walbuschi.de/midirock-leinenmix/p/44-5363?choice="
        "eyJzIjoiNDIiLCJjbiI6IldlacOfIiwiYW4iOiI0NC01MzYzIn0="
        "&mc=G21&wid=de_sh_go&campaign=de_sh_go/0/google/googleshopping/0/0//0"
        "&utm_source=google&utm_medium=cpc&utm_campaign=PLA_DE_Shopping-P-Max_Top_Seller"
        "&gad_source=1&gad_campaignid=21360507982&gbraid=0AAAAAD570CJuDkF4vkdJzYEAL_GFDQqsG"
        "&gclid=CjwKCAjw8uTQBhAdEiwAVvtJyiX5IEohVzwErmXQJZn_8uFLfkudHF_n9YiUvXnaxrlIRVO3uvue6hoCJlgQAvD_BwE"
    )

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(
                url,
                status=200,
                headers={"Content-Type": "text/html"},
                body="<html><body></body></html>",
            )

            res = await provider.scan(url, session)

    print(f"Testing URL: {url}")
    print(f"raw_score={res.raw_score}")
    print(f"signals={res.signals}")

    assert res.raw_score <= 0.65, (
        f"Unexpected raw score for walbusch URL: {res}"
    )


@pytest.mark.asyncio
async def test_gsb_provider():
    provider = GoogleSafeBrowsingProvider("dummy-key")
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=dummy-key",
                payload={"matches": [{"threatType": "MALWARE"}]}
            )
            res = await provider.scan("http://bad-url.com", session)
            assert res.raw_score == 1.0
            assert "matches" in res.raw_response

        with aioresponses() as m:
            m.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=dummy-key",
                payload={}
            )
            res2 = await provider.scan("http://good-url.com", session)
            assert res2.raw_score == 0.0


@pytest.mark.asyncio
async def test_clamav_provider_scores_found(monkeypatch):
    provider = ClamAVProvider()

    def fake_scan(settings, data):
        assert data == b"malware payload"
        return "stream: Eicar-Test-Signature FOUND"

    monkeypatch.setattr(clamav_module, "scan_bytes_with_clamd", fake_scan)

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.get("http://example.com/file", status=200, body=b"malware payload")

            res = await provider.scan("http://example.com/file", session)
            assert res.raw_score == 1.0
            assert "FOUND" in res.raw_response


@pytest.mark.asyncio
async def test_clamav_provider_scores_too_many_redirects_without_scanning():
    provider = ClamAVProvider(max_redirects=7)

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.get("http://example.com/start", status=301, headers={"Location": "http://example.com/r1"})
            m.get("http://example.com/r1", status=301, headers={"Location": "http://example.com/r2"})
            m.get("http://example.com/r2", status=301, headers={"Location": "http://example.com/r3"})
            m.get("http://example.com/r3", status=301, headers={"Location": "http://example.com/r4"})
            m.get("http://example.com/r4", status=301, headers={"Location": "http://example.com/r5"})
            m.get("http://example.com/r5", status=301, headers={"Location": "http://example.com/r6"})
            m.get("http://example.com/r6", status=301, headers={"Location": "http://example.com/r7"})
            m.get("http://example.com/r7", status=301, headers={"Location": "http://example.com/r8"})
            m.get("http://example.com/r8", status=200, body=b"late content")

            res = await provider.scan("http://example.com/start", session)
            assert res.raw_score == 0.9
            assert "more_than_7_redirects" in res.raw_response


@pytest.mark.asyncio
async def test_clamav_provider_logs_structured_http_error_for_blocked_fetch():
    provider = ClamAVProvider()

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.get(
                "https://www.digikey.de/",
                status=403,
                body="Access Denied - automated access blocked",
                headers={"Server": "AkamaiGHost", "Content-Type": "text/html"},
            )

            with patch.object(clamav_module.logger, "error") as log_error:
                result = await provider.scan("https://www.digikey.de/", session, link_id="link-123")

    assert result.raw_score is None
    assert len(result.errors) == 1
    assert "http_status=403" in result.errors[0]
    assert "block_hint=possible_bot_protection_or_access_denied" in result.errors[0]

    log_error.assert_called_once()
    _, kwargs = log_error.call_args
    extra_data = kwargs["extra"]["extra_data"]
    assert extra_data["link_id"] == "link-123"
    assert extra_data["http_status"] == 403
    assert extra_data["final_url"] == "https://www.digikey.de/"
    assert extra_data["server"] == "AkamaiGHost"
    assert extra_data["block_hint"] == "possible_bot_protection_or_access_denied"
    assert "Access Denied" in extra_data["response_preview"]


@pytest.mark.asyncio
async def test_heuristic_provider_scores_suspicious_godaddy_subdomain(monkeypatch):
    """
    Test that a suspicious subdomain on a known site-builder (like godaddysites.com)
    should NOT be scored as 0, even if the base domain is old.
    """
    provider = HeuristicProvider()

    async def mock_whois_old(hostname):
        return 0.0

    monkeypatch.setattr(provider.analyzer, "check_whois_age", mock_whois_old)

    url = "https://site-v4y2ws0vq.godaddysites.com/"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.get(url, status=200, body="<html></html>")
            m.head(url, status=200)

            res = await provider.scan(url, session)

    assert res.raw_score > 0


# ---------------------------------------------------------------------------
# Bug-Regression: brand_domains.csv / keyword→brand mapping
# ---------------------------------------------------------------------------

def test_brand_context_gmail_is_official():
    """gmail.com muss als offiziell erkannt werden (keyword 'gmail' → brand 'google')."""
    provider = HeuristicProvider()
    ctx = provider.domains.brand_context("gmail.com")
    assert ctx.official is True
    assert ctx.impersonation_score == 0.0


def test_brand_context_secure_paypal_subdomain_is_official():
    """secure.paypal.com ist eine legitime PayPal-Subdomain – official=True, kein Impersonation-Score."""
    provider = HeuristicProvider()
    ctx = provider.domains.brand_context("secure.paypal.com")
    assert ctx.official is True
    assert ctx.impersonation_score == 0.0


def test_brand_context_paypal_impersonation():
    """paypal-login.evil.com ist Impersonation – official=False, hoher Score."""
    provider = HeuristicProvider()
    ctx = provider.domains.brand_context("paypal-login.evil.com")
    assert ctx.official is False
    assert ctx.impersonation_score >= 0.8


def test_brand_context_netflix_is_official():
    """netflix.com war früher nicht in brand_domains.csv und wurde fälschlicherweise als Impersonation gewertet."""
    provider = HeuristicProvider()
    ctx = provider.domains.brand_context("netflix.com")
    assert ctx.official is True
    assert ctx.impersonation_score == 0.0


def test_brand_context_disney_is_official():
    """disney.com muss als offiziell erkannt werden."""
    provider = HeuristicProvider()
    ctx = provider.domains.brand_context("disney.com")
    assert ctx.official is True
    assert ctx.impersonation_score == 0.0


def test_brand_context_evil_netflix_flagged():
    """evil-netflix-login.tk ist eindeutig Impersonation."""
    provider = HeuristicProvider()
    ctx = provider.domains.brand_context("evil-netflix-login.tk")
    assert ctx.official is False
    assert ctx.impersonation_score >= 0.8


@pytest.mark.asyncio
async def test_heuristic_provider_gmail_low_risk(monkeypatch):
    """gmail.com darf keinen brand_impersonation-Signal erhalten."""
    provider = HeuristicProvider()
    monkeypatch.setattr(provider.analyzer, "check_whois_age", _no_whois_score)

    url = "https://mail.google.com/mail/"
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, headers={"Content-Type": "text/html"},
                  body='<form><input type="email"></form>')
            res = await provider.scan(url, session)

    assert "brand_impersonation" not in res.signals, (
        f"gmail.com should NOT be flagged as impersonation, signals={res.signals}"
    )


# ---------------------------------------------------------------------------
# Improvements v2: Trusted domains, Subdomains, Reasons, etc.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_trusted_domain_short_circuit():
    provider = HeuristicProvider()
    _update_provider_lists(provider, trusted_domains=("google.com",))

    async with aiohttp.ClientSession() as session:
        res = await provider.scan("https://www.google.com/search?q=test", session)
        assert res.raw_score == 0.0
        assert "trusted domain (www.google.com)" in res.reasons


@pytest.mark.asyncio
async def test_subdomain_entropy(monkeypatch):
    provider = HeuristicProvider()
    async def mock_whois(hostname): return 0.0
    monkeypatch.setattr(provider.analyzer, "check_whois_age", mock_whois)

    url = "https://a1b2c3d4e5f6.example.com"
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, body="<html></html>")
            res = await provider.scan(url, session)

    assert any("random-looking subdomain" in r for r in res.reasons)
    assert res.signals["suspicious_subdomain"] > 0


@pytest.mark.asyncio
async def test_subdomain_meaningful_long(monkeypatch):
    provider = HeuristicProvider()
    async def mock_whois(hostname): return 0.0
    monkeypatch.setattr(provider.analyzer, "check_whois_age", mock_whois)

    url = "https://service-status-dashboard-production.example.com"
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, body="<html></html>")
            res = await provider.scan(url, session)

    assert res.signals["suspicious_subdomain"] == provider.config.scores.subdomain_long
    assert any("unusually long/deep subdomain" in r for r in res.reasons)


@pytest.mark.asyncio
async def test_html_form_identity_provider(monkeypatch):
    provider = HeuristicProvider()
    async def mock_whois(hostname): return 0.0
    monkeypatch.setattr(provider.analyzer, "check_whois_age", mock_whois)
    _update_provider_lists(provider, identity_providers=("accounts.google.com",))

    url = "https://malicious-site.com/login"
    html = '<html><body><form action="https://accounts.google.com/o/oauth2/auth"><input type="password"></form></body></html>'

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, body=html, headers={"Content-Type": "text/html"})
            res = await provider.scan(url, session)

    assert res.signals["malicious_html_content"] == pytest.approx(0.12)
    assert any("idp action" in r for r in res.reasons)


@pytest.mark.asyncio
async def test_subdomain_of_match_mode(monkeypatch):
    provider = HeuristicProvider()
    from waechter.config_loader import BrandDomain
    new_brand_domains = {"testbrand": [BrandDomain(brand="testbrand", domain="testbrand.com", match_mode="subdomain_of")]}
    new_official_entries = (("testbrand.com", "subdomain_of"),)
    _update_provider_lists(provider, brand_domains=new_brand_domains, official_entries=new_official_entries)

    async def mock_whois(hostname): return 0.0
    monkeypatch.setattr(provider.analyzer, "check_whois_age", mock_whois)

    url = "https://sub.portal.testbrand.com/login"
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, body="<html></html>")
            res = await provider.scan(url, session)

    assert "brand_impersonation" not in res.signals


@pytest.mark.asyncio
async def test_whois_skip_hosting_platforms(monkeypatch):
    provider = HeuristicProvider()
    _update_provider_lists(provider, hosting_platforms=("workers.dev",))

    whois_called = False
    async def mock_whois(hostname):
        nonlocal whois_called
        whois_called = True
        return 0.5

    monkeypatch.setattr(provider.analyzer, "check_whois_age", mock_whois)

    url = "https://my-phish.workers.dev/"
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, body="<html></html>")
            res = await provider.scan(url, session)

    assert whois_called is False
    assert "whois_age_suspicious" not in res.signals


@pytest.mark.asyncio
async def test_reasons_and_signals_consistency(monkeypatch):
    provider = HeuristicProvider()
    async def mock_whois(hostname): return 0.0
    monkeypatch.setattr(provider.analyzer, "check_whois_age", mock_whois)

    url = "http://1.2.3.4/test"
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, body="<html></html>")
            res = await provider.scan(url, session)

    assert "ip_address" in res.signals
    assert any("raw IP in URL" in r for r in res.reasons)
    reason_for_ip = [r for r in res.reasons if "raw IP in URL" in r][0]
    assert f"(+{res.signals['ip_address']:.2f})" in reason_for_ip


@pytest.mark.asyncio
async def test_heuristic_provider_apk_download_reaches_warning(monkeypatch):
    """GitHub-APK-Download-Link muss mindestens Warning-Score (>= 0.4) erreichen."""
    provider = HeuristicProvider()
    async def mock_whois(hostname): return 0.0
    monkeypatch.setattr(provider.analyzer, "check_whois_age", mock_whois)

    url = "https://github.com/nortusmarsumi-create/Ppl/releases/download/v1.0/RTO_Challan.apk"
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, headers={"Content-Type": "application/octet-stream"}, body=b"")
            res = await provider.scan(url, session)

    assert res.raw_score >= 0.4, (
        f"APK-Download-Link sollte mindestens Warning-Score erreichen, "
        f"aber raw_score={res.raw_score:.3f}, signals={res.signals}, reasons={res.reasons}"
    )
    assert res.signals.get("suspicious_url_keywords", 0.0) > 0, (
        "Das Keyword 'apk' muss als suspicious_url_keywords erkannt werden"
    )
