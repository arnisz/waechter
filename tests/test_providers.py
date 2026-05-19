from datetime import datetime
import pytest
import aiohttp
from waechter.providers import HeuristicProvider, GoogleSafeBrowsingProvider, ClamAVProvider
from aioresponses import aioresponses
from unittest.mock import patch

import waechter.providers.clamav as clamav_module


async def _no_whois_score(hostname):
    return 0.0

@pytest.mark.asyncio
async def test_heuristic_provider():
    provider = HeuristicProvider()
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            # IP test
            m.get("http://192.168.0.1/path", status=200)
            res = await provider.scan("http://192.168.0.1/path", session)
            assert res["raw_score"] >= 0.6

        with aioresponses() as m:
            # Suspicious TLD
            m.get("http://example.tk", status=200)
            res2 = await provider.scan("http://example.tk", session)
            assert res2["raw_score"] >= 0.5

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
            assert res["raw_score"] >= 0.2

@pytest.mark.asyncio
async def test_heuristic_provider_scores_redirect_to_raw_ip():
    provider = HeuristicProvider()
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head("http://example.com/start", status=301, headers={"Location": "http://203.0.113.10/final"})
            m.head("http://203.0.113.10/final", status=200)

            res = await provider.scan("http://example.com/start", session)
            assert res["raw_score"] >= 0.7


def test_heuristic_provider_extracts_registrable_domain():
    provider = HeuristicProvider()

    assert provider._get_registrable_domain("www.amazon.de") == "amazon.de"
    assert provider._get_registrable_domain("login.amazon.co.uk") == "amazon.co.uk"
    assert provider._get_registrable_domain("amazon.de.evil.com") == "evil.com"


@pytest.mark.asyncio
async def test_heuristic_provider_treats_official_amazon_payment_url_as_low_risk(monkeypatch):
    provider = HeuristicProvider()
    url = "https://www.amazon.de/manage-monthly-payments?state=active"

    async def fail_if_called(hostname):
        raise AssertionError("WHOIS should be skipped for official brand domains")

    monkeypatch.setattr(provider, "_check_whois_age", fail_if_called)

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

    assert res["raw_score"] < 0.3
    assert "brand_impersonation" not in res["signals"]
    assert res["signals"].get("suspicious_url_keywords", 0.0) <= 0.05
    assert res["signals"].get("malicious_html_content", 0.0) <= 0.1


@pytest.mark.asyncio
async def test_heuristic_provider_scores_amazon_impersonation_as_high_risk(monkeypatch):
    provider = HeuristicProvider()
    monkeypatch.setattr(provider, "_check_whois_age", _no_whois_score)
    url = "https://amazon.manage-monthly-payments.example.top/login"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, headers={"Content-Type": "text/plain"}, body="")

            res = await provider.scan(url, session)

    assert res["raw_score"] >= 0.95
    assert res["signals"]["brand_impersonation"] >= 0.5
    assert res["signals"]["suspicious_path"] >= 0.3
    assert res["signals"]["suspicious_url_keywords"] >= 0.4


@pytest.mark.asyncio
async def test_heuristic_provider_scores_userinfo_trick(monkeypatch):
    provider = HeuristicProvider()
    monkeypatch.setattr(provider, "_check_whois_age", _no_whois_score)
    url = "https://www.amazon.de@evil.com/login"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, headers={"Content-Type": "text/plain"}, body="")

            res = await provider.scan(url, session)

    assert res["signals"]["url_userinfo_present"] == 0.8


@pytest.mark.asyncio
async def test_heuristic_provider_scores_punycode_hostname(monkeypatch):
    provider = HeuristicProvider()
    monkeypatch.setattr(provider, "_check_whois_age", _no_whois_score)
    url = "https://xn--amazn-mra.de/login"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.head(url, status=200)
            m.get(url, status=200, headers={"Content-Type": "text/plain"}, body="")

            res = await provider.scan(url, session)

    assert res["signals"]["punycode_hostname"] == 0.5

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
            assert res["raw_score"] == 1.0
            assert "matches" in res["raw_response"]

        with aioresponses() as m:
            m.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=dummy-key",
                payload={}
            )
            res2 = await provider.scan("http://good-url.com", session)
            assert res2["raw_score"] == 0.0

@pytest.mark.asyncio
async def test_clamav_provider_scores_found(monkeypatch):
    provider = ClamAVProvider()

    def fake_scan(data):
        assert data == b"malware payload"
        return "stream: Eicar-Test-Signature FOUND"

    monkeypatch.setattr(provider, "_scan_bytes_with_clamd", fake_scan)

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.get("http://example.com/file", status=200, body=b"malware payload")

            res = await provider.scan("http://example.com/file", session)
            assert res["raw_score"] == 1.0
            assert "FOUND" in res["raw_response"]

@pytest.mark.asyncio
async def test_clamav_provider_scores_too_many_redirects_without_scanning(monkeypatch):
    provider = ClamAVProvider(max_redirects=7)

    def fake_scan(data):
        raise AssertionError("ClamAV scan must not be called after too many redirects")

    monkeypatch.setattr(provider, "_scan_bytes_with_clamd", fake_scan)

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
            assert res["raw_score"] == 0.9
            assert "more_than_7_redirects" in res["raw_response"]


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
                with pytest.raises(clamav_module.ClamAVDownloadError) as exc_info:
                    await provider.scan("https://www.digikey.de/", session, link_id="link-123")

    message = str(exc_info.value)
    assert "http_status=403" in message
    assert "block_hint=possible_bot_protection_or_access_denied" in message

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
    
    Reproducer for reported issue: https://site-v4y2ws0vq.godaddysites.com/
    Currently this test FAILS as expected.
    """
    provider = HeuristicProvider()
    
    # Mock WHOIS to return an OLD creation date (2013) to reflect real world godaddysites.com
    async def mock_whois_old(hostname):
        return 0.0

    monkeypatch.setattr(provider, "_check_whois_age", mock_whois_old)
    
    url = "https://site-v4y2ws0vq.godaddysites.com/"
    
    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.get(url, status=200, body="<html></html>")
            m.head(url, status=200)
            
            res = await provider.scan(url, session)
            
    # Expected: score > 0 because site-v4y2ws0vq is a suspicious random-looking subdomain
    assert res["raw_score"] > 0
