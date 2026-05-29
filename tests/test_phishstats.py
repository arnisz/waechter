import pytest
import aiohttp
from waechter.providers.phishstats import PhishStatsProvider
from aioresponses import aioresponses

@pytest.mark.asyncio
async def test_phishstats_provider_hit():
    provider = PhishStatsProvider()
    url = "http://phishing-site.com"
    api_url = f"https://api.phishstats.info/api/phishing?_where=(url,eq,{url})"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.get(
                api_url,
                payload=[{"url": url, "ip": "1.2.3.4"}]
            )
            res = await provider.scan(url, session)
            assert res.raw_score == 1.0
            assert res.raw_response is not None
            assert "1.2.3.4" in res.raw_response

@pytest.mark.asyncio
async def test_phishstats_provider_miss():
    provider = PhishStatsProvider()
    url = "http://safe-site.com"
    api_url = f"https://api.phishstats.info/api/phishing?_where=(url,eq,{url})"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.get(
                api_url,
                payload=[]
            )
            res = await provider.scan(url, session)
            assert res.raw_score == 0.0

@pytest.mark.asyncio
async def test_phishstats_provider_error():
    provider = PhishStatsProvider()
    url = "http://error-site.com"
    api_url = f"https://api.phishstats.info/api/phishing?_where=(url,eq,{url})"

    async with aiohttp.ClientSession() as session:
        with aioresponses() as m:
            m.get(
                api_url,
                status=500
            )
            res = await provider.scan(url, session)
            assert res.raw_score is None
            assert res.errors

def test_phishstats_provider_weight():
    provider = PhishStatsProvider()
    assert provider.weight == 0.7
