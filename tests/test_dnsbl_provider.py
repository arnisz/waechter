import pytest
import aiohttp
import json
import socket
import ipaddress
from unittest.mock import AsyncMock, MagicMock, patch
from waechter.providers.dnsbl import DnsblProvider

class AsyncMockRedis:
    def __init__(self):
        self.data = {}
        self.aclose = AsyncMock()

    async def mget(self, keys):
        return [self.data.get(k) for k in keys]

    def set(self, key, value):
        self.data[key] = value

@pytest.mark.asyncio
async def test_dnsbl_provider_listed():
    mock_redis = AsyncMockRedis()
    # IP 1.2.3.4 -> int 16909060
    # Mask 32: u-32:16909060
    mock_redis.set("u-32:16909060", json.dumps(["Test ISP", "AS123", 5]))

    provider = DnsblProvider(enabled=True, redis_client=mock_redis)

    async with aiohttp.ClientSession() as session:
        # Host is IP
        res = await provider.scan("http://1.2.3.4", session)
        assert res.raw_score == 0.6
        assert res.raw_response["listed"] is True
        assert res.raw_response["matches"][0]["isp"] == "Test ISP"

@pytest.mark.asyncio
async def test_dnsbl_provider_not_listed():
    mock_redis = AsyncMockRedis()
    provider = DnsblProvider(enabled=True, redis_client=mock_redis)

    async with aiohttp.ClientSession() as session:
        res = await provider.scan("http://1.1.1.1", session)
        assert res.raw_score == 0.0
        assert res.raw_response["listed"] is False
        assert res.raw_response["matches"] == []

@pytest.mark.asyncio
async def test_dnsbl_provider_dns_resolution():
    mock_redis = AsyncMockRedis()
    mock_redis.set("u-32:16909060", json.dumps(["Test ISP", "AS123", 5]))

    provider = DnsblProvider(enabled=True, redis_client=mock_redis, redis_url="redis://localhost")

    async with aiohttp.ClientSession() as session:
        with patch("asyncio.get_running_loop") as mock_loop:
            mock_l = MagicMock()
            mock_l.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.2.3.4", 80))])
            mock_loop.return_value = mock_l

            res = await provider.scan("http://example.com", session)
            assert res.raw_score == 0.6
            assert res.raw_response["resolved_ips"] == ["1.2.3.4"]

@pytest.mark.asyncio
async def test_dnsbl_provider_private_ip():
    mock_redis = AsyncMockRedis()
    provider = DnsblProvider(enabled=True, redis_client=mock_redis)

    async with aiohttp.ClientSession() as session:
        res = await provider.scan("http://192.168.1.1", session)
        assert res.raw_score == 0.0
        assert res.raw_response["resolved_ips"] == ["192.168.1.1"]
        assert res.raw_response["matches"] == []

@pytest.mark.asyncio
async def test_dnsbl_provider_mask_matching():
    mock_redis = AsyncMockRedis()
    # 1.2.3.4 -> /24 match
    # IP: 1.2.3.4
    # /24 net: 1.2.3.0 -> int 16909056
    mock_redis.set("u-24:16909056", json.dumps(["Net ISP", "AS456", 7]))

    provider = DnsblProvider(enabled=True, redis_client=mock_redis)

    async with aiohttp.ClientSession() as session:
        res = await provider.scan("http://1.2.3.4", session)
        assert res.raw_score == 0.6
        assert res.raw_response["matches"][0]["mask"] == 24
        assert res.raw_response["matches"][0]["isp"] == "Net ISP"

@pytest.mark.asyncio
async def test_dnsbl_provider_most_specific_wins():
    mock_redis = AsyncMockRedis()
    # 1.2.3.4 -> /24 and /32 matches
    mock_redis.set("u-24:16909056", json.dumps(["Net ISP", "AS456", 7]))
    mock_redis.set("u-32:16909060", json.dumps(["Host ISP", "AS123", 5]))

    provider = DnsblProvider(enabled=True, redis_client=mock_redis)

    async with aiohttp.ClientSession() as session:
        res = await provider.scan("http://1.2.3.4", session)
        assert res.raw_response["matches"][0]["mask"] == 32
        assert res.raw_response["matches"][0]["isp"] == "Host ISP"

@pytest.mark.asyncio
async def test_dnsbl_provider_redis_error():
    mock_redis = MagicMock()
    mock_redis.mget = AsyncMock(side_effect=Exception("Redis down"))

    provider = DnsblProvider(enabled=True, redis_client=mock_redis)

    async with aiohttp.ClientSession() as session:
        # Should not raise exception, return no_verdict (raw_score=None)
        res = await provider.scan("http://1.2.3.4", session)
        assert res.raw_score is None
        assert "error" in res.raw_response

@pytest.mark.asyncio
async def test_dnsbl_provider_idn():
    mock_redis = AsyncMockRedis()
    provider = DnsblProvider(enabled=True, redis_client=mock_redis)

    async with aiohttp.ClientSession() as session:
        with patch("asyncio.get_running_loop") as mock_loop:
            mock_l = MagicMock()
            mock_l.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ("1.1.1.1", 80))])
            mock_loop.return_value = mock_l

            # xn--brse-5qa.de -> börse.de
            await provider.scan("http://xn--brse-5qa.de", session)
            mock_l.getaddrinfo.assert_called()
            # The first argument should be the decoded hostname
            args, kwargs = mock_l.getaddrinfo.call_args
            assert args[0] == "börse.de"

@pytest.mark.asyncio
async def test_dnsbl_provider_use_spamscore():
    mock_redis = AsyncMockRedis()
    # 1.2.3.4 -> spamscore 5
    mock_redis.set("u-32:16909060", json.dumps(["Test ISP", "AS123", 5]))

    # score_listed = 0.6.
    # spamscore 5 -> 5/10 * 0.6 = 0.3
    provider = DnsblProvider(enabled=True, redis_client=mock_redis, use_spamscore=True, score_listed=0.6)

    async with aiohttp.ClientSession() as session:
        res = await provider.scan("http://1.2.3.4", session)
        assert res.raw_score == pytest.approx(0.3)

    # spamscore 10 -> 10/10 * 0.6 = 0.6
    mock_redis.set("u-32:16909060", json.dumps(["Test ISP", "AS123", 10]))
    async with aiohttp.ClientSession() as session:
        res = await provider.scan("http://1.2.3.4", session)
        assert res.raw_score == pytest.approx(0.6)

@pytest.mark.asyncio
async def test_dnsbl_provider_ipv6_skipped():
    mock_redis = AsyncMockRedis()
    provider = DnsblProvider(enabled=True, redis_client=mock_redis)

    async with aiohttp.ClientSession() as session:
        with patch("asyncio.get_running_loop") as mock_loop:
            mock_l = MagicMock()
            # Return an IPv6 address
            mock_l.getaddrinfo = AsyncMock(return_value=[(socket.AF_INET6, None, None, None, ("2001:db8::1", 80))])
            mock_loop.return_value = mock_l

            res = await provider.scan("http://example.com", session)

        res = await provider.scan("http://[2001:db8::1]", session)
        assert res.raw_score == 0.0
        assert res.raw_response["skipped_ipv6"] is True
