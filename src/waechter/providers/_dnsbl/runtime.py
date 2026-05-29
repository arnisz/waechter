from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import urllib.parse

import idna
import redis.asyncio as redis

from waechter.logger import get_logger
from waechter.providers._dnsbl.config import DnsblSettings


logger = get_logger()


class DnsblRuntime:
    def __init__(self, settings: DnsblSettings, redis_client=None):
        self.settings = settings
        self._redis = redis_client
        self._redis_lock = asyncio.Lock()

    async def get_redis(self):
        if self._redis is not None:
            return self._redis

        async with self._redis_lock:
            if self._redis is None:
                self._redis = redis.from_url(
                    self.settings.redis_url,
                    password=self.settings.redis_password,
                    decode_responses=True,
                )
        return self._redis

    async def close(self) -> None:
        async with self._redis_lock:
            if self._redis is not None:
                await self._redis.aclose()
                self._redis = None

    def normalize_hostname(self, hostname: str) -> str:
        if not hostname:
            return ""
        hostname = hostname.strip().strip(".").lower()
        try:
            return idna.decode(hostname.encode("ascii")).lower()
        except Exception:
            return hostname

    def is_ip_address(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            return True
        except ValueError:
            return False

    async def scan_internal(self, url: str) -> dict[str, object]:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return {"raw_score": 0.0, "raw_response": {"error": "no_hostname"}}

        normalized_host = self.normalize_hostname(hostname)
        ips: list[str] = []
        skipped_ipv6 = False

        if self.is_ip_address(normalized_host):
            ips = [normalized_host.strip("[]")]
        else:
            try:
                loop = asyncio.get_running_loop()
                addrinfo = await loop.getaddrinfo(normalized_host, None, family=socket.AF_INET)
                ips = list(dict.fromkeys([info[4][0] for info in addrinfo]))
                ips = ips[:self.settings.max_ips]
            except socket.gaierror:
                logger.debug("dnsbl_dns_failed", extra={"extra_data": {"host": normalized_host}})
                return {
                    "raw_score": 0.0,
                    "raw_response": {"hostname": normalized_host, "error": "dns_failed"},
                }

        filtered_ips: list[str] = []
        for ip_str in ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.version == 6:
                    skipped_ipv6 = True
                    continue
                if ip_obj.is_global:
                    filtered_ips.append(ip_str)
            except ValueError:
                continue

        if not filtered_ips:
            return {
                "raw_score": 0.0,
                "raw_response": {
                    "hostname": normalized_host,
                    "resolved_ips": ips,
                    "skipped_ipv6": skipped_ipv6,
                    "listed": False,
                    "matches": [],
                },
            }

        client = await self.get_redis()
        matches = await self.lookup_matches(client, filtered_ips)

        raw_score = 0.0
        if matches:
            if self.settings.use_spamscore:
                max_spam = max(match.get("spamscore", 0) for match in matches)
                raw_score = self.settings.score_listed * (max_spam / 10.0 if max_spam < 10 else 1.0)
            else:
                raw_score = self.settings.score_listed

        result = {
            "raw_score": min(raw_score, 1.0),
            "raw_response": {
                "hostname": normalized_host,
                "resolved_ips": filtered_ips,
                "listed": len(matches) > 0,
                "matches": matches,
                "source": "uceprotect-l3",
                "skipped_ipv6": skipped_ipv6,
                "error": None,
            },
        }

        if matches:
            logger.info(
                "dnsbl_hit",
                extra={
                    "extra_data": {
                        "url": url,
                        "hostname": normalized_host,
                        "matches": len(matches),
                        "score": result["raw_score"],
                    }
                },
            )

        return result

    async def lookup_matches(self, client, filtered_ips: list[str]) -> list[dict[str, object]]:
        matches: list[dict[str, object]] = []
        for ip_str in filtered_ips:
            ip_int = int(ipaddress.ip_address(ip_str))
            keys = []
            for mask in range(32, 7, -1):
                net_int = ip_int & (0xFFFFFFFF << (32 - mask))
                keys.append(f"u-{mask}:{net_int}")

            values = await client.mget(keys)
            for index, value in enumerate(values):
                if not value:
                    continue
                try:
                    data = json.loads(value)
                    mask = 32 - index
                    matches.append(
                        {
                            "ip": ip_str,
                            "mask": mask,
                            "isp": data[0] if len(data) > 0 else "unknown",
                            "asn": data[1] if len(data) > 1 else "unknown",
                            "spamscore": data[2] if len(data) > 2 else 0,
                        }
                    )
                    break
                except (json.JSONDecodeError, TypeError, IndexError):
                    continue
        return matches
