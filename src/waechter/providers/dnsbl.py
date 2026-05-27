import asyncio
import socket
import ipaddress
import urllib.parse
import json
from typing import Any, Dict, List, Optional

import aiohttp
import idna
import redis.asyncio as redis

from waechter.providers.base import ScanProvider
from waechter.config_loader import as_bool, provider_cfg
from waechter.logger import get_logger

logger = get_logger()

class DnsblProvider(ScanProvider):
    name = "dnsbl"
    weight = 0.6

    def __init__(
        self,
        redis_url: str | None = None,
        redis_password: str | None = None,
        timeout_ms: int | None = None,
        max_ips: int | None = None,
        score_listed: float | None = None,
        use_spamscore: bool | None = None,
        enabled: bool | None = None,
        redis_client: Any = None,
    ):
        cfg = provider_cfg(self.name)
        self.weight = float(cfg.get("weight", 0.6))

        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = as_bool(cfg.get("enabled", False))

        self.redis_url = redis_url or cfg.get("redis_url", "redis://localhost:6379/0")
        self.redis_password = redis_password or cfg.get("redis_password")
        self.timeout_ms = timeout_ms if timeout_ms is not None else int(cfg.get("timeout_ms", 3000))
        self.max_ips = max_ips if max_ips is not None else int(cfg.get("max_ips", 8))
        self.score_listed = score_listed if score_listed is not None else float(cfg.get("score_listed", 0.6))
        self.use_spamscore = use_spamscore if use_spamscore is not None else as_bool(cfg.get("use_spamscore", False))

        self._redis = redis_client
        self._redis_lock = asyncio.Lock()

    async def _get_redis(self):
        if self._redis is not None:
            return self._redis
        
        async with self._redis_lock:
            if self._redis is None:
                # Password can be part of URL or separate
                self._redis = redis.from_url(
                    self.redis_url,
                    password=self.redis_password,
                    decode_responses=True
                )
        return self._redis

    def _normalize_hostname(self, hostname: str) -> str:
        if not hostname:
            return ""
        hostname = hostname.strip().strip(".").lower()
        try:
            # Handle IDN/Punycode
            return idna.decode(hostname.encode("ascii")).lower()
        except Exception:
            return hostname

    def _is_ip_address(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            return True
        except ValueError:
            return False

    async def scan(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        if not self.enabled:
            return {"raw_score": 0.0, "raw_response": "skipped: disabled"}

        try:
            return await asyncio.wait_for(self._scan_internal(url), timeout=self.timeout_ms / 1000.0)
        except asyncio.TimeoutError:
            logger.warning("dnsbl_timeout", extra={"extra_data": {"url": url, "timeout_ms": self.timeout_ms}})
            return {"raw_score": 0.0, "raw_response": {"error": "timeout"}}
        except Exception as e:
            logger.error("dnsbl_error", extra={"extra_data": {"url": url, "error": str(e)}})
            return {"raw_score": 0.0, "raw_response": {"error": str(e)}}

    async def _scan_internal(self, url: str) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return {"raw_score": 0.0, "raw_response": {"error": "no_hostname"}}

        normalized_host = self._normalize_hostname(hostname)
        ips = []
        skipped_ipv6 = False

        if self._is_ip_address(normalized_host):
            ips = [normalized_host.strip("[]")]
        else:
            try:
                loop = asyncio.get_running_loop()
                # Use getaddrinfo for async-safe DNS resolution
                addrinfo = await loop.getaddrinfo(normalized_host, None, family=socket.AF_INET)
                ips = list(dict.fromkeys([info[4][0] for info in addrinfo])) # unique IPs
                ips = ips[:self.max_ips]
            except socket.gaierror:
                logger.debug("dnsbl_dns_failed", extra={"extra_data": {"host": normalized_host}})
                return {
                    "raw_score": 0.0,
                    "raw_response": {
                        "hostname": normalized_host,
                        "error": "dns_failed"
                    }
                }

        # Filter global IPv4
        filtered_ips = []
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
                    "matches": []
                }
            }

        client = await self._get_redis()
        matches = []
        
        for ip_str in filtered_ips:
            ip_int = int(ipaddress.ip_address(ip_str))
            keys = []
            for mask in range(32, 7, -1):
                net_int = ip_int & (0xFFFFFFFF << (32 - mask))
                keys.append(f"u-{mask}:{net_int}")
            
            # Optimized lookup: one RTT for all masks of an IP
            values = await client.mget(keys)
            for i, val in enumerate(values):
                if val:
                    try:
                        data = json.loads(val)
                        # data expected: [isp_name, asn, spamscore]
                        mask = 32 - i
                        matches.append({
                            "ip": ip_str,
                            "mask": mask,
                            "isp": data[0] if len(data) > 0 else "unknown",
                            "asn": data[1] if len(data) > 1 else "unknown",
                            "spamscore": data[2] if len(data) > 2 else 0
                        })
                        break # Most specific hit wins for this IP
                    except (json.JSONDecodeError, TypeError, IndexError):
                        continue

        raw_score = 0.0
        if matches:
            if self.use_spamscore:
                max_spam = max(m.get("spamscore", 0) for m in matches)
                # Defensive scaling if spamscore is used
                raw_score = self.score_listed * (max_spam / 10.0 if max_spam < 10 else 1.0)
            else:
                raw_score = self.score_listed

        result = {
            "raw_score": min(raw_score, 1.0),
            "raw_response": {
                "hostname": normalized_host,
                "resolved_ips": filtered_ips,
                "listed": len(matches) > 0,
                "matches": matches,
                "source": "uceprotect-l3",
                "skipped_ipv6": skipped_ipv6,
                "error": None
            }
        }
        
        if matches:
            logger.info("dnsbl_hit", extra={"extra_data": {
                "url": url,
                "hostname": normalized_host,
                "matches": len(matches),
                "score": result["raw_score"]
            }})
        
        return result

    async def aclose(self):
        async with self._redis_lock:
            if self._redis is not None:
                await self._redis.aclose()
                self._redis = None
