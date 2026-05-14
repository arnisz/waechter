from typing import Any, Dict
import json

import aiohttp

from waechter.providers.base import QuotaAwareProvider
from waechter.config_loader import as_bool, provider_cfg


class GoogleSafeBrowsingProvider(QuotaAwareProvider):
    name = "google_safe_browsing"
    weight = 1.0
    daily_limit = 10000

    def __init__(self, api_key: str):
        super().__init__()
        cfg = provider_cfg(self.name)

        # weight and daily limit from config (fallbacks preserve previous behavior)
        self.weight = float(cfg.get("weight", 1.0))
        self.daily_limit = int((cfg.get("api", {}) or {}).get("daily_limit", 10000))

        client = (cfg.get("api", {}) or {}).get("client", {}) or {}
        self.client_id = str(client.get("id", "waechter"))
        self.client_version = str(client.get("version", "1.1.0"))

        self.api_key = api_key
        # enabled flag respects config but requires an API key
        self.enabled = as_bool(cfg.get("enabled", True)) and bool(self.api_key)

    async def scan(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        if not self.enabled:
            return {"raw_score": 0.0}

        self.check_and_increment_quota()
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {"clientId": self.client_id, "clientVersion": self.client_version},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        async with session.post(api_url, json=payload) as resp:
            resp.raise_for_status()
            data = await resp.json()
            if "matches" in data and len(data["matches"]) > 0:
                return {
                    "raw_score": 1.0,
                    "raw_response": json.dumps(data)
                }
            return {"raw_score": 0.0}
