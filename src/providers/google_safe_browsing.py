from typing import Any, Dict
import json

import aiohttp

from src.providers.base import QuotaAwareProvider


class GoogleSafeBrowsingProvider(QuotaAwareProvider):
    name = "google_safe_browsing"
    weight = 1.0
    daily_limit = 10000

    def __init__(self, api_key: str):
        super().__init__()
        self.api_key = api_key
        if not self.api_key:
            self.enabled = False

    async def scan(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        if not self.enabled:
            return {"raw_score": 0.0}

        self.check_and_increment_quota()
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {"clientId": "waechter", "clientVersion": "1.1.0"},
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
