import aiohttp
from typing import List
from src.types import PendingLink, ScanResultPayload

class WorkerApi:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    async def get_pending(self, session: aiohttp.ClientSession, limit: int = 50) -> List[PendingLink]:
        url = f"{self.base_url}/api/internal/links/pending?limit={limit}"
        async with session.get(url, headers=self.headers) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data.get("links", [])

    async def post_scan_result(self, session: aiohttp.ClientSession, link_id: str, payload: ScanResultPayload) -> None:
        url = f"{self.base_url}/api/internal/links/{link_id}/scan-result"
        async with session.post(url, headers=self.headers, json=payload) as resp:
            if resp.status == 404:
                return # manual_override=1 expected handling
            resp.raise_for_status()

    async def release_stale(self, session: aiohttp.ClientSession) -> None:
        url = f"{self.base_url}/api/internal/links/release-stale"
        async with session.post(url, headers=self.headers) as resp:
            resp.raise_for_status()

    async def health(self, session: aiohttp.ClientSession) -> None:
        url = f"{self.base_url}/api/internal/health"
        async with session.get(url, headers=self.headers) as resp:
            resp.raise_for_status()

