from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import aiohttp


class QuotaExhaustedError(Exception):
    pass


class RedirectLimitExceededError(Exception):
    pass


class ScanProvider(ABC):
    name: str
    weight: float
    enabled: bool = True

    @abstractmethod
    async def scan(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Gibt ein dict mit raw_score und optionalem raw_response zurück."""
        pass


class QuotaAwareProvider(ScanProvider):
    daily_limit: int

    def __init__(self):
        self.daily_used = 0
        self.daily_reset_at = self._next_midnight()

    def _next_midnight(self) -> datetime:
        now = datetime.now(timezone.utc)
        return (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

    def check_and_increment_quota(self):
        if datetime.now(timezone.utc) >= self.daily_reset_at:
            self.daily_used = 0
            self.daily_reset_at = self._next_midnight()

        if self.daily_used >= self.daily_limit:
            raise QuotaExhaustedError(self.name)
        self.daily_used += 1
