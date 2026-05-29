from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp


class QuotaExhaustedError(Exception):
    pass


class RedirectLimitExceededError(Exception):
    pass


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    weight: float
    raw_score: float | None
    raw_response: Any = None
    signals: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_verdict(self) -> bool:
        return self.raw_score is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "weight": self.weight,
            "raw_score": self.raw_score,
            "raw_response": self.raw_response,
            "signals": dict(self.signals),
            "reasons": list(self.reasons),
            "errors": list(self.errors),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProviderResult":
        raw_score = value.get("raw_score")
        return cls(
            provider=str(value.get("provider", "")),
            weight=float(value.get("weight", 1.0)),
            raw_score=None if raw_score is None else float(raw_score),
            raw_response=value.get("raw_response"),
            signals={str(k): float(v) for k, v in dict(value.get("signals") or {}).items()},
            reasons=list(value.get("reasons") or []),
            errors=list(value.get("errors") or []),
        )


class ScanProvider(ABC):
    name: str
    weight: float
    enabled: bool = True
    required_env_vars: tuple[str, ...] = ()
    optional_env_vars: tuple[str, ...] = ()
    startup_loaded: bool | None = None
    startup_reason: str = ""

    @abstractmethod
    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        link_id: str | None = None,
    ) -> ProviderResult:
        """Return a structured provider result."""
        pass

    def build_result(
        self,
        raw_score: float | None,
        *,
        raw_response: Any = None,
        signals: dict[str, float] | None = None,
        reasons: list[str] | None = None,
        errors: list[str] | None = None,
    ) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            weight=float(getattr(self, "weight", 1.0)),
            raw_score=raw_score,
            raw_response=raw_response,
            signals=dict(signals or {}),
            reasons=list(reasons or []),
            errors=list(errors or []),
        )

    def no_verdict(
        self,
        *errors: str,
        raw_response: Any = None,
        signals: dict[str, float] | None = None,
        reasons: list[str] | None = None,
    ) -> ProviderResult:
        return self.build_result(
            None,
            raw_response=raw_response,
            signals=signals,
            reasons=reasons,
            errors=[str(error) for error in errors if str(error)],
        )


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
