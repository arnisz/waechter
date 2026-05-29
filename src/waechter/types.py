import os
from typing import TypedDict, List, Optional, Literal


class PendingLink(TypedDict):
    id: str
    short_code: str
    target_url: str
    created_at: str


class ProviderScanPayload(TypedDict):
    provider: str
    raw_score: float
    raw_response: Optional[str]


class ScanResultPayload(TypedDict):
    aggregate_score: float
    status: Literal['active', 'warning', 'blocked']
    scans: List[ProviderScanPayload]


class ScanResult(TypedDict):
    raw_score: float
    raw_response: Optional[str]
