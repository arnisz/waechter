import os
import math
from typing import Literal

THRESHOLD_WARNING = float(os.environ.get("THRESHOLD_WARNING", 0.70))
THRESHOLD_BLOCK = float(os.environ.get("THRESHOLD_BLOCK", 0.95))

def aggregate_score(scans: list[dict]) -> float:
    if not scans:
        return 0.0

    # Bayesian noisy-OR: providers contribute independent positive evidence.
    # A score of 0.0 means "no positive signal", not proof that the URL is safe.
    probability_clean = 1.0
    for scan in scans:
        raw_score = _clamp_probability(float(scan["raw_score"]))
        weight = max(float(scan.get("weight", 1.0)), 0.0)

        if raw_score == 0.0 or weight == 0.0:
            continue

        probability_clean *= math.pow(1.0 - raw_score, weight)

    return _clamp_probability(1.0 - probability_clean)

def _clamp_probability(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value

def map_status(score: float, custom_warn: float = None, custom_block: float = None) -> Literal['active', 'warning', 'blocked']:
    warn = custom_warn if custom_warn is not None else THRESHOLD_WARNING
    block = custom_block if custom_block is not None else THRESHOLD_BLOCK

    if score >= block:
        return 'blocked'
    if score >= warn:
        return 'warning'
    return 'active'

