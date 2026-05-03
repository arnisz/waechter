import pytest
from src.aggregation import aggregate_score, map_status

def test_aggregate_score():
    scans = [
        {"raw_score": 1.0, "weight": 0.5},
        {"raw_score": 0.8, "weight": 1.0}
    ]
    assert aggregate_score(scans) == 1.0

    assert aggregate_score([]) == 0.0

def test_aggregate_score_combines_independent_signals():
    scans = [
        {"raw_score": 0.6, "weight": 0.6},
        {"raw_score": 0.8, "weight": 1.0}
    ]

    assert aggregate_score(scans) == pytest.approx(0.8846, abs=0.0001)

def test_aggregate_score_treats_zero_as_no_positive_evidence():
    scans = [
        {"raw_score": 0.0, "weight": 0.6},
        {"raw_score": 1.0, "weight": 1.0},
        {"raw_score": 0.0, "weight": 1.0}
    ]

    assert aggregate_score(scans) == 1.0

def test_map_status():
    assert map_status(0.96) == 'blocked'
    assert map_status(0.95) == 'blocked'
    assert map_status(0.80) == 'warning'
    assert map_status(0.70) == 'warning'
    assert map_status(0.69) == 'active'
    assert map_status(0.0) == 'active'

