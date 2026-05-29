import asyncio
import json

import aiohttp
import pytest

from waechter import loop
from waechter.providers import ScanProvider


class RecordingApi:
    def __init__(self):
        self.payloads = []

    async def post_scan_result(self, session, link_id, payload):
        self.payloads.append((link_id, payload))


class FailingThenRecordingApi:
    def __init__(self, failures):
        self.failures = failures
        self.payloads = []

    async def post_scan_result(self, session, link_id, payload):
        self.payloads.append((link_id, payload))
        if self.failures > 0:
            self.failures -= 1
            raise RuntimeError("backend rejected payload")


class SlowProvider(ScanProvider):
    name = "slow"
    weight = 1.0
    enabled = True

    async def scan(self, url, session, link_id=None):
        await asyncio.sleep(10)
        return self.build_result(0.0)


class FailingProvider(ScanProvider):
    name = "failing"
    weight = 1.0
    enabled = True

    async def scan(self, url, session, link_id=None):
        raise RuntimeError("boom")


class DictProvider(ScanProvider):
    name = "dict_provider"
    weight = 1.0
    enabled = True

    async def scan(self, url, session, link_id=None):
        return self.build_result(0.6, raw_response={"detail": "kept as json string"})


@pytest.fixture(autouse=True)
def reset_loop_state(monkeypatch):
    loop.link_failures.clear()
    monkeypatch.setattr(loop, "PROVIDER_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(loop, "MAX_LINK_SCAN_ATTEMPTS", 3)
    monkeypatch.setattr(loop, "PROBLEM_LINK_SCORE", 0.7)
    yield
    loop.link_failures.clear()


def pending_link(link_id="problem-link"):
    return {
        "id": link_id,
        "short_code": "abc123",
        "target_url": "https://example.test/problem",
        "created_at": "2026-05-29T00:00:00Z",
    }


@pytest.mark.asyncio
async def test_provider_timeout_is_counted_and_fallback_posts_warning_after_three_attempts():
    api = RecordingApi()
    link = pending_link()

    async with aiohttp.ClientSession() as session:
        await loop.scan_single_link(link, [SlowProvider()], api, session)
        await loop.scan_single_link(link, [SlowProvider()], api, session)
        await loop.scan_single_link(link, [SlowProvider()], api, session)

    assert len(api.payloads) == 1
    link_id, payload = api.payloads[0]
    assert link_id == "problem-link"
    assert payload["aggregate_score"] == 0.7
    assert payload["status"] == "warning"
    assert payload["scans"][0]["provider"] == "waechter_worker"
    raw_response = json.loads(payload["scans"][0]["raw_response"])
    assert raw_response["failure_count"] == 3
    assert raw_response["reason"] == "all_providers_failed_or_timed_out"
    assert "problem-link" not in loop.link_failures


@pytest.mark.asyncio
async def test_provider_errors_are_counted_without_post_before_max_attempts():
    api = RecordingApi()
    link = pending_link("failing-link")

    async with aiohttp.ClientSession() as session:
        await loop.scan_single_link(link, [FailingProvider()], api, session)
        await loop.scan_single_link(link, [FailingProvider()], api, session)

    assert api.payloads == []
    assert loop.link_failures["failing-link"] == 2


@pytest.mark.asyncio
async def test_successful_scan_resets_previous_failure_and_serializes_raw_response():
    api = RecordingApi()
    link = pending_link("recovered-link")
    loop.link_failures["recovered-link"] = 2

    async with aiohttp.ClientSession() as session:
        await loop.scan_single_link(link, [DictProvider()], api, session)

    assert "recovered-link" not in loop.link_failures
    assert len(api.payloads) == 1
    payload = api.payloads[0][1]
    assert payload["scans"][0]["raw_response"] == '{"detail": "kept as json string"}'


@pytest.mark.asyncio
async def test_repeated_post_failures_try_reduced_warning_fallback_payload():
    api = FailingThenRecordingApi(failures=3)
    link = pending_link("post-failing-link")

    async with aiohttp.ClientSession() as session:
        await loop.scan_single_link(link, [DictProvider()], api, session)
        await loop.scan_single_link(link, [DictProvider()], api, session)
        await loop.scan_single_link(link, [DictProvider()], api, session)

    assert len(api.payloads) == 4
    fallback_payload = api.payloads[-1][1]
    assert fallback_payload["aggregate_score"] == 0.7
    assert fallback_payload["status"] == "warning"
    assert fallback_payload["scans"][0]["provider"] == "waechter_worker"
    raw_response = json.loads(fallback_payload["scans"][0]["raw_response"])
    assert raw_response["reason"] == "scan_result_post_failed"
    assert raw_response["failure_count"] == 3
    assert "post-failing-link" not in loop.link_failures
