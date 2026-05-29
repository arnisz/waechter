import os
import sys
import json
import asyncio
import aiohttp
from typing import Any, List, cast
from waechter.types import PendingLink, ProviderScanPayload, ScanResultPayload
from waechter.api import WorkerApi
from waechter.providers import ScanProvider, QuotaExhaustedError
from waechter.aggregation import aggregate_score, map_status
from waechter.logger import get_logger

logger = get_logger()

MIN_WAIT_MS = int(os.environ.get("MIN_WAIT_MS", 5000))
MAX_WAIT_MS = int(os.environ.get("MAX_WAIT_MS", 60000))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", 50))
SCAN_CONCURRENCY = int(os.environ.get("SCAN_CONCURRENCY", 20))
PROVIDER_TIMEOUT_SECONDS = float(os.environ.get("PROVIDER_TIMEOUT_SECONDS", 60))
MAX_LINK_SCAN_ATTEMPTS = int(os.environ.get("MAX_LINK_SCAN_ATTEMPTS", 3))
PROBLEM_LINK_SCORE = float(os.environ.get("PROBLEM_LINK_SCORE", os.environ.get("THRESHOLD_WARNING", 0.70)))
PROBLEM_LINK_PROVIDER = "waechter_worker"

wait_ms = MIN_WAIT_MS
sem = asyncio.Semaphore(SCAN_CONCURRENCY)
link_failures: dict[str, int] = {}


def _build_problem_link_payload(link: PendingLink, failure_count: int, reason: str) -> ScanResultPayload:
    score = round(PROBLEM_LINK_SCORE, 4)
    return {
        "aggregate_score": score,
        "status": map_status(score),
        "scans": cast(List[ProviderScanPayload], [
            {
                "provider": PROBLEM_LINK_PROVIDER,
                "raw_score": score,
                "raw_response": json.dumps({
                    "reason": reason,
                    "failure_count": failure_count,
                    "max_attempts": MAX_LINK_SCAN_ATTEMPTS,
                    "action": "marked_after_repeated_worker_failures",
                    "target_url": link["target_url"],
                }),
            }
        ]),
    }


def _normalize_provider_result(provider: ScanProvider, result: Any) -> dict[str, Any] | None:
    if result is None:
        return None

    if hasattr(result, "to_dict"):
        payload = cast(dict[str, Any], result.to_dict())
    elif isinstance(result, dict):
        payload = dict(result)
    else:
        logger.warning(
            "provider_scan_unexpected_result",
            extra={"extra_data": {"provider": provider.name, "result_type": type(result).__name__}},
        )
        return None

    raw_score = payload.get("raw_score")
    if raw_score is None:
        return None

    payload.setdefault("provider", provider.name)
    payload.setdefault("weight", float(getattr(result, "weight", getattr(provider, "weight", 1.0))))
    payload["raw_score"] = float(raw_score)
    return payload

async def scan_single_link(link: PendingLink, providers: List[ScanProvider], api: WorkerApi, session: aiohttp.ClientSession) -> None:
    scans_payload: List[dict[str, Any]] = []
    aggregation_inputs: List[dict[str, Any]] = []
    provider_failures: List[dict[str, Any]] = []

    logger.info("scan_started", extra={"extra_data": {
        "link_id": link["id"],
        "short_code": link.get("short_code"),
        "url": link["target_url"],
        "previous_failures": link_failures.get(link["id"], 0),
        "provider_timeout_seconds": PROVIDER_TIMEOUT_SECONDS,
        "max_link_scan_attempts": MAX_LINK_SCAN_ATTEMPTS,
    }})

    for provider in providers:
        if not provider.enabled:
            logger.debug("provider_skipped_disabled", extra={"extra_data": {
                "provider": provider.name,
                "link_id": link["id"],
            }})
            continue
        try:
            logger.debug("provider_scan_start", extra={"extra_data": {
                "provider": provider.name,
                "link_id": link["id"],
                "url": link["target_url"],
            }})
            res = await asyncio.wait_for(
                provider.scan(link["target_url"], session, link_id=link["id"]),
                timeout=PROVIDER_TIMEOUT_SECONDS,
            )
            normalized = _normalize_provider_result(provider, res)
            if normalized is None:
                provider_failures.append({"provider": provider.name, "error_type": "NoVerdict", "error": "provider returned no usable result"})
                logger.debug("provider_scan_no_verdict", extra={"extra_data": {
                    "provider": provider.name,
                    "link_id": link["id"],
                }})
                continue

            raw_response = normalized.get("raw_response")
            logger.debug("provider_scan_result", extra={"extra_data": {
                "provider": provider.name,
                "link_id": link["id"],
                "raw_score": normalized["raw_score"],
                "has_raw_response": raw_response is not None,
                "raw_response_preview": str(raw_response)[:300] if raw_response is not None else None,
                "weight": provider.weight,
            }})
            scan_raw_score = round(float(normalized["raw_score"]), 4)
            if raw_response is not None and scan_raw_score >= 0.3:
                if isinstance(raw_response, (dict, list)):
                    scan_raw_response = json.dumps(raw_response)
                else:
                    scan_raw_response = str(raw_response)
            else:
                scan_raw_response = None

            scan_payload_entry = {
                "provider": str(normalized.get("provider", provider.name)),
                "raw_score": scan_raw_score,
                "raw_response": scan_raw_response,
            }
            scans_payload.append(scan_payload_entry)
            aggregation_inputs.append({
                "provider": str(normalized.get("provider", provider.name)),
                "raw_score": scan_raw_score,
                "raw_response": scan_raw_response,
                "weight": float(normalized.get("weight", provider.weight)),
            })
        except asyncio.TimeoutError:
            provider_failures.append({"provider": provider.name, "error_type": "TimeoutError", "error": f"provider exceeded {PROVIDER_TIMEOUT_SECONDS}s"})
            logger.error("provider_scan_timeout", extra={"extra_data": {
                "provider": provider.name,
                "link_id": link["id"],
                "url": link["target_url"],
                "timeout_seconds": PROVIDER_TIMEOUT_SECONDS,
            }})
        except QuotaExhaustedError as e:
            provider_failures.append({"provider": provider.name, "error_type": type(e).__name__, "error": str(e)})
            logger.warning(f"Quota exhausted: {e}", extra={"extra_data": {"provider": provider.name}})
        except Exception as e:
            provider_failures.append({"provider": provider.name, "error_type": type(e).__name__, "error": str(e)})
            logger.error("provider_scan_error", extra={"extra_data": {
                "provider": provider.name,
                "link_id": link["id"],
                "url": link["target_url"],
                "error_type": type(e).__name__,
                "error": str(e),
            }})

    if not scans_payload:
        failure_count = link_failures.get(link["id"], 0) + 1
        link_failures[link["id"]] = failure_count
        logger.error("all_providers_failed_or_disabled", extra={"extra_data": {
            "link_id": link["id"],
            "url": link["target_url"],
            "failure_count": failure_count,
            "max_attempts": MAX_LINK_SCAN_ATTEMPTS,
            "provider_failures": provider_failures,
        }})
        if failure_count < MAX_LINK_SCAN_ATTEMPTS:
            return

        payload = _build_problem_link_payload(link, failure_count, "all_providers_failed_or_timed_out")
        logger.warning("problem_link_fallback_payload_ready", extra={"extra_data": {
            "link_id": link["id"],
            "failure_count": failure_count,
            "payload": payload,
            "provider_failures": provider_failures,
        }})
        try:
            await api.post_scan_result(session, link["id"], payload)
            link_failures.pop(link["id"], None)
            logger.warning("problem_link_marked_warning", extra={"extra_data": {
                "link_id": link["id"],
                "score": payload["aggregate_score"],
                "status": payload["status"],
                "failure_count": failure_count,
            }})
        except Exception as e:
            logger.error("problem_link_fallback_post_failed", extra={"extra_data": {
                "link_id": link["id"],
                "error_type": type(e).__name__,
                "error": str(e),
            }})
        return

    agg_score = round(aggregate_score(aggregation_inputs), 4)
    status = map_status(agg_score)


    payload: ScanResultPayload = {
        "aggregate_score": agg_score,
        "status": status,
        "scans": cast(List[ProviderScanPayload], scans_payload)
    }
    logger.debug("scan_payload_ready", extra={"extra_data": {
        "link_id": link["id"],
        "aggregate_score": agg_score,
        "status": status,
        "scans": scans_payload,
    }})

    try:
        await api.post_scan_result(session, link["id"], payload)
        link_failures.pop(link["id"], None)
        logger.info("scan_complete", extra={"extra_data": {
            "link_id": link["id"],
            "score": agg_score,
            "status": status,
            "providers": len(scans_payload),
            "provider_scores": [
                {
                    "provider": scan["provider"],
                    "raw_score": scan["raw_score"],
                }
                for scan in scans_payload
            ],
        }})
    except Exception as e:
        failure_count = link_failures.get(link["id"], 0) + 1
        link_failures[link["id"]] = failure_count
        logger.error("scan_result_post_failed", extra={"extra_data": {
            "link_id": link["id"],
            "url": link["target_url"],
            "error_type": type(e).__name__,
            "error": str(e),
            "failure_count": failure_count,
            "max_attempts": MAX_LINK_SCAN_ATTEMPTS,
            "aggregate_score": agg_score,
            "status": status,
            "payload": payload,
        }})
        if failure_count >= MAX_LINK_SCAN_ATTEMPTS:
            fallback_payload = _build_problem_link_payload(link, failure_count, "scan_result_post_failed")
            logger.warning("problem_link_post_failure_fallback_payload_ready", extra={"extra_data": {
                "link_id": link["id"],
                "failure_count": failure_count,
                "payload": fallback_payload,
            }})
            try:
                await api.post_scan_result(session, link["id"], fallback_payload)
                link_failures.pop(link["id"], None)
                logger.warning("problem_link_marked_warning", extra={"extra_data": {
                    "link_id": link["id"],
                    "score": fallback_payload["aggregate_score"],
                    "status": fallback_payload["status"],
                    "failure_count": failure_count,
                }})
            except Exception as fallback_error:
                logger.error("problem_link_post_failure_fallback_failed", extra={"extra_data": {
                    "link_id": link["id"],
                    "error_type": type(fallback_error).__name__,
                    "error": str(fallback_error),
                }})

async def process_with_sem(link: PendingLink, providers: List[ScanProvider], api: WorkerApi, session: aiohttp.ClientSession):
    async with sem:
        await scan_single_link(link, providers, api, session)

async def pull_loop(providers: List[ScanProvider], api: WorkerApi):
    global wait_ms

    async with aiohttp.ClientSession() as session:
        # Initial healthcheck + release stale
        try:
            await api.health(session)
            await api.release_stale(session)
            logger.info("Waechter initialized successfully")
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            if "401" in str(e):
                logger.error("Authentication failed (401). Check that WAECHTER_TOKEN is correct and WORKER_BASE_URL uses https://.")
                sys.exit(1)
            # Sleep and let the loop handle it

        while True:
            try:
                links = await api.get_pending(session, BATCH_SIZE)
                if not links:
                    wait_ms = min(wait_ms * 2, MAX_WAIT_MS)
                    await asyncio.sleep(wait_ms / 1000.0)
                    # Periodically release stale claims if we are idling
                    if wait_ms == MAX_WAIT_MS:
                        await api.release_stale(session)
                    continue

                wait_ms = MIN_WAIT_MS
                tasks = [process_with_sem(link, providers, api, session) for link in links]
                await asyncio.gather(*tasks)

            except Exception as e:
                logger.error(f"Loop error: {e}")
                if "401" in str(e):
                    logger.error("Authentication failed (401). Check that WAECHTER_TOKEN is correct and WORKER_BASE_URL uses https://.")
                    sys.exit(1)
                await asyncio.sleep(wait_ms / 1000.0)
