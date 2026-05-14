import os
import sys
import asyncio
import aiohttp
from typing import List
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

wait_ms = MIN_WAIT_MS
sem = asyncio.Semaphore(SCAN_CONCURRENCY)

async def scan_single_link(link: PendingLink, providers: List[ScanProvider], api: WorkerApi, session: aiohttp.ClientSession) -> None:
    scans_payload: List[ProviderScanPayload] = []

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
            res = await provider.scan(link["target_url"], session)
            raw_response = res.get("raw_response")
            logger.debug("provider_scan_result", extra={"extra_data": {
                "provider": provider.name,
                "link_id": link["id"],
                "raw_score": res["raw_score"],
                "has_raw_response": raw_response is not None,
                "raw_response_preview": str(raw_response)[:300] if raw_response is not None else None,
                "weight": provider.weight,
            }})
            scans_payload.append({
                "provider": provider.name,
                "raw_score": res["raw_score"],
                "raw_response": res.get("raw_response") if res["raw_score"] >= 0.3 else None,
                "weight": provider.weight # passed for aggregation only, not part of payload schema
            })
        except QuotaExhaustedError as e:
            logger.warning(f"Quota exhausted: {e}", extra={"extra_data": {"provider": provider.name}})
        except Exception as e:
            logger.error(f"Provider error: {str(e)}", extra={"extra_data": {"provider": provider.name, "link_id": link["id"]}})

    if not scans_payload:
        logger.error("All providers failed or disabled", extra={"extra_data": {"link_id": link["id"]}})
        return

    agg_score = aggregate_score(scans_payload)
    status = map_status(agg_score)

    # Clean up weights before sending
    for s in scans_payload:
        s.pop("weight", None)

    payload: ScanResultPayload = {
        "aggregate_score": agg_score,
        "status": status,
        "scans": scans_payload
    }
    logger.debug("scan_payload_ready", extra={"extra_data": {
        "link_id": link["id"],
        "aggregate_score": agg_score,
        "status": status,
        "scans": scans_payload,
    }})

    try:
        await api.post_scan_result(session, link["id"], payload)
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
        logger.error(f"Failed to post result for {link['id']}: {str(e)}")

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
                    sys.exit(1)
                await asyncio.sleep(wait_ms / 1000.0)

