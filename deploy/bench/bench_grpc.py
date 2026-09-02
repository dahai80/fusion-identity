from __future__ import annotations

import argparse
import asyncio
import logging
import time

from fusion_identity.client.identity_client import IdentityClient

logger = logging.getLogger("bench")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


async def warmup(client: IdentityClient, api_key: str, rounds: int = 50) -> None:
    for _ in range(rounds):
        await client.authorize_and_acquire(
            api_key=api_key, target_module="bench", target_model="bench", request_id="warm"
        )


async def bench(client: IdentityClient, api_key: str, total: int, concurrency: int) -> dict:
    sem = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    allowed = 0
    denied = 0

    async def one(i: int) -> None:
        nonlocal allowed, denied
        t0 = time.perf_counter()
        async with sem:
            resp = await client.authorize_and_acquire(
                api_key=api_key,
                target_module="bench",
                target_model="bench",
                request_id=f"b{i}",
            )
        latencies.append((time.perf_counter() - t0) * 1000)
        if resp.is_allowed:
            allowed += 1
            await client.release_lease(resp.lease_id, resp.tenant_context.tenant_id, reason="bench")
        else:
            denied += 1

    start = time.perf_counter()
    await asyncio.gather(*(one(i) for i in range(total)))
    elapsed = time.perf_counter() - start

    latencies.sort()
    qps = total / elapsed if elapsed > 0 else 0
    return {
        "total": total,
        "concurrency": concurrency,
        "elapsed_s": round(elapsed, 3),
        "qps": round(qps, 1),
        "allowed": allowed,
        "denied": denied,
        "p50_ms": round(latencies[len(latencies) // 2], 3),
        "p95_ms": round(latencies[int(len(latencies) * 0.95)], 3),
        "p99_ms": round(latencies[int(len(latencies) * 0.99)], 3),
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="fusion-identity gRPC bench")
    parser.add_argument("--target", default="127.0.0.1:50051")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--total", type=int, default=5000)
    parser.add_argument("--concurrency", type=int, default=50)
    args = parser.parse_args()

    client = IdentityClient(target=args.target, deadline_ms=2000)
    await client.connect()
    try:
        logger.info("warmup...")
        await warmup(client, args.api_key)
        result = await bench(client, args.api_key, args.total, args.concurrency)
        logger.info("bench result: %s", result)
        p99_ok = result["p99_ms"] < 2000
        qps_ok = result["qps"] > 5000
        logger.info("P99<2ms: %s | QPS>5000: %s", p99_ok, qps_ok)
        if not (p99_ok and qps_ok):
            logger.warning("perf target NOT met")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
