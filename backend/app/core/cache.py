"""Valkey/Redis-backed cache, distributed lock, and rate limiter.

Everything degrades to a no-op when the cache server is unavailable so a Redis outage
slows the registry down but never takes it offline.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Any

import orjson
import redis.asyncio as aioredis

from ..config import settings

log = logging.getLogger(__name__)

_redis: aioredis.Redis | None = None
# Process-local guard so N concurrent requests for the same cold packument
# collapse into one upstream fetch even before Redis is consulted.
_local_locks: dict[str, asyncio.Lock] = {}


async def init_redis() -> aioredis.Redis | None:
    global _redis
    try:
        _redis = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=False,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        )
        await _redis.ping()
        log.info("redis connected: %s", settings.redis_url)
    except Exception as exc:
        log.warning("redis unavailable, running without cache: %s", exc)
        _redis = None
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis is not None:
        await _redis.aclose()
    _redis = None


def redis_client() -> aioredis.Redis | None:
    return _redis


async def cache_get_json(key: str) -> Any | None:
    if _redis is None:
        return None
    try:
        raw = await _redis.get(key)
    except Exception:
        return None
    if raw is None:
        return None
    try:
        return orjson.loads(raw)
    except orjson.JSONDecodeError:
        return None


async def cache_set_json(key: str, value: Any, ttl: int) -> None:
    if _redis is None:
        return
    with contextlib.suppress(Exception):
        await _redis.set(key, orjson.dumps(value), ex=ttl)


async def cache_delete(*keys: str) -> None:
    if _redis is None or not keys:
        return
    with contextlib.suppress(Exception):
        await _redis.delete(*keys)


async def cache_delete_prefix(prefix: str) -> None:
    """Drop every key under a prefix. Uses SCAN so it never blocks Redis."""
    if _redis is None:
        return
    with contextlib.suppress(Exception):
        cursor = 0
        while True:
            cursor, keys = await _redis.scan(cursor=cursor, match=f"{prefix}*", count=500)
            if keys:
                await _redis.delete(*keys)
            if cursor == 0:
                break


class herd_guard:
    """Collapse concurrent cold-cache work for the same key.

    Local asyncio lock first (cheap, covers the common single-replica case),
    then an optional Redis lock so a multi-replica deployment doesn't stampede
    an upstream either.
    """

    def __init__(self, key: str, ttl: int = 30):
        self.key = f"lock:{key}"
        self.ttl = ttl
        self._local = _local_locks.setdefault(self.key, asyncio.Lock())
        self._held_remote = False

    async def __aenter__(self) -> herd_guard:
        await self._local.acquire()
        if _redis is not None:
            try:
                for _ in range(int(self.ttl * 10)):
                    if await _redis.set(self.key, b"1", nx=True, ex=self.ttl):
                        self._held_remote = True
                        return self
                    await asyncio.sleep(0.1)
            except Exception:
                pass
        return self

    async def __aexit__(self, *exc) -> None:
        if self._held_remote and _redis is not None:
            with contextlib.suppress(Exception):
                await _redis.delete(self.key)
        self._local.release()


def rate_limit_retry_after(window: int = 60) -> int:
    """Seconds until the current fixed window rolls over (at least 1)."""
    return max(1, window - int(time.time()) % window)


async def rate_limit(key: str, limit: int, window: int = 60) -> tuple[bool, int]:
    """Fixed-window counter. Returns (allowed, remaining).

    The window number is part of the key, so the count genuinely resets every
    ``window`` seconds no matter how steady the traffic is. Refreshing the TTL
    on every hit is then harmless -- it only ever touches the current window's
    key -- and it keeps the key alive even if a crash lands between INCR and
    EXPIRE on the first hit. (An earlier version keyed on ``key`` alone and
    refreshed the TTL per request, which made the "window" end only after 60 s
    of *silence*: a busy CI runner that tripped the limit once stayed locked
    out for as long as it kept retrying.)
    """
    if _redis is None or not settings.rate_limit_enabled or limit <= 0:
        return True, limit
    try:
        bucket = int(time.time()) // window
        rkey = f"rl:{key}:{window}:{bucket}"
        pipe = _redis.pipeline()
        pipe.incr(rkey)
        pipe.expire(rkey, window * 2)
        count, _ = await pipe.execute()
        return int(count) <= limit, max(0, limit - int(count))
    except Exception:
        return True, limit
