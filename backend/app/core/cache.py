"""Redis-backed cache, distributed lock, and rate limiter.

Everything degrades to a no-op when Redis is unavailable so a Redis outage
slows the registry down but never takes it offline.
"""

from __future__ import annotations

import asyncio
import logging
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
    try:
        await _redis.set(key, orjson.dumps(value), ex=ttl)
    except Exception:
        pass


async def cache_delete(*keys: str) -> None:
    if _redis is None or not keys:
        return
    try:
        await _redis.delete(*keys)
    except Exception:
        pass


async def cache_delete_prefix(prefix: str) -> None:
    """Drop every key under a prefix. Uses SCAN so it never blocks Redis."""
    if _redis is None:
        return
    try:
        cursor = 0
        while True:
            cursor, keys = await _redis.scan(cursor=cursor, match=f"{prefix}*", count=500)
            if keys:
                await _redis.delete(*keys)
            if cursor == 0:
                break
    except Exception:
        pass


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

    async def __aenter__(self) -> "herd_guard":
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
            try:
                await _redis.delete(self.key)
            except Exception:
                pass
        self._local.release()


async def rate_limit(key: str, limit: int, window: int = 60) -> tuple[bool, int]:
    """Fixed-window counter. Returns (allowed, remaining)."""
    if _redis is None or not settings.rate_limit_enabled or limit <= 0:
        return True, limit
    try:
        rkey = f"rl:{key}:{window}"
        pipe = _redis.pipeline()
        pipe.incr(rkey)
        pipe.expire(rkey, window)
        count, _ = await pipe.execute()
        return int(count) <= limit, max(0, limit - int(count))
    except Exception:
        return True, limit
