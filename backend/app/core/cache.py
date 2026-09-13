"""Valkey/Redis-backed cache, distributed lock, and rate limiter.

Everything degrades to a no-op when the cache server is unavailable so a Redis outage
slows the registry down but never takes it offline.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
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
# Backoff between reconnect attempts when the cache is down.
_RECONNECT_INTERVAL = 30.0
_next_reconnect_at: float = 0.0


async def init_redis() -> aioredis.Redis | None:
    global _redis, _next_reconnect_at
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
        _next_reconnect_at = 0.0
        log.info("cache connected: %s", settings.redis_url)
    except Exception as exc:
        log.warning("cache unavailable, running degraded: %s", exc)
        _redis = None
        _next_reconnect_at = time.monotonic() + _RECONNECT_INTERVAL
    return _redis


async def ensure_redis() -> aioredis.Redis | None:
    """Reconnect if the cache was down at boot.

    The connection used to be made exactly once during startup. If the cache
    container came up a second later than the app -- an ordinary outcome after
    a host reboot, since `depends_on` only waits for the container, not for a
    usable socket -- the process ran for its whole life with no cache, no herd
    guard and, worst of all, no rate limiting, while the healthcheck stayed
    green.
    """
    global _next_reconnect_at
    if _redis is not None:
        return _redis
    now = time.monotonic()
    if now < _next_reconnect_at:
        return None
    _next_reconnect_at = now + _RECONNECT_INTERVAL
    return await init_redis()


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


# Release only our own lock. Deleting by key alone means a holder whose work
# outran the TTL deletes the *next* holder's lock on the way out -- with a
# 300 s artifact TTL and a slow upstream, that is a real window.
_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0
"""


class herd_guard:
    """Collapse concurrent cold-cache work for the same key.

    Local asyncio lock first (cheap, covers the common single-replica case),
    then an optional Redis lock so a multi-replica deployment doesn't stampede
    an upstream either.

    Yields whether the lock was actually taken. With ``wait=True`` (the
    default) that is always True by the time the body runs; with
    ``wait=False`` the body runs immediately and must check, which is what a
    singleton background job wants.
    """

    def __init__(self, key: str, ttl: int = 30, *, wait: bool = True):
        self.key = f"lock:{key}"
        self.ttl = ttl
        self.wait = wait
        self._token = secrets.token_hex(16).encode()
        self._local = _local_locks.setdefault(self.key, asyncio.Lock())
        self._held_remote = False
        self._held_local = False

    async def __aenter__(self) -> bool:
        if self.wait:
            await self._local.acquire()
            self._held_local = True
        else:
            self._held_local = not self._local.locked()
            if self._held_local:
                await self._local.acquire()
            else:
                return False

        if _redis is None:
            return True
        try:
            attempts = int(self.ttl * 10) if self.wait else 1
            for _ in range(max(1, attempts)):
                if await _redis.set(self.key, self._token, nx=True, ex=self.ttl):
                    self._held_remote = True
                    return True
                if not self.wait:
                    return False
                await asyncio.sleep(0.1)
        except Exception:
            # Redis is unreachable: the process-local lock is the whole guard.
            return True
        # Waited out the TTL without getting it. Proceed rather than hang; the
        # cost is a duplicated upstream fetch, not a stuck request.
        log.warning("herd guard %s not acquired within its TTL; proceeding", self.key)
        return True

    async def __aexit__(self, *exc) -> None:
        if self._held_remote and _redis is not None:
            with contextlib.suppress(Exception):
                await _redis.eval(_RELEASE_SCRIPT, 1, self.key, self._token)
        if self._held_local:
            self._local.release()
        # One Lock per package name and per file id, kept for the life of the
        # process, is a slow leak on a registry that sees hundreds of thousands
        # of names. Nothing is waiting on an unlocked lock, so drop it.
        if not self._local.locked():
            _local_locks.pop(self.key, None)


def rate_limit_retry_after(window: int = 60) -> int:
    """Seconds until the current fixed window rolls over (at least 1)."""
    return max(1, window - int(time.time()) % window)


# Fallback counters for when the cache is unreachable. Bounded, per-process
# and approximate -- worth having anyway, because failing open on the *login*
# bucket turns a cache outage into an open door for password guessing.
_local_counters: dict[tuple[str, int], int] = {}
_local_counter_window: int = 0


def _local_rate_limit(key: str, limit: int, window: int) -> tuple[bool, int]:
    global _local_counter_window
    bucket = int(time.time()) // window
    if bucket != _local_counter_window:
        _local_counters.clear()
        _local_counter_window = bucket
    if len(_local_counters) > 100_000:
        _local_counters.clear()
    count = _local_counters.get((key, bucket), 0) + 1
    _local_counters[(key, bucket)] = count
    return count <= limit, max(0, limit - count)


async def rate_limit(
    key: str, limit: int, window: int = 60, *, fail_closed: bool = False
) -> tuple[bool, int]:
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
    if not settings.rate_limit_enabled or limit <= 0:
        return True, limit
    client = await ensure_redis()
    if client is None:
        return _local_rate_limit(key, limit, window) if fail_closed else (True, limit)
    try:
        bucket = int(time.time()) // window
        rkey = f"rl:{key}:{window}:{bucket}"
        pipe = client.pipeline()
        pipe.incr(rkey)
        pipe.expire(rkey, window * 2)
        count, _ = await pipe.execute()
        return int(count) <= limit, max(0, limit - int(count))
    except Exception:
        return _local_rate_limit(key, limit, window) if fail_closed else (True, limit)
