"""Valkey/Redis-backed cache, distributed lock, and rate limiter.

Everything degrades to a no-op when the cache server is unavailable so a Redis outage
slows the registry down but never takes it offline.

Outages are handled by a small circuit breaker. The first command that fails
trips it, and for a short, growing backoff every cache call returns its
"no cache" answer at once instead of paying the socket timeout again -- a
request makes several cache calls, and at two seconds each an outage used to
cost seconds per request. When the backoff lapses the next call tries the
server again, so recovery needs no restart.
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
# collapse into one upstream fetch even before Redis is consulted. Each entry
# is [lock, users]: the number of herd_guards holding or queued on the lock,
# so it is dropped only when nobody can still be waiting on it.
_local_locks: dict[str, list] = {}
# Circuit breaker. The backoff doubles from the minimum to the maximum while
# the server stays down, and resets on the first success.
_BREAKER_MIN = 2.0
_BREAKER_MAX = 30.0
_breaker_backoff: float = 0.0
_down_until: float = 0.0
# The client the breaker tripped on. Swapping the client (a reconnect, or a
# test substituting a fake) clears the breaker.
_tripped_client: object | None = None


def _trip(exc: BaseException | None = None) -> None:
    """Open the breaker after a failed cache command or connect."""
    global _breaker_backoff, _down_until, _tripped_client
    first = _breaker_backoff == 0.0
    _breaker_backoff = min(max(_breaker_backoff * 2, _BREAKER_MIN), _BREAKER_MAX)
    _down_until = time.monotonic() + _breaker_backoff
    _tripped_client = _redis
    if first:
        log.warning("cache unreachable; skipping it for %.0fs at a time: %s", _breaker_backoff, exc)


def _healthy() -> None:
    global _breaker_backoff, _down_until, _tripped_client
    if _breaker_backoff:
        log.info("cache reachable again")
        _breaker_backoff = 0.0
        _down_until = 0.0
        _tripped_client = None


def _tripped() -> bool:
    return _tripped_client is _redis and time.monotonic() < _down_until


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
        _healthy()
        log.info("cache connected: %s", settings.redis_url)
    except Exception as exc:
        log.warning("cache unavailable, running degraded: %s", exc)
        _redis = None
        _trip(exc)
    return _redis


async def ensure_redis() -> aioredis.Redis | None:
    """The cache client, or None while it is unreachable.

    Reconnects if the cache was down at boot: the connection used to be made
    exactly once during startup, so a cache container that came up a second
    after the app left the process with no cache, no herd guard and no rate
    limiting for its whole life while the healthcheck stayed green.

    While the breaker is open this returns None without touching the network;
    once it lapses the next caller makes one attempt.
    """
    if _redis is not None:
        return None if _tripped() else _redis
    if time.monotonic() < _down_until:
        return None
    return await init_redis()


async def close_redis() -> None:
    global _redis
    if _redis is not None:
        await _redis.aclose()
    _redis = None


def redis_client() -> aioredis.Redis | None:
    """The client, or None while it is down or the breaker is open.

    Synchronous, so it never reconnects; the async helpers below do.
    """
    if _redis is None or _tripped():
        return None
    return _redis


async def cache_get_json(key: str) -> Any | None:
    client = await ensure_redis()
    if client is None:
        return None
    try:
        raw = await client.get(key)
    except Exception as exc:
        _trip(exc)
        return None
    _healthy()
    if raw is None:
        return None
    try:
        return orjson.loads(raw)
    except orjson.JSONDecodeError:
        return None


async def cache_set_json(key: str, value: Any, ttl: int) -> None:
    client = await ensure_redis()
    if client is None:
        return
    try:
        await client.set(key, orjson.dumps(value), ex=ttl)
    except Exception as exc:
        _trip(exc)


async def cache_delete(*keys: str) -> None:
    if not keys:
        return
    client = await ensure_redis()
    if client is None:
        return
    try:
        await client.delete(*keys)
    except Exception as exc:
        _trip(exc)


async def cache_delete_prefix(prefix: str) -> None:
    """Drop every key under a prefix. Uses SCAN so it never blocks Redis."""
    client = await ensure_redis()
    if client is None:
        return
    try:
        cursor = 0
        while True:
            cursor, keys = await client.scan(cursor=cursor, match=f"{prefix}*", count=500)
            if keys:
                await client.delete(*keys)
            if cursor == 0:
                break
    except Exception as exc:
        _trip(exc)


# Release only our own lock. Deleting by key alone means a holder whose work
# outran the TTL deletes the *next* holder's lock on the way out.
_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0
"""
_RENEW_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('expire', KEYS[1], ARGV[2])
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

    The Redis lock has one fixed TTL and is never renewed, so this suits work
    reliably shorter than ``ttl``. Work that can run long (a download, a
    housekeeping pass) takes a :class:`Lease` instead.
    """

    def __init__(self, key: str, ttl: int = 30, *, wait: bool = True):
        self.key = f"lock:{key}"
        self.ttl = ttl
        self.wait = wait
        self._token = secrets.token_hex(16).encode()
        self._entry: list | None = None
        self._held_remote = False
        self._held_local = False

    def _enter_local(self) -> asyncio.Lock:
        # Looked up on entry, not in __init__: an instance built earlier could
        # otherwise carry a lock that has since been dropped from the map.
        entry = _local_locks.get(self.key)
        if entry is None:
            entry = _local_locks[self.key] = [asyncio.Lock(), 0]
        entry[1] += 1
        self._entry = entry
        return entry[0]

    def _leave_local(self) -> None:
        entry, self._entry = self._entry, None
        if entry is None:
            return
        entry[1] -= 1
        # One lock per package name and per file id, kept for the life of the
        # process, is a slow leak; drop it once no guard holds or awaits it.
        # Checking `not locked()` instead was wrong: that is true in the gap
        # between a release and the woken waiter re-acquiring, so a third
        # request got a fresh lock and ran alongside the waiter.
        if entry[1] <= 0 and _local_locks.get(self.key) is entry:
            del _local_locks[self.key]

    async def __aenter__(self) -> bool:
        lock = self._enter_local()
        try:
            if not self.wait and lock.locked():
                return False
            await lock.acquire()
            self._held_local = True
        except BaseException:
            self._leave_local()
            raise

        client = await ensure_redis()
        if client is None:
            return True
        try:
            attempts = int(self.ttl * 10) if self.wait else 1
            for _ in range(max(1, attempts)):
                if await client.set(self.key, self._token, nx=True, ex=self.ttl):
                    self._held_remote = True
                    return True
                if not self.wait:
                    return False
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            await self.__aexit__(None, None, None)
            raise
        except Exception as exc:
            # Redis is unreachable: the process-local lock is the whole guard.
            _trip(exc)
            return True
        # Waited out the TTL without getting it. Proceed rather than hang; the
        # cost is a duplicated upstream fetch, not a stuck request.
        log.warning("herd guard %s not acquired within its TTL; proceeding", self.key)
        return True

    async def __aexit__(self, *exc) -> None:
        if self._held_remote:
            self._held_remote = False
            client = redis_client()
            if client is not None:
                with contextlib.suppress(Exception):
                    await client.eval(_RELEASE_SCRIPT, 1, self.key, self._token)
        if self._held_local and self._entry is not None:
            self._held_local = False
            self._entry[0].release()
        self._leave_local()


class Lease:
    """A cross-replica lease, renewed in the background for as long as it is held.

    ``herd_guard`` takes one fixed TTL, so work that outran it -- a 900 s
    download under a 300 s lock, a housekeeping pass under an hour's lock --
    let a second replica start the same work half way through. A lease has a
    short TTL and a task that extends it every ``ttl / 3`` while the holder is
    alive; if the holder's process dies the lease lapses within ``ttl``.

    With no reachable cache it always succeeds: the caller's in-process
    single flight is then the whole guard, as with ``herd_guard``.
    """

    def __init__(self, key: str, ttl: int = 30) -> None:
        self.key = f"lock:{key}"
        self.ttl = ttl
        self.token = secrets.token_hex(16).encode()
        self.held = False
        self._remote = False
        self._renewer: asyncio.Task | None = None

    async def acquire(self) -> bool:
        client = await ensure_redis()
        if client is None:
            self.held = True
            return True
        try:
            got = bool(await client.set(self.key, self.token, nx=True, ex=self.ttl))
        except Exception as exc:
            _trip(exc)
            self.held = True
            return True
        self.held = self._remote = got
        if got:
            self._renewer = asyncio.create_task(self._renew_loop())
        return got

    async def renew(self) -> bool:
        """Extend the lease now. False if it was lost to someone else."""
        client = redis_client()
        if client is None or not self._remote:
            return True
        try:
            return bool(await client.eval(_RENEW_SCRIPT, 1, self.key, self.token, self.ttl))
        except Exception as exc:
            _trip(exc)
            return True

    async def _renew_loop(self) -> None:
        while True:
            await asyncio.sleep(max(0.05, self.ttl / 3))
            if not await self.renew():
                log.warning("lease %s was lost while held", self.key)
                return

    async def release(self) -> None:
        renewer, self._renewer = self._renewer, None
        if renewer is not None:
            renewer.cancel()
            with contextlib.suppress(BaseException):
                await renewer
        if self._remote:
            client = redis_client()
            if client is not None:
                with contextlib.suppress(Exception):
                    await client.eval(_RELEASE_SCRIPT, 1, self.key, self.token)
        self.held = self._remote = False


async def lease_is_free(key: str) -> bool:
    """Whether nobody holds ``Lease(key)`` right now. True with no cache."""
    client = await ensure_redis()
    if client is None:
        return True
    try:
        return not await client.exists(f"lock:{key}")
    except Exception as exc:
        _trip(exc)
        return True


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


async def cache_get_bytes(key: str) -> bytes | None:
    """Raw cached bytes, for callers that serve them as-is.

    A document stored serialised and returned serialised is never parsed back
    into Python objects on a hit, which for a rendered packument was most of
    the cost of serving it.
    """
    if _redis is None:
        return None
    try:
        raw = await _redis.get(key)
    except Exception:
        return None
    return bytes(raw) if raw is not None else None


async def cache_set_bytes(key: str, value: bytes, ttl: int) -> None:
    if _redis is None:
        return
    with contextlib.suppress(Exception):
        await _redis.set(key, value, ex=ttl)
