"""The fixed-window rate limiter.

Redis is not available under pytest (conftest points REDIS_URL at a closed
port), so these tests substitute a minimal in-memory stand-in that models the
two commands the limiter uses: INCR and EXPIRE.
"""

from __future__ import annotations

import pytest

from app.core import cache


class _FakePipeline:
    def __init__(self, store: _FakeRedis):
        self._store = store
        self._ops: list[tuple] = []

    def incr(self, key):
        self._ops.append(("incr", key))

    def expire(self, key, seconds):
        self._ops.append(("expire", key, seconds))

    async def execute(self):
        out = []
        for op in self._ops:
            if op[0] == "incr":
                self._store.counts[op[1]] = self._store.counts.get(op[1], 0) + 1
                out.append(self._store.counts[op[1]])
            else:
                self._store.ttl[op[1]] = op[2]
                out.append(True)
        return out


class _FakeRedis:
    def __init__(self):
        self.counts: dict[str, int] = {}
        self.ttl: dict[str, int] = {}

    def pipeline(self):
        return _FakePipeline(self)


@pytest.fixture
def fake_redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(cache, "_redis", fake)
    monkeypatch.setattr(cache.settings, "rate_limit_enabled", True)
    return fake


@pytest.fixture
def clock(monkeypatch):
    now = {"t": 1_000_000.0}
    monkeypatch.setattr(cache.time, "time", lambda: now["t"])
    return now


async def test_allows_up_to_the_limit_then_rejects(fake_redis, clock):
    results = [await cache.rate_limit("read:ip1.2.3.4", 3) for _ in range(4)]
    assert [allowed for allowed, _ in results] == [True, True, True, False]
    assert [remaining for _, remaining in results] == [2, 1, 0, 0]


async def test_steady_traffic_still_resets_at_the_window_boundary(fake_redis, clock):
    """The regression behind CI's 429 storms.

    A runner that trips the limit keeps retrying; every retry used to refresh
    the TTL on the single counter key, so the "minute" never ended while the
    runner stayed busy. The window number is now part of the key, so a client
    that is hammering the registry gets a fresh budget on the next boundary
    regardless of what it did in the previous one.
    """
    clock["t"] = 1_000_000.0  # some way into a window
    for _ in range(5):
        await cache.rate_limit("read:ip1.2.3.4", 2)  # over the limit, and retrying
    allowed, _ = await cache.rate_limit("read:ip1.2.3.4", 2)
    assert allowed is False

    clock["t"] = 1_000_020.0  # next 60 s boundary is at 1_000_020
    allowed, remaining = await cache.rate_limit("read:ip1.2.3.4", 2)
    assert allowed is True
    assert remaining == 1


async def test_keys_are_scoped_to_the_window(fake_redis, clock):
    clock["t"] = 1_000_000.0
    await cache.rate_limit("read:ip1.2.3.4", 10)
    clock["t"] = 1_000_020.0
    await cache.rate_limit("read:ip1.2.3.4", 10)
    assert sorted(fake_redis.counts) == [
        "rl:read:ip1.2.3.4:60:16666",
        "rl:read:ip1.2.3.4:60:16667",
    ]
    # The TTL outlives the window so a key never disappears mid-window, and
    # is short enough that stale windows do not pile up in Redis.
    assert set(fake_redis.ttl.values()) == {120}


async def test_separate_keys_do_not_share_a_budget(fake_redis, clock):
    for _ in range(3):
        await cache.rate_limit("read:ip10.0.0.1", 2)
    allowed, _ = await cache.rate_limit("read:ip10.0.0.2", 2)
    assert allowed is True


async def test_retry_after_counts_down_to_the_boundary(clock):
    clock["t"] = 1_000_000.0
    assert cache.rate_limit_retry_after() == 20
    clock["t"] = 1_000_019.5
    assert cache.rate_limit_retry_after() == 1
    clock["t"] = 1_000_020.0
    assert cache.rate_limit_retry_after() == 60


async def test_disabled_or_no_redis_is_a_no_op(monkeypatch):
    monkeypatch.setattr(cache, "_redis", None)
    assert await cache.rate_limit("read:ipx", 1) == (True, 1)
    monkeypatch.setattr(cache, "_redis", _FakeRedis())
    monkeypatch.setattr(cache.settings, "rate_limit_enabled", False)
    assert await cache.rate_limit("read:ipx", 1) == (True, 1)


async def test_redis_errors_fail_open(monkeypatch):
    class _Broken:
        def pipeline(self):
            raise ConnectionError("redis went away")

    monkeypatch.setattr(cache, "_redis", _Broken())
    monkeypatch.setattr(cache.settings, "rate_limit_enabled", True)
    assert await cache.rate_limit("read:ipx", 5) == (True, 5)
