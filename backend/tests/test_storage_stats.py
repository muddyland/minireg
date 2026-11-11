"""The storage page and health check must not walk the blob store.

Both used to stat every cached file on every request, which on a large store
took the dashboard and the storage page tens of seconds. The walk now
happens once an hour, in the orphan sweep, and the page shows its result.
"""

from __future__ import annotations

import os

from app.services import artifacts
from tests.test_integration import app_client, auth  # noqa: F401


async def test_neither_endpoint_walks_the_store(app_client, monkeypatch):  # noqa: F811
    def no_walk(*_args, **_kwargs):
        raise AssertionError("a request walked the blob store")

    monkeypatch.setattr(os, "walk", no_walk)
    health = await app_client.get("/api/health/detailed", headers=auth(app_client, "admin"))
    assert health.status_code == 200
    assert health.json()["checks"]["storage"]["disk_total"] > 0

    stats = await app_client.get("/api/admin/stats/storage", headers=auth(app_client, "admin"))
    assert stats.status_code == 200
    disk = stats.json()["disk"]
    assert disk["total"] > 0
    # Before the first sweep there is no measurement, and it says so.
    assert disk["measured_at"] is None
    assert disk["blob_files_on_disk"] is None


async def test_the_hourly_sweep_records_what_is_on_disk(app_client):  # noqa: F811
    from tests.test_integration import npm_publish_body

    published = await app_client.put(
        "/npm/test-pkg", json=npm_publish_body(), headers=auth(app_client)
    )
    assert published.status_code in (200, 201)
    await artifacts.sweep_orphan_files()

    stats = await app_client.get("/api/admin/stats/storage", headers=auth(app_client, "admin"))
    disk = stats.json()["disk"]
    assert disk["measured_at"] is not None
    assert disk["blob_files_on_disk"] == 1
    assert disk["blob_bytes_on_disk"] == stats.json()["blobs"]["physical_bytes"]
