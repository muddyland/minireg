"""The shipped compose file keeps the scanner away from the data services.

The Trivy sidecar unpacks untrusted image layers. It used to share one
bridge network with a password-less Valkey -- whose contents (rendered
packuments, policy rules and settings) the app serves and trusts verbatim --
and with a Postgres that fell back to the password ``minireg``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from app.core import cache

COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose() -> dict:
    if not COMPOSE.exists():
        pytest.skip("docker-compose.yml is not part of this checkout")
    return yaml.safe_load(COMPOSE.read_text())


def networks_of(service: dict) -> set[str]:
    nets = service.get("networks") or ["default"]
    return set(nets if isinstance(nets, list) else nets.keys())


class TestNetworkIsolation:
    def test_scanner_shares_no_network_with_postgres_or_valkey(self, compose):
        services = compose["services"]
        data = networks_of(services["postgres"]) | networks_of(services["redis"])
        assert not networks_of(services["scanner"]) & data

    def test_scanner_can_still_reach_minireg(self, compose):
        services = compose["services"]
        assert networks_of(services["scanner"]) & networks_of(services["minireg"])
        assert services["scanner"]["environment"]["MINIREG_URL"] == "http://minireg:8000"

    def test_data_services_sit_on_internal_networks_only(self, compose):
        declared = compose["networks"]
        for name in ("postgres", "redis"):
            for net in networks_of(compose["services"][name]):
                assert declared[net].get("internal") is True, (name, net)


class TestNoDefaultCredentials:
    def test_postgres_password_is_required(self, compose):
        env = compose["services"]["postgres"]["environment"]
        assert env["POSTGRES_PASSWORD"].startswith("${POSTGRES_PASSWORD:?")
        url = compose["services"]["minireg"]["environment"]["DATABASE_URL"]
        assert "${POSTGRES_PASSWORD:?" in url
        assert ":-minireg}@" not in url

    def test_valkey_requires_a_password_and_the_app_sends_it(self, compose):
        command = compose["services"]["redis"]["command"]
        index = command.index("--requirepass")
        assert command[index + 1].startswith("${REDIS_PASSWORD:?")
        url = compose["services"]["minireg"]["environment"]["REDIS_URL"]
        assert url.startswith("redis://:${REDIS_PASSWORD:?")
        # The healthcheck authenticates too, or Valkey never turns healthy.
        assert "REDISCLI_AUTH" in " ".join(compose["services"]["redis"]["healthcheck"]["test"])


class TestRedisUrlIsNotLogged:
    @pytest.mark.parametrize(
        "url,shown",
        [
            ("redis://:hunter2@redis:6379/0", "redis://:***@redis:6379/0"),
            ("redis://user:hunter2@redis/1", "redis://user:***@redis/1"),
            ("rediss://:hunter2@[::1]:6380/0", "rediss://:***@[::1]:6380/0"),
            ("redis://redis:6379/0", "redis://redis:6379/0"),
        ],
    )
    def test_redact_url(self, url, shown):
        assert cache.redact_url(url) == shown

    async def test_connect_line_carries_no_password(self, monkeypatch, caplog):
        class Fake:
            async def ping(self):
                return True

        monkeypatch.setattr(cache.settings, "redis_url", "redis://:hunter2@redis:6379/0")
        monkeypatch.setattr(cache.aioredis, "from_url", lambda *a, **k: Fake())
        monkeypatch.setattr(cache, "_redis", None)
        with caplog.at_level(logging.INFO, logger=cache.log.name):
            await cache.init_redis()
        assert "cache connected" in caplog.text
        assert "hunter2" not in caplog.text
