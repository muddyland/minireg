"""Cargo sparse-index conformance: naming, provider parsing, rendering, proxying.

The index format is what cargo resolves against *before* it downloads
anything, so a field we drop or reshape does not degrade metadata -- it changes
which versions the resolver picks. Most of what is asserted here is
pass-through fidelity for that reason.
"""

import hashlib
from datetime import UTC, datetime

import httpx
import orjson
import pytest
import pytest_asyncio
import respx
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.core.naming import (
    cargo_crate_filename,
    cargo_index_path,
    is_valid_cargo_name,
    normalize_cargo_name,
    sort_versions_for,
)
from app.models import Ecosystem, PackageRule, RuleAction, Upstream, UpstreamKind
from app.services import cargo_render
from app.services.policy import invalidate_policy_cache
from app.services.storage import BlobStore, set_store
from app.upstreams.base import UpstreamNotFound
from app.upstreams.cargo_provider import CargoProvider

from .conftest import add_file, make_package


def make_upstream(**kwargs):
    defaults = {
        "id": 1,
        "name": "mock-cargo",
        "ecosystem": Ecosystem.cargo,
        "kind": UpstreamKind.cargo,
        "url": "https://index.upstream.test",
        "tier": 1,
        "priority": 100,
        "enabled": True,
        "auth_type": "none",
        "credential_enc": None,
        "timeout_seconds": 5.0,
        "verify_ssl": True,
        "healthy": True,
        "consecutive_failures": 0,
        "extra": {},
    }
    defaults.update(kwargs)
    return Upstream(**defaults)


# --------------------------------------------------------------------------- #
# Naming
# --------------------------------------------------------------------------- #
class TestCargoNaming:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("a", "1/a"),
            ("ab", "2/ab"),
            ("abc", "3/a/abc"),
            ("serde", "se/rd/serde"),
            ("serde_json", "se/rd/serde_json"),
            ("async-trait", "as/yn/async-trait"),
        ],
    )
    def test_index_shard_layout(self, name, expected):
        """Clients compute this path themselves, so it has to match exactly."""
        assert cargo_index_path(name) == expected

    def test_index_path_is_lowercased(self):
        assert cargo_index_path("Serde") == "se/rd/serde"

    def test_hyphen_and_underscore_are_distinct(self):
        """crates.io folds them when deciding whether a *new* name collides, but
        the index is keyed on the name as spelled -- folding here would resolve
        `foo_bar` to whichever of the pair we happened to cache first."""
        assert normalize_cargo_name("foo_bar") != normalize_cargo_name("foo-bar")
        assert cargo_index_path("foo_bar") != cargo_index_path("foo-bar")

    @pytest.mark.parametrize("name", ["serde", "serde_json", "async-trait", "x1"])
    def test_accepts_real_names(self, name):
        assert is_valid_cargo_name(name)

    @pytest.mark.parametrize("name", ["", "1foo", "foo bar", "foo/bar", "foo.bar", "x" * 65])
    def test_rejects_impossible_names(self, name):
        assert not is_valid_cargo_name(name)

    def test_artifact_filename(self):
        assert cargo_crate_filename("async-trait", "0.1.77") == "async-trait-0.1.77.crate"
        assert cargo_crate_filename("serde", "1.0.0-beta.1") == "serde-1.0.0-beta.1.crate"

    def test_versions_sort_by_semver_not_pep440(self):
        """`1.0.0-beta.10` is not a PEP 440 version at all, so routing cargo
        through the PyPI sorter would drop it into the unparseable bucket and
        order it below every release."""
        ordered = sort_versions_for(
            "cargo", ["1.10.0", "1.9.0", "1.0.0-beta.2", "1.0.0-beta.10", "2.0.0"]
        )
        assert ordered == ["1.0.0-beta.2", "1.0.0-beta.10", "1.9.0", "1.10.0", "2.0.0"]


# --------------------------------------------------------------------------- #
# Provider
# --------------------------------------------------------------------------- #
INDEX_BODY = "\n".join(
    [
        orjson.dumps(
            {
                "name": "serde",
                "vers": "1.0.0",
                "deps": [],
                "cksum": "a" * 64,
                "features": {},
                "yanked": False,
            }
        ).decode(),
        orjson.dumps(
            {
                "name": "serde",
                "vers": "1.0.1",
                "deps": [
                    {
                        "name": "serde_derive",
                        "req": "^1.0",
                        "features": [],
                        "optional": True,
                        "default_features": True,
                        "target": None,
                        "kind": "normal",
                    }
                ],
                "cksum": "b" * 64,
                "features": {"derive": ["serde_derive"]},
                "yanked": True,
                "rust_version": "1.31",
                "pubtime": "2024-05-06T12:00:00Z",
            }
        ).decode(),
    ]
)


class TestCargoProvider:
    @respx.mock
    async def test_parses_the_index_into_versions(self):
        respx.get("https://index.upstream.test/config.json").mock(
            return_value=httpx.Response(200, json={"dl": "https://static.upstream.test/api/v1/crates"})
        )
        respx.get("https://index.upstream.test/se/rd/serde").mock(
            return_value=httpx.Response(200, text=INDEX_BODY)
        )

        package = await CargoProvider(make_upstream()).fetch_package("serde")
        assert package.name == "serde"
        assert [v.version for v in package.versions] == ["1.0.0", "1.0.1"]

        latest = package.versions[1]
        assert latest.yanked is True
        # The dependency and feature graph must survive verbatim: cargo resolves
        # against it, so a dropped `optional` flag changes the build.
        assert latest.metadata["deps"][0]["req"] == "^1.0"
        assert latest.metadata["deps"][0]["optional"] is True
        assert latest.metadata["features"] == {"derive": ["serde_derive"]}
        assert latest.metadata["rust_version"] == "1.31"

    @respx.mock
    async def test_pubtime_becomes_the_publication_date(self):
        """crates.io stamps entries with `pubtime`. It is an extension rather
        than part of the sparse-index spec, so a registry without it is not
        malformed -- the version just has no known date."""
        respx.get("https://index.upstream.test/config.json").mock(
            return_value=httpx.Response(200, json={"dl": "https://dl.test"})
        )
        respx.get("https://index.upstream.test/se/rd/serde").mock(
            return_value=httpx.Response(200, text=INDEX_BODY)
        )
        package = await CargoProvider(make_upstream()).fetch_package("serde")
        assert package.versions[1].published_at == datetime(2024, 5, 6, 12, 0, tzinfo=UTC)
        assert package.versions[0].published_at is None

    @respx.mock
    async def test_file_carries_the_checksum_and_download_url(self):
        respx.get("https://index.upstream.test/config.json").mock(
            return_value=httpx.Response(200, json={"dl": "https://static.upstream.test/api/v1/crates"})
        )
        respx.get("https://index.upstream.test/se/rd/serde").mock(
            return_value=httpx.Response(200, text=INDEX_BODY)
        )

        package = await CargoProvider(make_upstream()).fetch_package("serde")
        file_row = package.versions[0].files[0]
        assert file_row.filename == "serde-1.0.0.crate"
        assert file_row.hashes["sha256"] == "a" * 64
        # No markers in the template, so cargo's documented fallback applies.
        assert file_row.url == "https://static.upstream.test/api/v1/crates/serde/1.0.0/download"

    @pytest.mark.parametrize(
        "template,expected",
        [
            (
                "https://dl.test/api/v1/crates",
                "https://dl.test/api/v1/crates/serde/1.0.0/download",
            ),
            (
                "https://dl.test/{crate}/{version}/dl",
                "https://dl.test/serde/1.0.0/dl",
            ),
            (
                "https://dl.test/{prefix}/{crate}-{version}.crate",
                "https://dl.test/se/rd/serde-1.0.0.crate",
            ),
            (
                "https://dl.test/{lowerprefix}/{crate}/{sha256-checksum}",
                "https://dl.test/se/rd/serde/" + "a" * 64,
            ),
        ],
    )
    def test_dl_template_substitution(self, template, expected):
        provider = CargoProvider(make_upstream())
        assert provider.download_url(template, "serde", "1.0.0", "a" * 64) == expected

    @respx.mock
    async def test_missing_crate_is_not_found(self):
        respx.get("https://index.upstream.test/se/rd/serde").mock(
            return_value=httpx.Response(404)
        )
        with pytest.raises(UpstreamNotFound):
            await CargoProvider(make_upstream()).fetch_package("serde")

    @respx.mock
    async def test_a_malformed_line_does_not_lose_the_crate(self):
        """The index is append-only; one bad record must not make every version
        of a crate unresolvable."""
        respx.get("https://index.upstream.test/config.json").mock(
            return_value=httpx.Response(200, json={"dl": "https://dl.test"})
        )
        body = INDEX_BODY.split("\n")[0] + "\n{not json at all\n" + INDEX_BODY.split("\n")[1]
        respx.get("https://index.upstream.test/se/rd/serde").mock(
            return_value=httpx.Response(200, text=body)
        )
        package = await CargoProvider(make_upstream()).fetch_package("serde")
        assert [v.version for v in package.versions] == ["1.0.0", "1.0.1"]

    @respx.mock
    async def test_missing_config_json_falls_back_to_the_conventional_path(self):
        respx.get("https://index.upstream.test/config.json").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://index.upstream.test/se/rd/serde").mock(
            return_value=httpx.Response(200, text=INDEX_BODY)
        )
        package = await CargoProvider(make_upstream()).fetch_package("serde")
        assert package.versions[0].files[0].url == (
            "https://index.upstream.test/serde/1.0.0/download"
        )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def cargo_package(versions=(("1.0.0", {}),), **kwargs):
    package = make_package(name="serde", ecosystem=Ecosystem.cargo, versions=versions, **kwargs)
    for version_row in package.versions:
        add_file(
            version_row,
            cargo_crate_filename("serde", version_row.version),
            sha256="c" * 64,
            content_type="application/x-tar",
        )
    return package


class TestCargoRender:
    def test_index_is_newline_delimited_json(self):
        package = cargo_package(versions=(("1.0.0", {}), ("1.0.1", {})))
        body = cargo_render.render_index(package)
        lines = body.strip().split("\n")
        assert len(lines) == 2
        assert [orjson.loads(line)["vers"] for line in lines] == ["1.0.0", "1.0.1"]

    def test_entries_are_ordered_by_semver(self):
        package = cargo_package(versions=(("1.10.0", {}), ("1.9.0", {}), ("1.0.0", {})))
        versions = [
            orjson.loads(line)["vers"] for line in cargo_render.render_index(package).strip().split("\n")
        ]
        assert versions == ["1.0.0", "1.9.0", "1.10.0"]

    def test_stored_index_entry_is_passed_through(self):
        stored = {
            "name": "serde",
            "vers": "1.0.0",
            "deps": [{"name": "libc", "req": "^0.2", "kind": "normal"}],
            "features": {"std": []},
            "links": None,
            "v": 2,
            "features2": {"derive": ["dep:serde_derive"]},
        }
        package = cargo_package(versions=(("1.0.0", stored),))
        entry = orjson.loads(cargo_render.render_index(package).strip())
        assert entry["deps"] == stored["deps"]
        assert entry["features"] == {"std": []}
        assert entry["features2"] == {"derive": ["dep:serde_derive"]}
        assert entry["v"] == 2

    def test_checksum_comes_from_the_stored_file(self):
        package = cargo_package()
        entry = orjson.loads(cargo_render.render_index(package).strip())
        assert entry["cksum"] == "c" * 64

    def test_deps_and_features_are_always_present(self):
        """Cargo treats a missing `deps` as a parse error, not as 'none'."""
        package = cargo_package(versions=(("1.0.0", {}),))
        entry = orjson.loads(cargo_render.render_index(package).strip())
        assert entry["deps"] == []
        assert entry["features"] == {}

    def test_a_blocked_version_is_marked_yanked(self):
        package = cargo_package(versions=(("1.0.0", {}), ("1.0.1", {})))
        body = cargo_render.render_index(package, blocked_versions={"1.0.1"})
        entries = {orjson.loads(line)["vers"]: orjson.loads(line) for line in body.strip().split("\n")}
        assert entries["1.0.0"]["yanked"] is False
        # The index has no other "do not select this" signal, and the download
        # route refuses it outright regardless.
        assert entries["1.0.1"]["yanked"] is True

    def test_config_json_omits_the_api_key(self):
        """Advertising `api` would tell cargo that publish, yank and search
        work here. They do not -- this is a read-only mirror."""
        config = cargo_render.render_config_json()
        assert config["dl"] == "http://registry.test/cargo/api/v1/crates"
        assert "api" not in config


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #
CRATE = b"pretend-this-is-a-gzipped-crate-tarball" * 10
CRATE_SHA256 = hashlib.sha256(CRATE).hexdigest()

PROXY_INDEX = "\n".join(
    [
        orjson.dumps(
            {
                "name": "leftpad",
                "vers": "1.0.0",
                "deps": [{"name": "libc", "req": "^0.2", "kind": "normal"}],
                "cksum": CRATE_SHA256,
                "features": {},
                "yanked": False,
            }
        ).decode(),
    ]
)


@pytest_asyncio.fixture
async def cargo_client(tmp_path):
    from app.main import app

    db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'cargo.db'}")
    await db_module.create_schema()

    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)

    async with db_module.session_scope() as session:
        session.add(
            Upstream(
                name="mock-cargo",
                ecosystem=Ecosystem.cargo,
                kind=UpstreamKind.cargo,
                url="https://index.upstream.test",
                tier=1,
                enabled=True,
            )
        )
    await invalidate_policy_cache()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://registry.test"
    ) as client:
        yield client

    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]


def mock_cargo_upstream():
    respx.get("https://index.upstream.test/config.json").mock(
        return_value=httpx.Response(200, json={"dl": "https://static.upstream.test/crates"})
    )
    respx.get("https://index.upstream.test/le/ft/leftpad").mock(
        return_value=httpx.Response(200, text=PROXY_INDEX)
    )
    return respx.get("https://static.upstream.test/crates/leftpad/1.0.0/download").mock(
        return_value=httpx.Response(200, content=CRATE)
    )


class TestCargoProxy:
    async def test_config_json_is_served(self, cargo_client):
        response = await cargo_client.get("/cargo/index/config.json")
        assert response.status_code == 200
        assert response.json()["dl"] == "http://registry.test/cargo/api/v1/crates"

    @respx.mock
    async def test_index_is_proxied(self, cargo_client):
        mock_cargo_upstream()
        response = await cargo_client.get("/cargo/index/le/ft/leftpad")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")

        entry = orjson.loads(response.text.strip())
        assert entry["name"] == "leftpad"
        assert entry["vers"] == "1.0.0"
        assert entry["cksum"] == CRATE_SHA256
        assert entry["deps"][0]["req"] == "^0.2"

    @respx.mock
    async def test_a_mismatched_shard_prefix_is_rejected(self, cargo_client):
        """Serving `se/rd/leftpad` would cache under a path no client will ask
        for again, and hide the client-side bug that produced it."""
        mock_cargo_upstream()
        response = await cargo_client.get("/cargo/index/se/rd/leftpad")
        assert response.status_code == 404

    @respx.mock
    async def test_artifact_is_fetched_cached_and_served(self, cargo_client):
        route = mock_cargo_upstream()
        await cargo_client.get("/cargo/index/le/ft/leftpad")

        first = await cargo_client.get("/cargo/api/v1/crates/leftpad/1.0.0/download")
        assert first.status_code == 200
        assert first.content == CRATE
        assert hashlib.sha256(first.content).hexdigest() == CRATE_SHA256

        second = await cargo_client.get("/cargo/api/v1/crates/leftpad/1.0.0/download")
        assert second.content == CRATE
        # Served from the blob store the second time, not re-fetched.
        assert route.call_count == 1

    @respx.mock
    async def test_unknown_crate_is_404(self, cargo_client):
        respx.get("https://index.upstream.test/no/pe/nope").mock(
            return_value=httpx.Response(404)
        )
        response = await cargo_client.get("/cargo/index/no/pe/nope")
        assert response.status_code == 404

    @respx.mock
    async def test_a_blocked_crate_is_refused(self, cargo_client):
        mock_cargo_upstream()
        async with db_module.session_scope() as session:
            session.add(
                PackageRule(
                    ecosystem=Ecosystem.cargo,
                    pattern="leftpad",
                    action=RuleAction.block,
                    reason="policy test",
                )
            )
        await invalidate_policy_cache()

        index = await cargo_client.get("/cargo/index/le/ft/leftpad")
        assert index.status_code == 403
        assert "policy test" in index.text

        download = await cargo_client.get("/cargo/api/v1/crates/leftpad/1.0.0/download")
        assert download.status_code == 403
