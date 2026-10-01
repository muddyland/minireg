"""Shared fixtures for the container registry tests.

A fake OCI upstream built on respx: it serves a bearer challenge, a token
endpoint, manifests (by tag and digest), and blobs through a CDN redirect,
exactly the shape Docker Hub has. Every request it receives is counted so
tests can assert how much upstream quota a scenario costs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass, field

import httpx
import pytest_asyncio
import respx
from httpx import ASGITransport, AsyncClient

from app import db as db_module
from app.core.security import generate_token
from app.docker import registry as reg
from app.docker import upstream as upstream_mod
from app.docker.policy import invalidate_policy
from app.docker.store import OciStore, set_oci_store
from app.models import ApiToken, Ecosystem, Upstream, UpstreamKind, User
from app.services.storage import BlobStore, set_store

UP = "https://registry.upstream.test"
AUTH = "https://auth.upstream.test/token"
CDN = "https://cdn.upstream.test"

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def dumps(doc) -> bytes:
    return json.dumps(doc, separators=(",", ":")).encode()


@dataclass
class Image:
    config: bytes
    layers: list[bytes]
    manifest: bytes = b""
    digest: str = ""

    @classmethod
    def build(
        cls, seed: str, layer_sizes=(1000, 3000), extra: dict | None = None, config: dict | None = None
    ) -> Image:
        config = dumps(config or {"architecture": "amd64", "os": "linux", "seed": seed})
        layers = [(seed.encode() + bytes([i])) * (n // (len(seed) + 1) + 1) for i, n in enumerate(layer_sizes)]
        doc = {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {"mediaType": OCI_CONFIG, "digest": sha(config), "size": len(config)},
            "layers": [{"mediaType": OCI_LAYER, "digest": sha(b), "size": len(b)} for b in layers],
        }
        if extra:
            doc.update(extra)
        body = dumps(doc)
        return cls(config=config, layers=layers, manifest=body, digest=sha(body))

    @property
    def blobs(self) -> dict[str, bytes]:
        out = {sha(self.config): self.config}
        out.update({sha(b): b for b in self.layers})
        return out


def index_of(*images: tuple[Image, str], attestation: Image | None = None) -> tuple[bytes, str]:
    entries = []
    for img, platform in images:
        os_, arch, *variant = platform.split("/")
        spec = {"os": os_, "architecture": arch}
        if variant:
            spec["variant"] = variant[0]
        entries.append(
            {
                "mediaType": OCI_MANIFEST,
                "digest": img.digest,
                "size": len(img.manifest),
                "platform": spec,
            }
        )
    if attestation is not None:
        entries.append(
            {
                "mediaType": OCI_MANIFEST,
                "digest": attestation.digest,
                "size": len(attestation.manifest),
                "platform": {"os": "unknown", "architecture": "unknown"},
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": images[0][0].digest,
                },
            }
        )
    body = dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries})
    return body, sha(body)


@dataclass
class FakeRegistry:
    """Serves repositories of the form {repo: {tag: manifest_bytes}}."""

    repos: dict[str, dict[str, bytes]] = field(default_factory=dict)
    manifests: dict[str, tuple[bytes, str]] = field(default_factory=dict)
    blobs: dict[str, bytes] = field(default_factory=dict)
    calls: Counter = field(default_factory=Counter)
    #: status to answer manifest requests with instead (e.g. 429, 503)
    fail_with: int | None = None
    ratelimit_remaining: int = 99
    #: Where blob redirects point (a hostile upstream would change this).
    redirect_host: str = CDN
    #: Optional replacement handlers, for registries that misbehave in a
    #: particular way (redirecting the API itself, say).
    manifest_hook: object = None
    cdn_hook: object = None
    referrers_hook: object = None

    def add_image(self, repo: str, tag: str | None, image: Image) -> None:
        self.manifests[image.digest] = (image.manifest, OCI_MANIFEST)
        self.blobs.update(image.blobs)
        if tag:
            self.repos.setdefault(repo, {})[tag] = image.manifest
        else:
            self.repos.setdefault(repo, {})

    def add_index(self, repo: str, tag: str, body: bytes, *children: Image) -> None:
        self.manifests[sha(body)] = (body, OCI_INDEX)
        for child in children:
            self.manifests[child.digest] = (child.manifest, OCI_MANIFEST)
            self.blobs.update(child.blobs)
        self.repos.setdefault(repo, {})[tag] = body

    def install(self, router: respx.MockRouter) -> None:
        router.get(f"{UP}/v2/").mock(side_effect=self._ping)
        router.get(AUTH).mock(side_effect=self._token)
        router.route(host="registry.upstream.test", path__regex=r"^/v2/.+/manifests/.+$").mock(
            side_effect=lambda r: (self.manifest_hook or self._manifest)(r)
        )
        router.route(host="registry.upstream.test", path__regex=r"^/v2/.+/blobs/.+$").mock(
            side_effect=self._blob
        )
        router.route(host="registry.upstream.test", path__regex=r"^/v2/.+/referrers/.+$").mock(
            side_effect=lambda r: self.referrers_hook(r) if self.referrers_hook else httpx.Response(404)
        )
        router.route(host="registry.upstream.test", path__regex=r"^/v2/.+/tags/list$").mock(
            side_effect=self._tags
        )
        router.route(host="cdn.upstream.test").mock(side_effect=lambda r: (self.cdn_hook or self._cdn)(r))

    def _authed(self, request: httpx.Request) -> bool:
        return request.headers.get("authorization", "").startswith("Bearer tok-")

    def _challenge(self, request, repo):
        return httpx.Response(
            401,
            headers={
                "www-authenticate": f'Bearer realm="{AUTH}",service="upstream.test",scope="repository:{repo}:pull"'
            },
        )

    def _ping(self, request):
        self.calls["ping"] += 1
        return httpx.Response(401, headers={"www-authenticate": f'Bearer realm="{AUTH}",service="upstream.test"'})

    def _token(self, request):
        self.calls["token"] += 1
        return httpx.Response(200, json={"token": "tok-" + request.url.params.get("scope", ""), "expires_in": 300})

    def _split(self, path: str, marker: str) -> tuple[str, str]:
        rest = path[len("/v2/"):]
        repo, _, ref = rest.rpartition(marker)
        return repo, ref

    def _manifest(self, request: httpx.Request):
        repo, ref = self._split(request.url.path, "/manifests/")
        if not self._authed(request):
            return self._challenge(request, repo)
        kind = "head" if request.method == "HEAD" else "get"
        self.calls[f"manifest_{kind}"] += 1
        self.calls[f"manifest_{kind}:{repo}:{ref}"] += 1
        rl = {"ratelimit-limit": "100;w=21600", "ratelimit-remaining": f"{self.ratelimit_remaining};w=21600"}
        if self.fail_with:
            return httpx.Response(self.fail_with, headers={"retry-after": "60", **rl})
        tags = self.repos.get(repo)
        if tags is None:
            return httpx.Response(404, json={"errors": [{"code": "NAME_UNKNOWN"}]})
        if ref.startswith("sha256:"):
            found = self.manifests.get(ref)
        else:
            body = tags.get(ref)
            found = (body, OCI_INDEX if b'"manifests"' in body else OCI_MANIFEST) if body else None
        if not found:
            return httpx.Response(404, json={"errors": [{"code": "MANIFEST_UNKNOWN"}]})
        body, media_type = found
        headers = {"content-type": media_type, "docker-content-digest": sha(body), **rl}
        if request.method == "HEAD":
            headers["content-length"] = str(len(body))
            return httpx.Response(200, headers=headers)
        return httpx.Response(200, content=body, headers=headers)

    def _blob(self, request: httpx.Request):
        repo, digest = self._split(request.url.path, "/blobs/")
        if not self._authed(request):
            return self._challenge(request, repo)
        self.calls["blob"] += 1
        if digest not in self.blobs:
            return httpx.Response(404)
        return httpx.Response(307, headers={"location": f"{self.redirect_host}/blobs/{digest}?sig=abc"})

    def _cdn(self, request: httpx.Request):
        self.calls["cdn"] += 1
        if request.headers.get("authorization"):
            # The registry's bearer must never follow a redirect to a CDN.
            self.calls["cdn_leaked_auth"] += 1
        digest = request.url.path.rsplit("/", 1)[-1]
        data = self.blobs.get(digest)
        if data is None:
            return httpx.Response(404)
        return httpx.Response(200, content=data, headers={"content-length": str(len(data))})

    def _tags(self, request):
        repo = request.url.path[len("/v2/"): -len("/tags/list")]
        if not self._authed(request):
            return self._challenge(request, repo)
        self.calls["tags"] += 1
        return httpx.Response(200, json={"name": repo, "tags": sorted(self.repos.get(repo, {}))})


@pytest_asyncio.fixture
async def docker_env(tmp_path, monkeypatch):
    """App + sqlite + stores + a fake upstream named 'dockerhub' (default)."""
    from app.config import settings
    from app.main import app

    monkeypatch.setattr(settings, "upstream_allow_private_addresses", True)
    # SQLite by default. DOCKER_TEST_DATABASE_URL runs the same tests against
    # PostgreSQL, which is stricter (GROUP BY, types, FK enforcement) and is
    # what production runs; each test gets a fresh schema.
    pg_url = os.environ.get("DOCKER_TEST_DATABASE_URL")
    if pg_url:
        db_module.init_engine(pg_url)
        from app.models import Base

        async with db_module.get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    else:
        db_module.init_engine(f"sqlite+aiosqlite:///{tmp_path / 'docker.db'}")
    await db_module.create_schema()
    store = BlobStore(str(tmp_path / "storage"))
    store.ensure_dirs()
    set_store(store)
    oci = OciStore(tmp_path / "oci")
    oci.ensure_dirs()
    set_oci_store(oci)
    reg._clients.clear()
    reg._local_neg.clear()
    upstream_mod.RATELIMITS.clear()

    async with db_module.session_scope() as session:
        session.add(
            Upstream(
                name="dockerhub",
                ecosystem=Ecosystem.docker,
                kind=UpstreamKind.oci,
                url=UP,
                tier=1,
                enabled=True,
                extra={"blob_hosts": ["cdn.upstream.test"], "auth_hosts": ["auth.upstream.test"], "default": True, "library_prefix": True},
            )
        )
        session.add(
            Upstream(
                name="quay",
                ecosystem=Ecosystem.docker,
                kind=UpstreamKind.oci,
                url=UP,
                tier=1,
                enabled=True,
                extra={"blob_hosts": ["cdn.upstream.test"], "auth_hosts": ["auth.upstream.test"]},
            )
        )
    await invalidate_policy()

    fake = FakeRegistry()
    # The pinned transport cannot be intercepted by respx; tests use a plain
    # client, and check_target still applies its host rules.
    plain = httpx.AsyncClient(follow_redirects=False)
    upstream_mod.set_test_client(plain)
    # check_target resolves hosts; the .test names do not exist.
    async def fake_resolve(host, port):
        return ["203.0.113.10"]

    monkeypatch.setattr(upstream_mod, "_resolve", fake_resolve)

    with respx.mock(assert_all_called=False) as router:
        fake.install(router)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://registry.test") as client:
            yield client, fake

    upstream_mod.set_test_client(None)
    await plain.aclose()
    await db_module.dispose_engine()
    set_store(None)  # type: ignore[arg-type]
    set_oci_store(None)


async def settle_fills(store=None, timeout: float = 30) -> None:
    """Wait for background blob fills to finish.

    A client gets its last byte before the fill task has verified, renamed
    and recorded the blob. Tests that then look at the store or the database
    used to sleep 50 ms for that, which a loaded CI runner outlasts.
    """
    from app.docker.store import get_oci_store

    store = store or get_oci_store()
    tasks = [f.task for f in list(store._fills.values()) if f.task is not None]
    if tasks:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout)


async def make_user(
    *,
    username="dev",
    scopes=("read", "docker:push"),
    can_publish=True,
    is_admin=False,
    prefixes=(),
) -> str:
    async with db_module.session_scope() as session:
        from sqlalchemy import select

        user = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if user is None:
            user = User(username=username, can_publish=can_publish, is_admin=is_admin, is_active=True)
            session.add(user)
            await session.flush()
        full, prefix, token_hash = generate_token()
        session.add(
            ApiToken(
                user_id=user.id,
                name=f"t-{username}",
                prefix=prefix,
                token_hash=token_hash,
                scopes=list(scopes),
                docker_repo_prefixes=list(prefixes),
            )
        )
    return full


async def bearer(client: AsyncClient, scope: str, token: str | None = None) -> dict[str, str]:
    """Run the docker login dance and return an Authorization header."""
    auth = (("u", token) if token else None)
    resp = await client.get("/v2/token", params={"service": "minireg", "scope": scope}, auth=auth)
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}
