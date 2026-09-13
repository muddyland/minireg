"""GitLab Package Registry providers.

GitLab exposes ecosystem-native endpoints under its own API prefix, so these
subclass the plain npm/PyPI providers and only override URL construction plus
the GitLab-specific listing and publish paths.

Endpoints used
--------------
npm   read    GET  /api/v4/projects/:id/packages/npm/:package_name
      publish PUT  /api/v4/projects/:id/packages/npm/:package_name
      group   GET  /api/v4/groups/:id/-/packages/npm/:package_name
pypi  read    GET  /api/v4/projects/:id/packages/pypi/simple/:normalized_name
      publish POST /api/v4/projects/:id/packages/pypi
list          GET  /api/v4/projects/:id/packages?package_type=npm|pypi
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from ..core.naming import normalize_pypi_name, npm_name_to_path
from ..core.security import decrypt_credential
from .base import SearchHit, UpstreamError
from .npm_provider import NpmProvider
from .pypi_provider import PyPIProvider

log = logging.getLogger(__name__)


class _GitLabMixin:
    """Shared GitLab addressing and auth."""

    def auth_headers(self) -> dict[str, str]:  # type: ignore[override]
        secret = decrypt_credential(self.upstream.credential_enc)  # type: ignore[attr-defined]
        if not secret:
            return {}
        auth_type = (self.upstream.auth_type or "token_header").lower()  # type: ignore[attr-defined]
        if auth_type == "bearer":
            return {"authorization": f"Bearer {secret}"}
        if auth_type == "job_token":
            return {"JOB-TOKEN": secret}
        # Personal / group / project access tokens and deploy tokens all work
        # with PRIVATE-TOKEN, which is GitLab's default.
        header = self.upstream.auth_header_name or "PRIVATE-TOKEN"  # type: ignore[attr-defined]
        return {header: secret}

    @property
    def api_root(self) -> str:
        base = self.base_url  # type: ignore[attr-defined]
        return base if base.endswith("/api/v4") else f"{base}/api/v4"

    @property
    def scope_path(self) -> str:
        """Project scope when configured, otherwise group, otherwise instance."""
        project = self.upstream.gitlab_project_id  # type: ignore[attr-defined]
        group = self.upstream.gitlab_group_id  # type: ignore[attr-defined]
        if project:
            return f"/projects/{quote(str(project), safe='')}"
        if group:
            return f"/groups/{quote(str(group), safe='')}/-"
        return ""

    async def _list_gitlab_packages(self, package_type: str) -> list[dict]:
        """Paginate ``/packages``. Used both for search indexing and health."""
        if not (self.upstream.gitlab_project_id or self.upstream.gitlab_group_id):  # type: ignore[attr-defined]
            raise UpstreamError(f"{self.name}: listing requires a project or group id")  # type: ignore[attr-defined]

        results: list[dict] = []
        page = 1
        while page <= 200:  # hard stop; 200 * 100 = 20k packages
            resp = await self.request(  # type: ignore[attr-defined]
                "GET",
                f"{self.api_root}{self.scope_path}/packages",
                params={"package_type": package_type, "per_page": 100, "page": page},
            )
            if resp.status_code >= 400:
                raise UpstreamError(f"{self.name}: HTTP {resp.status_code}")  # type: ignore[attr-defined]
            batch = self.check_body_size(resp).json()
            if not isinstance(batch, list) or not batch:
                break
            results.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return results

    async def health_check(self) -> tuple[bool, str | None]:
        try:
            resp = await self.request("GET", f"{self.api_root}/version", retries=0)  # type: ignore[attr-defined]
            if resp.status_code in (200, 401, 403):
                # 401/403 still proves GitLab is reachable; credentials are a
                # separate concern surfaced on the first real request.
                return resp.status_code == 200, (
                    None if resp.status_code == 200 else f"auth failed (HTTP {resp.status_code})"
                )
            return False, f"HTTP {resp.status_code}"
        except UpstreamError as exc:
            return False, str(exc)


def _gitlab_packages_page(upstream) -> str | None:
    """GitLab's package registry UI lives under a project's path, which the
    API does not expose from a numeric id. Only derivable when the admin gave
    us a path rather than an id."""
    project = upstream.gitlab_project_id
    if project and not str(project).isdigit():
        from urllib.parse import unquote

        base = upstream.url.rstrip("/").removesuffix("/api/v4")
        return f"{base}/{unquote(str(project))}/-/packages"
    return None


class GitLabNpmProvider(_GitLabMixin, NpmProvider):
    supports_indexing = True
    supports_publish = True
    supports_search = False

    def package_url(self, name: str) -> str:
        return f"{self.api_root}{self.scope_path}/packages/npm/{npm_name_to_path(name)}"

    def default_web_url(self, name: str) -> str | None:
        return _gitlab_packages_page(self.upstream)

    async def list_packages(self) -> list[str]:
        return sorted({p["name"] for p in await self._list_gitlab_packages("npm") if p.get("name")})

    async def search(self, query: str, size: int = 20, offset: int = 0) -> list[SearchHit]:
        """GitLab has no npm search endpoint, so we filter the package list."""
        try:
            packages = await self._list_gitlab_packages("npm")
        except UpstreamError:
            return []
        needle = query.lower()
        hits = [
            SearchHit(
                name=p["name"],
                version=p.get("version"),
                description=None,
                links={"registry": f"{self.base_url}"},
                score=1.0 if p["name"].lower() == needle else 0.5,
            )
            for p in packages
            if p.get("name") and needle in p["name"].lower()
        ]
        return hits[offset : offset + size]

    async def publish(self, payload: dict, ecosystem: str = "npm") -> tuple[bool, str]:
        """Forward an npm publish document verbatim to GitLab."""
        name = payload.get("name")
        if not name:
            return False, "publish payload has no name"
        if not self.upstream.gitlab_project_id:
            return False, "GitLab npm publishing requires a project id"
        url = f"{self.api_root}{self.scope_path}/packages/npm/{npm_name_to_path(name)}"
        resp = await self.request(
            "PUT", url, json=payload, headers={"content-type": "application/json"}, retries=0
        )
        if resp.status_code in (200, 201, 202):
            return True, "published"
        if resp.status_code == 409:
            return False, "version already exists upstream"
        return False, f"GitLab returned HTTP {resp.status_code}: {resp.text[:400]}"


class GitLabPyPIProvider(_GitLabMixin, PyPIProvider):
    supports_indexing = True
    supports_publish = True

    def project_url(self, name: str) -> str:
        return (
            f"{self.api_root}{self.scope_path}/packages/pypi/simple/"
            f"{normalize_pypi_name(name)}/"
        )

    def default_web_url(self, name: str) -> str | None:
        return _gitlab_packages_page(self.upstream)

    async def list_packages(self) -> list[str]:
        return sorted({p["name"] for p in await self._list_gitlab_packages("pypi") if p.get("name")})

    async def publish(self, payload: dict, ecosystem: str = "pypi") -> tuple[bool, str]:
        """Forward a PyPI legacy upload to GitLab's pypi endpoint.

        ``payload`` carries the parsed form fields plus ``content`` as
        ``(filename, bytes, content_type)``.
        """
        if not self.upstream.gitlab_project_id:
            return False, "GitLab PyPI publishing requires a project id"

        content = payload.get("content")
        if not content:
            return False, "publish payload has no file content"
        filename, data, content_type = content

        fields = {
            k: str(v)
            for k, v in payload.items()
            if k != "content" and v is not None and not isinstance(v, (list, dict, tuple))
        }
        resp = await self.request(
            "POST",
            f"{self.api_root}{self.scope_path}/packages/pypi",
            data=fields,
            files={"content": (filename, data, content_type)},
            retries=0,
        )
        if resp.status_code in (200, 201, 202):
            return True, "published"
        if resp.status_code == 409:
            return False, "file already exists upstream"
        return False, f"GitLab returned HTTP {resp.status_code}: {resp.text[:400]}"
