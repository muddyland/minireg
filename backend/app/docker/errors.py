"""OCI distribution error bodies.

Clients print the ``message`` of the first error, so a policy block written
as a proper ``DENIED`` body shows the reason in ``docker pull`` output rather
than a bare "unexpected status code 403".
"""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse

#: Returned on every /v2 response. Clients check it on /v2/ to decide the
#: endpoint speaks the distribution API.
API_VERSION_HEADER = {"Docker-Distribution-API-Version": "registry/2.0"}

_STATUS = {
    "BLOB_UNKNOWN": 404,
    "BLOB_UPLOAD_INVALID": 400,
    "BLOB_UPLOAD_UNKNOWN": 404,
    "DIGEST_INVALID": 400,
    "MANIFEST_BLOB_UNKNOWN": 400,
    "MANIFEST_INVALID": 400,
    "MANIFEST_UNKNOWN": 404,
    "NAME_INVALID": 400,
    "NAME_UNKNOWN": 404,
    "SIZE_INVALID": 400,
    "UNAUTHORIZED": 401,
    "DENIED": 403,
    "UNSUPPORTED": 405,
    "TOOMANYREQUESTS": 429,
    "RANGE_INVALID": 416,
    "UNAVAILABLE": 503,
    "UPSTREAM_ERROR": 502,
}


class RegistryError(Exception):
    """Raised anywhere under /v2 and rendered as an OCI error body."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int | None = None,
        detail: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status or _STATUS.get(code, 400)
        self.detail = detail
        self.headers = headers or {}

    def response(self, *, head: bool = False) -> JSONResponse:
        body: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.detail is not None:
            body["detail"] = self.detail
        # The body is built here, so its length is too: a Content-Length
        # borrowed from the caller's headers would mis-frame the response.
        headers = {
            **API_VERSION_HEADER,
            **{k: v for k, v in self.headers.items() if k.lower() != "content-length"},
        }
        if head:
            # A HEAD response carries no body, but the status and the headers
            # still tell the client what happened.
            return JSONResponse(None, status_code=self.status, headers=headers)
        return JSONResponse({"errors": [body]}, status_code=self.status, headers=headers)
