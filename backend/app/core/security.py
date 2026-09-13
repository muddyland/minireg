"""Password hashing, API tokens, session JWTs, and credential encryption."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from ..config import settings

_hasher = PasswordHasher()

# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #


def hash_password(password: str) -> str:
    return _hasher.hash(password)


#: Hash of a value nobody knows, verified against when the account does not
#: exist. Without it an unknown username returned in microseconds while a
#: known one paid a full argon2 verify, which is a usable oracle for
#: enumerating accounts.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        # Same work, same duration, same answer.
        with contextlib.suppress(Exception):
            _hasher.verify(_DUMMY_HASH, password)
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# API tokens
# --------------------------------------------------------------------------- #
# Format: {prefix}_{public_id}_{secret}
#   e.g. mrg_a1b2c3d4_9f8e...  (the secret half is never stored)
#
# The public id gives us an indexed O(1) lookup, so verification is a single
# row fetch plus one constant-time compare -- no table scan, no bcrypt-per-row.

TOKEN_ID_BYTES = 6
TOKEN_SECRET_BYTES = 32


def generate_token() -> tuple[str, str, str]:
    """Return ``(full_token, public_prefix, sha256_hash_of_secret)``."""
    public_id = secrets.token_hex(TOKEN_ID_BYTES)
    secret = secrets.token_urlsafe(TOKEN_SECRET_BYTES)
    prefix = f"{settings.token_prefix}_{public_id}"
    full = f"{prefix}_{secret}"
    return full, prefix, hash_token_secret(secret)


def hash_token_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def split_token(token: str) -> tuple[str, str] | None:
    """Split a presented token into ``(prefix, secret)``."""
    parts = token.strip().split("_")
    if len(parts) < 3:
        return None
    prefix = "_".join(parts[:2])
    secret = "_".join(parts[2:])
    if not prefix or not secret:
        return None
    return prefix, secret


def verify_token_secret(secret: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_token_secret(secret), expected_hash)


def parse_basic_auth(header: str) -> tuple[str, str] | None:
    """Decode an HTTP Basic header.

    pip sends credentials this way (``__token__`` / token, per PyPI
    convention), and older npm clients do too.
    """
    if not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:].strip()).decode("utf-8", "replace")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    user, _, password = decoded.partition(":")
    return user, password


def extract_bearer(header: str | None) -> str | None:
    if not header:
        return None
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


# --------------------------------------------------------------------------- #
# Session JWTs (browser / admin UI)
# --------------------------------------------------------------------------- #
JWT_ALG = "HS256"


def create_session_token(
    user_id: int,
    username: str,
    is_admin: bool,
    ttl: int | None = None,
    session_version: int = 0,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "username": username,
        "admin": is_admin,
        # Compared against the user row on every request, so a password change
        # or an explicit sign-out-everywhere invalidates existing cookies
        # instead of leaving them valid for the rest of their 12 hours.
        "sv": session_version,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl or settings.session_ttl_seconds)).timestamp()),
        "typ": "session",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALG)


def decode_session_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        return None
    if payload.get("typ") != "session":
        return None
    return payload


def create_state_token(data: dict, ttl: int = 600) -> str:
    """Signed OIDC state/nonce carrier, so we hold no server-side login state."""
    now = datetime.now(UTC)
    payload = {**data, "iat": int(now.timestamp()), "exp": int((now + timedelta(seconds=ttl)).timestamp()), "typ": "oidc_state"}
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALG)


def decode_state_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        return None
    if payload.get("typ") != "oidc_state":
        return None
    return payload


# --------------------------------------------------------------------------- #
# Upstream credential encryption at rest
# --------------------------------------------------------------------------- #


def _fernet() -> Fernet:
    key = settings.credential_key
    if not key:
        # Derive deterministically from SECRET_KEY so a single-secret deployment
        # still gets encrypted upstream credentials.
        digest = hashlib.sha256(f"minireg-credential:{settings.secret_key}".encode()).digest()
        key = base64.urlsafe_b64encode(digest).decode()
    elif len(key) != 44 or not key.endswith("="):
        digest = hashlib.sha256(key.encode()).digest()
        key = base64.urlsafe_b64encode(digest).decode()
    return Fernet(key)


def encrypt_credential(plaintext: str | None) -> str | None:
    if not plaintext:
        return None
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_credential(ciphertext: str | None) -> str | None:
    if not ciphertext:
        return None
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return None


def mask_secret(value: str | None, keep: int = 4) -> str | None:
    """Render a secret for display without leaking it."""
    if not value:
        return None
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(len(value) - keep, 20)
