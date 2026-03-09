"""
JWT authentication and password hashing engine.

Implements secure password hashing using PBKDF2-HMAC-SHA256 (hashlib),
JWT token creation/validation with HMAC-SHA256, and token refresh logic.

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import base64
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256, stdlib only)
# ---------------------------------------------------------------------------

_DEFAULT_ITERATIONS = 260_000
_SALT_LENGTH = 32
_KEY_LENGTH = 32


def hash_password(password: str, iterations: int = _DEFAULT_ITERATIONS) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256.

    Returns a string in the format: ``$pbkdf2-sha256$<iterations>$<salt_b64>$<hash_b64>``
    """
    salt = os.urandom(_SALT_LENGTH)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=_KEY_LENGTH,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(dk).decode("ascii")
    return f"$pbkdf2-sha256${iterations}${salt_b64}${hash_b64}"


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a PBKDF2 hash string.
    """
    try:
        parts = hashed.split("$")
        # format: ['', 'pbkdf2-sha256', iterations, salt_b64, hash_b64]
        if len(parts) != 5 or parts[1] != "pbkdf2-sha256":
            return False
        iterations = int(parts[2])
        salt = base64.b64decode(parts[3])
        expected_hash = base64.b64decode(parts[4])

        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=_KEY_LENGTH,
        )
        return hmac.compare_digest(dk, expected_hash)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT Token handling (stdlib HMAC-SHA256, no PyJWT dependency)
# ---------------------------------------------------------------------------

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _create_jwt(payload: dict[str, Any], secret: str) -> str:
    """Create a JWT token using HMAC-SHA256."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":"), default=str).encode())

    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _base64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _verify_jwt(token: str, secret: str) -> Optional[dict[str, Any]]:
    """
    Verify and decode a JWT token.

    Returns the payload dict if valid, ``None`` otherwise.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, sig_b64 = parts

        # verify signature
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        actual_sig = _base64url_decode(sig_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload = json.loads(_base64url_decode(payload_b64))

        # check expiry
        if "exp" in payload and payload["exp"] < time.time():
            return None

        return payload
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Authenticator class
# ---------------------------------------------------------------------------

class Authenticator:
    """
    Central authentication service.

    Manages JWT access / refresh tokens and password verification.
    """

    def __init__(
        self,
        secret_key: str = "change-me-in-production-use-256-bit-secret-key",
        access_token_ttl_minutes: int = 30,
        refresh_token_ttl_days: int = 7,
        algorithm: str = "HS256",
    ) -> None:
        self._secret_key = secret_key
        self._access_ttl = access_token_ttl_minutes
        self._refresh_ttl = refresh_token_ttl_days
        self._algorithm = algorithm
        # simple in-memory blacklist (for demo / single-process)
        self._blacklisted_tokens: set[str] = set()

    # -- password helpers --------------------------------------------------

    @staticmethod
    def hash_password(password: str) -> str:
        return hash_password(password)

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        return verify_password(password, hashed)

    # -- token creation ----------------------------------------------------

    def create_access_token(
        self,
        user_id: str,
        username: str,
        roles: list[str],
        extra_claims: Optional[dict[str, Any]] = None,
    ) -> str:
        """Create a short-lived access JWT."""
        now = time.time()
        payload: dict[str, Any] = {
            "sub": user_id,
            "username": username,
            "roles": roles,
            "type": "access",
            "iat": int(now),
            "exp": int(now + self._access_ttl * 60),
            "jti": secrets.token_hex(16),
        }
        if extra_claims:
            payload.update(extra_claims)
        return _create_jwt(payload, self._secret_key)

    def create_refresh_token(self, user_id: str) -> str:
        """Create a long-lived refresh JWT."""
        now = time.time()
        payload: dict[str, Any] = {
            "sub": user_id,
            "type": "refresh",
            "iat": int(now),
            "exp": int(now + self._refresh_ttl * 86400),
            "jti": secrets.token_hex(16),
        }
        return _create_jwt(payload, self._secret_key)

    # -- token validation --------------------------------------------------

    def validate_token(self, token: str) -> Optional[dict[str, Any]]:
        """Validate a JWT token. Returns payload or ``None``."""
        if token in self._blacklisted_tokens:
            return None
        return _verify_jwt(token, self._secret_key)

    def validate_access_token(self, token: str) -> Optional[dict[str, Any]]:
        """Validate specifically an access token."""
        payload = self.validate_token(token)
        if payload and payload.get("type") == "access":
            return payload
        return None

    def validate_refresh_token(self, token: str) -> Optional[dict[str, Any]]:
        """Validate specifically a refresh token."""
        payload = self.validate_token(token)
        if payload and payload.get("type") == "refresh":
            return payload
        return None

    # -- token refresh -----------------------------------------------------

    def refresh_access_token(
        self,
        refresh_token: str,
        username: str,
        roles: list[str],
    ) -> Optional[str]:
        """
        Exchange a valid refresh token for a new access token.

        Returns a new access JWT or ``None`` if the refresh token is invalid.
        """
        payload = self.validate_refresh_token(refresh_token)
        if payload is None:
            return None
        user_id = payload["sub"]
        return self.create_access_token(user_id, username, roles)

    # -- revocation --------------------------------------------------------

    def revoke_token(self, token: str) -> None:
        """Add a token to the blacklist."""
        self._blacklisted_tokens.add(token)

    # -- password policy ---------------------------------------------------

    @staticmethod
    def validate_password_strength(
        password: str,
        min_length: int = 12,
        require_upper: bool = True,
        require_lower: bool = True,
        require_digit: bool = True,
        require_special: bool = True,
    ) -> tuple[bool, list[str]]:
        """
        Validate password against complexity requirements.

        Returns (is_valid, list_of_violations).
        """
        violations: list[str] = []

        if len(password) < min_length:
            violations.append(f"Password must be at least {min_length} characters")
        if require_upper and not any(c.isupper() for c in password):
            violations.append("Password must contain at least one uppercase letter")
        if require_lower and not any(c.islower() for c in password):
            violations.append("Password must contain at least one lowercase letter")
        if require_digit and not any(c.isdigit() for c in password):
            violations.append("Password must contain at least one digit")
        if require_special and not any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in password):
            violations.append("Password must contain at least one special character")

        return (len(violations) == 0, violations)
