"""
API key generation, validation, and revocation.

Keys are generated as cryptographically random tokens with a human-readable
prefix (``mlsk_``).  Only the SHA-256 hash is stored; the plaintext key is
returned exactly once at creation time.

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)

_KEY_PREFIX = "mlsk_"
_KEY_BYTES = 32  # 256-bit random part


class APIKeyManager:
    """
    Manages the lifecycle of API keys for programmatic access.

    Keys follow the format ``mlsk_<hex-random>``.  Storage is delegated
    to a ``UserStore`` instance (SQLite).
    """

    def __init__(self, store: Optional[Any] = None) -> None:
        self._store = store

    # -- key lifecycle -----------------------------------------------------

    def create_key(
        self,
        user_id: str,
        name: str = "default",
        scopes: Optional[list[str]] = None,
        ttl_days: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Generate a new API key.

        Returns a dict containing the plaintext ``key`` (shown once),
        ``key_prefix``, ``key_hash``, and metadata.
        """
        raw = secrets.token_hex(_KEY_BYTES)
        plaintext = f"{_KEY_PREFIX}{raw}"
        key_hash = self._hash_key(plaintext)
        key_prefix = plaintext[:12]

        expires_at: Optional[datetime] = None
        if ttl_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)

        if self._store is not None:
            self._store.store_api_key(
                key_hash=key_hash,
                key_prefix=key_prefix,
                user_id=user_id,
                name=name,
                scopes=scopes or [],
                expires_at=expires_at,
            )

        logger.info("API key created for user=%s name=%s", user_id, name)

        return {
            "key": plaintext,
            "key_prefix": key_prefix,
            "key_hash": key_hash,
            "user_id": user_id,
            "name": name,
            "scopes": scopes or [],
            "expires_at": expires_at.isoformat() if expires_at else None,
        }

    def validate_key(self, plaintext_key: str) -> Optional[dict[str, Any]]:
        """
        Validate an API key and return the associated record.

        Returns ``None`` if the key is invalid, revoked, or expired.
        """
        if not plaintext_key.startswith(_KEY_PREFIX):
            return None

        key_hash = self._hash_key(plaintext_key)

        if self._store is None:
            return None

        record = self._store.get_api_key_record(key_hash)
        if record is None:
            return None

        if not record.get("is_active", False):
            return None

        # check expiry
        expires_str = record.get("expires_at")
        if expires_str:
            expires_at = datetime.fromisoformat(expires_str)
            if expires_at < datetime.now(timezone.utc):
                return None

        # update last-used timestamp
        self._store.update_api_key_last_used(key_hash)

        return record

    def revoke_key(self, plaintext_key: str) -> bool:
        """Revoke an API key by its plaintext value."""
        key_hash = self._hash_key(plaintext_key)
        if self._store is not None:
            return self._store.revoke_api_key(key_hash)
        return False

    def revoke_key_by_hash(self, key_hash: str) -> bool:
        """Revoke an API key by its stored hash."""
        if self._store is not None:
            return self._store.revoke_api_key(key_hash)
        return False

    def list_keys(self, user_id: str) -> list[dict[str, Any]]:
        """List all API keys for a user (without revealing the plaintext)."""
        if self._store is not None:
            return self._store.list_api_keys_for_user(user_id)
        return []

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _hash_key(plaintext: str) -> str:
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
