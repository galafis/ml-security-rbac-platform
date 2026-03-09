"""
Security audit logger with tamper-detection hash chain.

Records every access decision (allow / deny) with full context:
who, what, when, action, result, source IP, and a SHA-256 hash
chain that links each entry to its predecessor for integrity
verification.

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


class AuditEntry:
    """Immutable record of a single auditable event."""

    __slots__ = (
        "timestamp",
        "user_id",
        "username",
        "action",
        "resource_type",
        "resource_id",
        "result",
        "ip_address",
        "details",
        "hash_chain",
    )

    def __init__(
        self,
        user_id: str,
        username: str,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        result: str = "allow",
        ip_address: str = "127.0.0.1",
        details: Optional[dict[str, Any]] = None,
        hash_chain: str = "",
    ) -> None:
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.user_id = user_id
        self.username = username
        self.action = action
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.result = result
        self.ip_address = ip_address
        self.details = details or {}
        self.hash_chain = hash_chain

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "username": self.username,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "result": self.result,
            "ip_address": self.ip_address,
            "details": self.details,
            "hash_chain": self.hash_chain,
        }


class AuditLogger:
    """
    Audit logger with optional SQLite persistence and hash-chain integrity.

    When a ``UserStore`` is provided, entries are persisted to the
    ``audit_log`` table.  Otherwise they are kept in memory (useful for
    testing and the CLI demo).
    """

    def __init__(self, store: Optional[Any] = None, enable_hash_chain: bool = True) -> None:
        self._store = store
        self._enable_hash_chain = enable_hash_chain
        self._last_hash: str = "0" * 64  # genesis hash
        self._entries: list[AuditEntry] = []

    # -- core API ----------------------------------------------------------

    def log(
        self,
        user_id: str,
        username: str,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        result: str = "allow",
        ip_address: str = "127.0.0.1",
        details: Optional[dict[str, Any]] = None,
    ) -> AuditEntry:
        """
        Record an audit event.

        Returns the ``AuditEntry`` (with hash-chain value set).
        """
        entry = AuditEntry(
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            ip_address=ip_address,
            details=details,
        )

        if self._enable_hash_chain:
            entry.hash_chain = self._compute_hash(entry)
            self._last_hash = entry.hash_chain

        self._entries.append(entry)

        # persist
        if self._store is not None:
            try:
                self._store.insert_audit_entry(
                    user_id=entry.user_id,
                    username=entry.username,
                    action=entry.action,
                    resource_type=entry.resource_type,
                    resource_id=entry.resource_id,
                    result=entry.result,
                    ip_address=entry.ip_address,
                    details=entry.details,
                    hash_chain=entry.hash_chain,
                )
            except Exception as exc:  # pragma: no cover
                logger.error("Failed to persist audit entry: %s", exc)

        logger.info(
            "AUDIT | %s | user=%s action=%s resource=%s:%s result=%s",
            entry.timestamp,
            username,
            action,
            resource_type,
            resource_id,
            result,
        )
        return entry

    def log_access(
        self,
        user_id: str,
        username: str,
        resource_type: str,
        resource_id: str,
        action: str,
        allowed: bool,
        ip_address: str = "127.0.0.1",
        reason: str = "",
    ) -> AuditEntry:
        """Convenience wrapper for resource access events."""
        return self.log(
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result="allow" if allowed else "deny",
            ip_address=ip_address,
            details={"reason": reason},
        )

    def log_auth_event(
        self,
        user_id: str,
        username: str,
        event: str,
        ip_address: str = "127.0.0.1",
        success: bool = True,
        details: Optional[dict[str, Any]] = None,
    ) -> AuditEntry:
        """Convenience wrapper for authentication events."""
        return self.log(
            user_id=user_id,
            username=username,
            action=event,
            result="success" if success else "failure",
            ip_address=ip_address,
            details=details,
        )

    # -- query -------------------------------------------------------------

    def get_entries(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve audit entries from persistent or in-memory store."""
        if self._store is not None:
            return self._store.get_audit_logs(user_id=user_id, action=action, limit=limit)

        entries = self._entries
        if user_id:
            entries = [e for e in entries if e.user_id == user_id]
        if action:
            entries = [e for e in entries if e.action == action]
        return [e.to_dict() for e in entries[-limit:]]

    # -- integrity ---------------------------------------------------------

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the in-memory hash chain.

        Returns ``True`` if no entries have been tampered with.
        """
        prev_hash = "0" * 64
        for entry in self._entries:
            expected = self._compute_hash_with_prev(entry, prev_hash)
            if entry.hash_chain != expected:
                return False
            prev_hash = entry.hash_chain
        return True

    # -- internal ----------------------------------------------------------

    def _compute_hash(self, entry: AuditEntry) -> str:
        return self._compute_hash_with_prev(entry, self._last_hash)

    @staticmethod
    def _compute_hash_with_prev(entry: AuditEntry, prev_hash: str) -> str:
        data = (
            f"{prev_hash}|{entry.timestamp}|{entry.user_id}|"
            f"{entry.action}|{entry.resource_type}:{entry.resource_id}|"
            f"{entry.result}|{entry.ip_address}"
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
