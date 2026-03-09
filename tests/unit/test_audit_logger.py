"""
Unit tests for the AuditLogger.

Author: Gabriel Demetrios Lafis
"""

from src.audit.audit_logger import AuditLogger


class TestAuditLogger:
    """Tests for audit logging and hash chain."""

    def test_log_creates_entry(self):
        logger = AuditLogger(enable_hash_chain=True)
        entry = logger.log(
            user_id="u1",
            username="testuser",
            action="login",
            result="success",
        )
        assert entry.user_id == "u1"
        assert entry.action == "login"
        assert entry.hash_chain != ""

    def test_hash_chain_integrity(self):
        logger = AuditLogger(enable_hash_chain=True)
        logger.log("u1", "user1", "login", result="success")
        logger.log("u2", "user2", "read", resource_type="model", resource_id="m1")
        logger.log("u1", "user1", "write", resource_type="dataset", resource_id="d1")
        assert logger.verify_chain() is True

    def test_get_entries_returns_logged_data(self):
        logger = AuditLogger(enable_hash_chain=False)
        logger.log("u1", "alice", "login")
        logger.log("u2", "bob", "read", resource_type="model")
        entries = logger.get_entries()
        assert len(entries) == 2

    def test_get_entries_filter_by_user(self):
        logger = AuditLogger(enable_hash_chain=False)
        logger.log("u1", "alice", "login")
        logger.log("u2", "bob", "login")
        logger.log("u1", "alice", "read")
        entries = logger.get_entries(user_id="u1")
        assert len(entries) == 2

    def test_log_access_convenience(self):
        logger = AuditLogger(enable_hash_chain=False)
        entry = logger.log_access(
            user_id="u1",
            username="alice",
            resource_type="model",
            resource_id="m1",
            action="read",
            allowed=True,
            reason="Permission granted",
        )
        assert entry.result == "allow"
        assert entry.details["reason"] == "Permission granted"

    def test_log_auth_event_convenience(self):
        logger = AuditLogger(enable_hash_chain=False)
        entry = logger.log_auth_event(
            user_id="u1",
            username="alice",
            event="login",
            success=False,
        )
        assert entry.action == "login"
        assert entry.result == "failure"
