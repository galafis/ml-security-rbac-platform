"""
Unit tests for the APIKeyManager.

Author: Gabriel Demetrios Lafis
"""

from src.api_keys.manager import APIKeyManager


class TestAPIKeyManager:
    """Tests for API key create / validate / revoke."""

    def test_create_key_returns_plaintext(self, api_key_manager):
        result = api_key_manager.create_key(user_id="u1", name="test-key")
        assert result["key"].startswith("mlsk_")
        assert len(result["key"]) > 20
        assert result["user_id"] == "u1"

    def test_validate_created_key(self, api_key_manager):
        result = api_key_manager.create_key(user_id="u1", name="validate-test")
        record = api_key_manager.validate_key(result["key"])
        assert record is not None

    def test_invalid_key_returns_none(self, api_key_manager):
        assert api_key_manager.validate_key("mlsk_invalid_key_here") is None
        assert api_key_manager.validate_key("not-even-prefixed") is None

    def test_revoke_key(self, api_key_manager):
        result = api_key_manager.create_key(user_id="u1", name="revoke-test")
        api_key_manager.revoke_key(result["key"])
        assert api_key_manager.validate_key(result["key"]) is None

    def test_list_keys_for_user(self, api_key_manager):
        api_key_manager.create_key(user_id="u1", name="key-a")
        api_key_manager.create_key(user_id="u1", name="key-b")
        api_key_manager.create_key(user_id="u2", name="key-c")
        keys = api_key_manager.list_keys("u1")
        assert len(keys) == 2
