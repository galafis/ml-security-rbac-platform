"""
Unit tests for the Authenticator module.

Author: Gabriel Demetrios Lafis
"""

import time

from src.auth.authenticator import (
    Authenticator,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    """Tests for PBKDF2 password hashing."""

    def test_hash_produces_valid_format(self):
        hashed = hash_password("testpassword")
        parts = hashed.split("$")
        assert len(parts) == 5
        assert parts[1] == "pbkdf2-sha256"

    def test_verify_correct_password(self):
        hashed = hash_password("my-secret-password")
        assert verify_password("my-secret-password", hashed) is True

    def test_verify_wrong_password(self):
        hashed = hash_password("correct-password")
        assert verify_password("wrong-password", hashed) is False

    def test_different_hashes_for_same_password(self):
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2  # different salts

    def test_verify_with_corrupted_hash(self):
        assert verify_password("anything", "corrupted-hash") is False
        assert verify_password("anything", "") is False


class TestJWTTokens:
    """Tests for JWT token creation and validation."""

    def test_create_and_validate_access_token(self, authenticator):
        token = authenticator.create_access_token(
            user_id="user-123",
            username="testuser",
            roles=["ml_viewer"],
        )
        payload = authenticator.validate_access_token(token)
        assert payload is not None
        assert payload["sub"] == "user-123"
        assert payload["username"] == "testuser"
        assert payload["roles"] == ["ml_viewer"]
        assert payload["type"] == "access"

    def test_create_and_validate_refresh_token(self, authenticator):
        token = authenticator.create_refresh_token(user_id="user-456")
        payload = authenticator.validate_refresh_token(token)
        assert payload is not None
        assert payload["sub"] == "user-456"
        assert payload["type"] == "refresh"

    def test_access_token_not_valid_as_refresh(self, authenticator):
        token = authenticator.create_access_token("u1", "user", ["ml_viewer"])
        payload = authenticator.validate_refresh_token(token)
        assert payload is None

    def test_refresh_token_not_valid_as_access(self, authenticator):
        token = authenticator.create_refresh_token("u1")
        payload = authenticator.validate_access_token(token)
        assert payload is None

    def test_invalid_token_returns_none(self, authenticator):
        assert authenticator.validate_token("not.a.valid.token") is None
        assert authenticator.validate_token("") is None

    def test_token_with_wrong_secret(self):
        auth1 = Authenticator(secret_key="secret-one")
        auth2 = Authenticator(secret_key="secret-two")
        token = auth1.create_access_token("u1", "user", ["ml_viewer"])
        assert auth2.validate_access_token(token) is None

    def test_revoke_token(self, authenticator):
        token = authenticator.create_access_token("u1", "user", ["ml_viewer"])
        assert authenticator.validate_access_token(token) is not None
        authenticator.revoke_token(token)
        assert authenticator.validate_access_token(token) is None

    def test_refresh_access_token(self, authenticator):
        refresh = authenticator.create_refresh_token("u1")
        new_access = authenticator.refresh_access_token(refresh, "user", ["ml_admin"])
        assert new_access is not None
        payload = authenticator.validate_access_token(new_access)
        assert payload is not None
        assert payload["roles"] == ["ml_admin"]

    def test_expired_token_returns_none(self):
        auth = Authenticator(
            secret_key="test",
            access_token_ttl_minutes=0,  # expires immediately
        )
        token = auth.create_access_token("u1", "user", ["ml_viewer"])
        # token has exp = now + 0*60 = now, which is already past
        time.sleep(0.1)
        assert auth.validate_access_token(token) is None


class TestPasswordPolicy:
    """Tests for password strength validation."""

    def test_strong_password_passes(self):
        valid, violations = Authenticator.validate_password_strength(
            "MyStr0ng!Pass", min_length=8
        )
        assert valid is True
        assert violations == []

    def test_short_password_fails(self):
        valid, violations = Authenticator.validate_password_strength(
            "Ab1!", min_length=8
        )
        assert valid is False
        assert any("at least 8" in v for v in violations)

    def test_missing_uppercase_fails(self):
        valid, violations = Authenticator.validate_password_strength(
            "alllowercase1!", min_length=8
        )
        assert valid is False
        assert any("uppercase" in v for v in violations)

    def test_missing_digit_fails(self):
        valid, violations = Authenticator.validate_password_strength(
            "NoDigitsHere!!", min_length=8
        )
        assert valid is False
        assert any("digit" in v for v in violations)
