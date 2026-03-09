"""
Unit tests for the RateLimiter.

Author: Gabriel Demetrios Lafis
"""

import pytest

from src.middleware.rate_limiter import RateLimiter, RateLimitExceeded


class TestRateLimiter:
    """Tests for the token-bucket rate limiter."""

    def test_allows_within_limit(self, rate_limiter):
        for _ in range(5):
            assert rate_limiter.allow("client-1") is True

    def test_blocks_over_limit(self, rate_limiter):
        for _ in range(5):
            rate_limiter.allow("client-2")
        assert rate_limiter.allow("client-2") is False

    def test_different_clients_independent(self, rate_limiter):
        for _ in range(5):
            rate_limiter.allow("client-a")
        # client-b should still have tokens
        assert rate_limiter.allow("client-b") is True

    def test_check_raises_on_exceeded(self, rate_limiter):
        for _ in range(5):
            rate_limiter.check("client-3")
        with pytest.raises(RateLimitExceeded):
            rate_limiter.check("client-3")

    def test_get_remaining(self, rate_limiter):
        remaining = rate_limiter.get_remaining("new-client")
        assert remaining == 5

    def test_reset_restores_tokens(self, rate_limiter):
        for _ in range(5):
            rate_limiter.allow("reset-client")
        assert rate_limiter.allow("reset-client") is False
        rate_limiter.reset("reset-client")
        assert rate_limiter.allow("reset-client") is True
