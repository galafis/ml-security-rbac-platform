"""
Authentication module for ML Security RBAC Platform.

Provides password hashing, JWT token management,
and role-based authorization controls.

Author: Gabriel Demetrios Lafis
"""

from src.auth.authenticator import Authenticator
from src.auth.authorization import AuthorizationEngine

__all__ = [
    "Authenticator",
    "AuthorizationEngine",
]
