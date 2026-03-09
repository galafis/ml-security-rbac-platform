"""
Shared test fixtures for ML Security RBAC Platform.

Author: Gabriel Demetrios Lafis
"""

import os
import sys
import tempfile

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.auth.authenticator import Authenticator
from src.auth.authorization import AuthorizationEngine
from src.models.user import User, UserStatus
from src.models.resource import Resource, ResourceType, AccessLevel
from src.storage.user_store import UserStore
from src.audit.audit_logger import AuditLogger
from src.api_keys.manager import APIKeyManager
from src.middleware.rate_limiter import RateLimiter


@pytest.fixture
def authenticator() -> Authenticator:
    return Authenticator(secret_key="test-secret-key-for-unit-tests")


@pytest.fixture
def authorization_engine() -> AuthorizationEngine:
    return AuthorizationEngine()


@pytest.fixture
def temp_db(tmp_path) -> str:
    db_path = str(tmp_path / "test_security.db")
    return db_path


@pytest.fixture
def store(temp_db) -> UserStore:
    return UserStore(db_path=temp_db)


@pytest.fixture
def audit_logger(store) -> AuditLogger:
    return AuditLogger(store=store)


@pytest.fixture
def api_key_manager(store) -> APIKeyManager:
    return APIKeyManager(store=store)


@pytest.fixture
def rate_limiter() -> RateLimiter:
    return RateLimiter(max_requests=5, window_seconds=60)


@pytest.fixture
def admin_user() -> User:
    return User(
        username="admin",
        email="admin@test.com",
        full_name="Admin User",
        hashed_password=Authenticator.hash_password("AdminP@ss123!"),
        status=UserStatus.ACTIVE,
        roles=["ml_admin"],
    )


@pytest.fixture
def viewer_user() -> User:
    return User(
        username="viewer",
        email="viewer@test.com",
        full_name="Viewer User",
        hashed_password=Authenticator.hash_password("ViewerP@ss123!"),
        status=UserStatus.ACTIVE,
        roles=["ml_viewer"],
    )


@pytest.fixture
def engineer_user() -> User:
    return User(
        username="engineer",
        email="engineer@test.com",
        full_name="ML Engineer",
        hashed_password=Authenticator.hash_password("EngineerP@ss123!"),
        status=UserStatus.ACTIVE,
        roles=["ml_engineer"],
    )


@pytest.fixture
def data_scientist_user() -> User:
    return User(
        username="datascientist",
        email="ds@test.com",
        full_name="Data Scientist",
        hashed_password=Authenticator.hash_password("DataSciP@ss123!"),
        status=UserStatus.ACTIVE,
        roles=["data_scientist"],
    )


@pytest.fixture
def sample_model_resource(admin_user) -> Resource:
    return Resource(
        name="test-model",
        resource_type=ResourceType.MODEL,
        owner_id=admin_user.id,
        access_level=AccessLevel.INTERNAL,
    )


@pytest.fixture
def sample_dataset_resource(data_scientist_user) -> Resource:
    return Resource(
        name="test-dataset",
        resource_type=ResourceType.DATASET,
        owner_id=data_scientist_user.id,
        access_level=AccessLevel.INTERNAL,
    )
