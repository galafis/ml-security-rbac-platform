"""
User and role domain models.

Provides dataclass-based representations for users, roles, and
their relationships within the ML security platform.

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class UserStatus(str, Enum):
    """User account status enumeration."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING = "pending"
    SUSPENDED = "suspended"


@dataclass
class UserRole:
    """
    Role definition with hierarchical permission support.

    Roles follow a hierarchy where higher-level roles inherit
    all permissions from lower-level roles in the chain.

    Attributes:
        id: Unique role identifier.
        name: Human-readable role name.
        description: Role description.
        permissions: Set of permission strings (e.g., 'model:read').
        parent_role: Parent role name for hierarchy inheritance.
        level: Hierarchy level (higher = more privileges).
        is_system_role: Whether this is a built-in system role.
        created_at: Role creation timestamp.
        metadata: Additional role metadata.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    permissions: set[str] = field(default_factory=set)
    parent_role: Optional[str] = None
    level: int = 0
    is_system_role: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)

    def has_permission(self, permission: str) -> bool:
        """Check if role has a specific permission."""
        if "*" in self.permissions:
            return True
        parts = permission.split(":")
        if len(parts) == 2:
            wildcard = f"{parts[0]}:*"
            if wildcard in self.permissions:
                return True
        return permission in self.permissions

    def add_permission(self, permission: str) -> None:
        """Add a permission to this role."""
        self.permissions.add(permission)

    def remove_permission(self, permission: str) -> None:
        """Remove a permission from this role."""
        self.permissions.discard(permission)

    def to_dict(self) -> dict:
        """Serialize role to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "permissions": sorted(self.permissions),
            "parent_role": self.parent_role,
            "level": self.level,
            "is_system_role": self.is_system_role,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }


# Pre-defined ML team role templates
ML_ROLE_TEMPLATES: dict[str, UserRole] = {
    "ml_admin": UserRole(
        name="ml_admin",
        description="ML Platform Administrator with full access",
        permissions={
            "*",
        },
        level=100,
        is_system_role=True,
    ),
    "ml_engineer": UserRole(
        name="ml_engineer",
        description="ML Engineer - train, deploy, manage models",
        permissions={
            "model:read",
            "model:write",
            "model:execute",
            "dataset:read",
            "dataset:write",
            "experiment:read",
            "experiment:write",
            "experiment:execute",
            "endpoint:read",
            "endpoint:write",
            "endpoint:execute",
        },
        parent_role="ml_viewer",
        level=60,
        is_system_role=True,
    ),
    "data_scientist": UserRole(
        name="data_scientist",
        description="Data Scientist - experiment and analyze",
        permissions={
            "model:read",
            "model:write",
            "dataset:read",
            "dataset:write",
            "experiment:read",
            "experiment:write",
            "experiment:execute",
            "endpoint:read",
        },
        parent_role="ml_viewer",
        level=50,
        is_system_role=True,
    ),
    "ml_ops": UserRole(
        name="ml_ops",
        description="MLOps Engineer - deploy and monitor",
        permissions={
            "model:read",
            "model:execute",
            "endpoint:read",
            "endpoint:write",
            "endpoint:execute",
            "endpoint:admin",
            "experiment:read",
        },
        parent_role="ml_viewer",
        level=55,
        is_system_role=True,
    ),
    "ml_viewer": UserRole(
        name="ml_viewer",
        description="ML Viewer - read-only access",
        permissions={
            "model:read",
            "dataset:read",
            "experiment:read",
            "endpoint:read",
        },
        level=10,
        is_system_role=True,
    ),
    "auditor": UserRole(
        name="auditor",
        description="Security Auditor - audit and compliance access",
        permissions={
            "audit:read",
            "model:read",
            "dataset:read",
            "experiment:read",
            "endpoint:read",
            "report:read",
            "report:write",
        },
        level=40,
        is_system_role=True,
    ),
}


@dataclass
class User:
    """
    User entity for the ML Security platform.

    Attributes:
        id: Unique user identifier (UUID).
        username: Unique username.
        email: User email address.
        full_name: Display name.
        hashed_password: bcrypt-hashed password.
        status: Account status.
        roles: Assigned roles.
        sso_provider: External SSO provider name.
        sso_subject: External SSO subject identifier.
        failed_login_attempts: Consecutive failed logins.
        last_login: Last successful login timestamp.
        password_changed_at: Last password change.
        created_at: Account creation timestamp.
        updated_at: Last update timestamp.
        mfa_enabled: Whether MFA is active.
        metadata: Additional user metadata.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: str = ""
    email: str = ""
    full_name: str = ""
    hashed_password: Optional[str] = None
    status: UserStatus = UserStatus.PENDING
    roles: list[str] = field(default_factory=list)
    sso_provider: Optional[str] = None
    sso_subject: Optional[str] = None
    failed_login_attempts: int = 0
    last_login: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    mfa_enabled: bool = False
    metadata: dict = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return self.status == UserStatus.ACTIVE

    @property
    def is_locked(self) -> bool:
        return self.status == UserStatus.LOCKED

    @property
    def is_sso_user(self) -> bool:
        return self.sso_provider is not None

    def lock_account(self) -> None:
        """Lock the user account after failed login attempts."""
        self.status = UserStatus.LOCKED
        self.updated_at = datetime.now(timezone.utc)

    def unlock_account(self) -> None:
        """Unlock the user account."""
        self.status = UserStatus.ACTIVE
        self.failed_login_attempts = 0
        self.updated_at = datetime.now(timezone.utc)

    def record_login(self) -> None:
        """Record a successful login."""
        self.last_login = datetime.now(timezone.utc)
        self.failed_login_attempts = 0
        self.updated_at = datetime.now(timezone.utc)

    def record_failed_login(self, max_attempts: int = 5) -> bool:
        """
        Record a failed login attempt.

        Returns:
            True if account should be locked.
        """
        self.failed_login_attempts += 1
        self.updated_at = datetime.now(timezone.utc)
        if self.failed_login_attempts >= max_attempts:
            self.lock_account()
            return True
        return False

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Serialize user to dictionary."""
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "status": self.status.value,
            "roles": self.roles,
            "sso_provider": self.sso_provider,
            "mfa_enabled": self.mfa_enabled,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if include_sensitive:
            data["failed_login_attempts"] = self.failed_login_attempts
            data["sso_subject"] = self.sso_subject
            data["metadata"] = self.metadata
        return data
