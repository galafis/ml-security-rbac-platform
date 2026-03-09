"""
Role-Based Access Control (RBAC) authorization engine.

Evaluates access requests against user roles and resource permissions,
supporting role hierarchy, resource ownership, and access-level checks.

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from src.models.user import User, UserRole, ML_ROLE_TEMPLATES
from src.models.resource import (
    Resource,
    Permission,
    AccessLevel,
    AccessRequest,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AuthorizationResult:
    """Outcome of an authorization check."""

    allowed: bool
    reason: str
    matched_role: Optional[str] = None
    matched_permission: Optional[str] = None


class AuthorizationEngine:
    """
    Core RBAC engine that evaluates access requests.

    Features:
        - Role hierarchy (parent roles inherit child permissions).
        - Resource ownership bypass (owners get full access).
        - Access-level restrictions (public, internal, confidential, restricted).
        - Wildcard permission support (``*`` grants everything).
    """

    def __init__(
        self,
        role_registry: Optional[dict[str, UserRole]] = None,
        enable_hierarchy: bool = True,
    ) -> None:
        self._roles: dict[str, UserRole] = role_registry or dict(ML_ROLE_TEMPLATES)
        self._enable_hierarchy = enable_hierarchy

    # -- public API --------------------------------------------------------

    def check_permission(
        self,
        user: User,
        resource: Resource,
        action: Permission,
    ) -> AuthorizationResult:
        """
        Determine whether *user* is allowed to perform *action* on *resource*.
        """
        # 1. User must be active
        if not user.is_active:
            return AuthorizationResult(
                allowed=False,
                reason="User account is not active",
            )

        # 2. Validate action is valid for resource type
        if not resource.is_valid_action(action):
            return AuthorizationResult(
                allowed=False,
                reason=f"Action '{action.value}' is not valid for resource type '{resource.resource_type.value}'",
            )

        # 3. Owner has full access to their own resources
        if resource.owner_id and resource.owner_id == user.id:
            return AuthorizationResult(
                allowed=True,
                reason="User is the resource owner",
                matched_role="owner",
                matched_permission=f"{resource.resource_type.value}:*",
            )

        # 4. Build required permission string
        required = resource.format_permission(action)

        # 5. Evaluate each role assigned to the user
        for role_name in user.roles:
            effective_permissions = self._get_effective_permissions(role_name)
            if self._permission_matches(required, effective_permissions):
                # 5a. Access-level gate: restricted resources need admin
                if resource.access_level == AccessLevel.RESTRICTED:
                    admin_perm = f"{resource.resource_type.value}:admin"
                    if not self._permission_matches(admin_perm, effective_permissions):
                        continue  # this role doesn't unlock restricted

                return AuthorizationResult(
                    allowed=True,
                    reason=f"Permission '{required}' granted via role '{role_name}'",
                    matched_role=role_name,
                    matched_permission=required,
                )

        return AuthorizationResult(
            allowed=False,
            reason=f"No role grants permission '{required}'",
        )

    def check_permission_simple(
        self,
        user: User,
        resource_type: str,
        action: str,
    ) -> AuthorizationResult:
        """
        Simplified permission check using string resource type and action.
        """
        if not user.is_active:
            return AuthorizationResult(allowed=False, reason="User account is not active")

        required = f"{resource_type}:{action}"

        for role_name in user.roles:
            effective_permissions = self._get_effective_permissions(role_name)
            if self._permission_matches(required, effective_permissions):
                return AuthorizationResult(
                    allowed=True,
                    reason=f"Permission '{required}' granted via role '{role_name}'",
                    matched_role=role_name,
                    matched_permission=required,
                )

        return AuthorizationResult(
            allowed=False,
            reason=f"No role grants permission '{required}'",
        )

    def evaluate_request(self, request: AccessRequest, user: User, resource: Resource) -> AuthorizationResult:
        """Evaluate an ``AccessRequest`` object."""
        return self.check_permission(user, resource, request.action)

    # -- role management ---------------------------------------------------

    def register_role(self, role: UserRole) -> None:
        """Register (or update) a role in the engine's registry."""
        self._roles[role.name] = role

    def get_role(self, name: str) -> Optional[UserRole]:
        return self._roles.get(name)

    def list_roles(self) -> list[UserRole]:
        return list(self._roles.values())

    # -- internal helpers --------------------------------------------------

    def _get_effective_permissions(self, role_name: str) -> set[str]:
        """
        Resolve all permissions for a role, including inherited ones.
        """
        visited: set[str] = set()
        permissions: set[str] = set()
        self._collect_permissions(role_name, permissions, visited)
        return permissions

    def _collect_permissions(
        self,
        role_name: str,
        permissions: set[str],
        visited: set[str],
    ) -> None:
        if role_name in visited:
            return
        visited.add(role_name)
        role = self._roles.get(role_name)
        if role is None:
            return
        permissions.update(role.permissions)

        if self._enable_hierarchy and role.parent_role:
            self._collect_permissions(role.parent_role, permissions, visited)

    @staticmethod
    def _permission_matches(required: str, available: set[str]) -> bool:
        """
        Check if *required* is satisfied by the *available* permission set.

        Supports wildcards: ``*`` matches everything, ``model:*`` matches
        any model action, etc.
        """
        if "*" in available:
            return True
        if required in available:
            return True
        parts = required.split(":")
        if len(parts) == 2:
            wildcard = f"{parts[0]}:*"
            if wildcard in available:
                return True
        return False
