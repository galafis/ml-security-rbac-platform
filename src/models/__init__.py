"""
Data models for ML Security RBAC Platform.

Defines domain entities including users, roles, resources,
permissions, and audit events.

Author: Gabriel Demetrios Lafis
"""

from src.models.user import User, UserRole, UserStatus, ML_ROLE_TEMPLATES
from src.models.resource import (
    Resource,
    ResourceType,
    Permission,
    AccessLevel,
    AccessRequest,
)
from src.models.role import (
    ROLE_TEMPLATES,
    ROLE_HIERARCHY,
    get_role_template,
    create_custom_role,
)

__all__ = [
    "User",
    "UserRole",
    "UserStatus",
    "ML_ROLE_TEMPLATES",
    "Resource",
    "ResourceType",
    "Permission",
    "AccessLevel",
    "AccessRequest",
    "ROLE_TEMPLATES",
    "ROLE_HIERARCHY",
    "get_role_template",
    "create_custom_role",
]
