"""
Resource and permission domain models.

Defines ML platform resources (models, datasets, experiments, endpoints)
and the permission model for controlling access.

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class ResourceType(str, Enum):
    """Types of ML platform resources."""

    MODEL = "model"
    DATASET = "dataset"
    EXPERIMENT = "experiment"
    ENDPOINT = "endpoint"
    PIPELINE = "pipeline"
    ARTIFACT = "artifact"
    REPORT = "report"


class Permission(str, Enum):
    """Granular action permissions for resources."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"


class AccessLevel(str, Enum):
    """Access level classification for resources."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# Maps resource types to valid permissions
RESOURCE_PERMISSION_MATRIX: dict[ResourceType, set[Permission]] = {
    ResourceType.MODEL: {
        Permission.READ,
        Permission.WRITE,
        Permission.EXECUTE,
        Permission.DELETE,
        Permission.ADMIN,
    },
    ResourceType.DATASET: {
        Permission.READ,
        Permission.WRITE,
        Permission.DELETE,
        Permission.ADMIN,
    },
    ResourceType.EXPERIMENT: {
        Permission.READ,
        Permission.WRITE,
        Permission.EXECUTE,
        Permission.DELETE,
        Permission.ADMIN,
    },
    ResourceType.ENDPOINT: {
        Permission.READ,
        Permission.WRITE,
        Permission.EXECUTE,
        Permission.DELETE,
        Permission.ADMIN,
    },
    ResourceType.PIPELINE: {
        Permission.READ,
        Permission.WRITE,
        Permission.EXECUTE,
        Permission.DELETE,
        Permission.ADMIN,
    },
    ResourceType.ARTIFACT: {
        Permission.READ,
        Permission.WRITE,
        Permission.DELETE,
    },
    ResourceType.REPORT: {
        Permission.READ,
        Permission.WRITE,
        Permission.DELETE,
    },
}


@dataclass
class Resource:
    """
    ML platform resource entity.

    Represents any managed asset in the ML platform that requires
    access control: models, datasets, experiments, endpoints, etc.

    Attributes:
        id: Unique resource identifier.
        name: Human-readable resource name.
        resource_type: Type classification.
        owner_id: User ID of the resource owner.
        access_level: Security classification.
        description: Resource description.
        tags: Searchable tags.
        parent_id: Parent resource ID for hierarchy.
        created_at: Creation timestamp.
        updated_at: Last modification timestamp.
        metadata: Flexible metadata store.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    resource_type: ResourceType = ResourceType.MODEL
    owner_id: str = ""
    access_level: AccessLevel = AccessLevel.INTERNAL
    description: str = ""
    tags: list[str] = field(default_factory=list)
    parent_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)

    @property
    def permission_key(self) -> str:
        """Generate the base permission key for this resource type."""
        return self.resource_type.value

    def get_valid_permissions(self) -> set[Permission]:
        """Return the set of valid permissions for this resource type."""
        return RESOURCE_PERMISSION_MATRIX.get(self.resource_type, set())

    def format_permission(self, action: Permission) -> str:
        """
        Format a fully-qualified permission string.

        Example: 'model:read', 'dataset:write'
        """
        return f"{self.resource_type.value}:{action.value}"

    def is_valid_action(self, action: Permission) -> bool:
        """Check whether a given action is valid for this resource type."""
        return action in self.get_valid_permissions()

    def to_dict(self) -> dict:
        """Serialize resource to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "resource_type": self.resource_type.value,
            "owner_id": self.owner_id,
            "access_level": self.access_level.value,
            "description": self.description,
            "tags": self.tags,
            "parent_id": self.parent_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class AccessRequest:
    """
    Represents an access request to be evaluated by the permission engine.

    Attributes:
        user_id: Requesting user ID.
        resource_id: Target resource ID.
        resource_type: Type of the resource.
        action: Requested action.
        context: Additional context (IP, timestamp, etc.).
    """

    user_id: str = ""
    resource_id: str = ""
    resource_type: ResourceType = ResourceType.MODEL
    action: Permission = Permission.READ
    context: dict = field(default_factory=dict)

    @property
    def permission_string(self) -> str:
        """Generate permission string for this request."""
        return f"{self.resource_type.value}:{self.action.value}"
