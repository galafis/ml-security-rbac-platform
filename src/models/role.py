"""
Predefined role definitions for the ML Security RBAC Platform.

Provides convenience factories and constants for the built-in roles:
Admin, DataScientist, MLEngineer, MLOps, Viewer, Auditor.

The actual ``UserRole`` dataclass lives in ``src.models.user`` and is
re-exported here for convenience.

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

from src.models.user import UserRole, ML_ROLE_TEMPLATES

# Re-export the template registry
ROLE_TEMPLATES = ML_ROLE_TEMPLATES

# Convenient constants
ADMIN = ML_ROLE_TEMPLATES["ml_admin"]
DATA_SCIENTIST = ML_ROLE_TEMPLATES["data_scientist"]
ML_ENGINEER = ML_ROLE_TEMPLATES["ml_engineer"]
ML_OPS = ML_ROLE_TEMPLATES["ml_ops"]
VIEWER = ML_ROLE_TEMPLATES["ml_viewer"]
AUDITOR = ML_ROLE_TEMPLATES["auditor"]

# Ordered hierarchy (highest privilege first)
ROLE_HIERARCHY: list[str] = [
    "ml_admin",
    "ml_engineer",
    "ml_ops",
    "data_scientist",
    "auditor",
    "ml_viewer",
]


def get_role_template(name: str) -> UserRole | None:
    """Return a *copy* of a built-in role template, or ``None``."""
    template = ML_ROLE_TEMPLATES.get(name)
    if template is None:
        return None
    return UserRole(
        name=template.name,
        description=template.description,
        permissions=set(template.permissions),
        parent_role=template.parent_role,
        level=template.level,
        is_system_role=template.is_system_role,
    )


def create_custom_role(
    name: str,
    description: str,
    permissions: set[str],
    parent_role: str | None = None,
    level: int = 20,
) -> UserRole:
    """Create a new custom (non-system) role."""
    return UserRole(
        name=name,
        description=description,
        permissions=permissions,
        parent_role=parent_role,
        level=level,
        is_system_role=False,
    )
