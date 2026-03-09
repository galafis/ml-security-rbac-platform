"""
Unit tests for domain models (User, UserRole, Resource).

Author: Gabriel Demetrios Lafis
"""

from src.models.user import User, UserRole, UserStatus, ML_ROLE_TEMPLATES
from src.models.resource import Resource, ResourceType, Permission, AccessLevel
from src.models.role import get_role_template, create_custom_role


class TestUserRole:
    """Tests for the UserRole model."""

    def test_admin_has_wildcard(self):
        admin = ML_ROLE_TEMPLATES["ml_admin"]
        assert admin.has_permission("model:read")
        assert admin.has_permission("anything:whatever")

    def test_viewer_read_only(self):
        viewer = ML_ROLE_TEMPLATES["ml_viewer"]
        assert viewer.has_permission("model:read")
        assert not viewer.has_permission("model:write")

    def test_add_remove_permission(self):
        role = UserRole(name="custom")
        role.add_permission("model:read")
        assert role.has_permission("model:read")
        role.remove_permission("model:read")
        assert not role.has_permission("model:read")

    def test_to_dict(self):
        role = ML_ROLE_TEMPLATES["ml_viewer"]
        d = role.to_dict()
        assert d["name"] == "ml_viewer"
        assert "model:read" in d["permissions"]


class TestUser:
    """Tests for the User model."""

    def test_is_active_when_active(self):
        user = User(status=UserStatus.ACTIVE)
        assert user.is_active is True

    def test_is_not_active_when_locked(self):
        user = User(status=UserStatus.LOCKED)
        assert user.is_active is False

    def test_lock_and_unlock(self):
        user = User(status=UserStatus.ACTIVE)
        user.lock_account()
        assert user.is_locked is True
        user.unlock_account()
        assert user.is_active is True

    def test_failed_login_locks_after_threshold(self):
        user = User(status=UserStatus.ACTIVE)
        for _ in range(4):
            locked = user.record_failed_login(max_attempts=5)
            assert locked is False
        locked = user.record_failed_login(max_attempts=5)
        assert locked is True
        assert user.is_locked is True

    def test_to_dict_excludes_sensitive(self):
        user = User(username="test", email="test@test.com", status=UserStatus.ACTIVE)
        d = user.to_dict(include_sensitive=False)
        assert "failed_login_attempts" not in d
        d_sensitive = user.to_dict(include_sensitive=True)
        assert "failed_login_attempts" in d_sensitive


class TestResource:
    """Tests for the Resource model."""

    def test_permission_key(self):
        res = Resource(resource_type=ResourceType.MODEL)
        assert res.permission_key == "model"

    def test_format_permission(self):
        res = Resource(resource_type=ResourceType.DATASET)
        assert res.format_permission(Permission.WRITE) == "dataset:write"

    def test_is_valid_action(self):
        res = Resource(resource_type=ResourceType.ARTIFACT)
        assert res.is_valid_action(Permission.READ) is True
        assert res.is_valid_action(Permission.EXECUTE) is False


class TestRoleHelpers:
    """Tests for role.py helper functions."""

    def test_get_role_template_returns_copy(self):
        role = get_role_template("ml_admin")
        assert role is not None
        assert role.name == "ml_admin"
        # should be a different object
        assert role is not ML_ROLE_TEMPLATES["ml_admin"]

    def test_get_role_template_unknown_returns_none(self):
        assert get_role_template("nonexistent") is None

    def test_create_custom_role(self):
        role = create_custom_role(
            name="custom_analyst",
            description="Custom analyst role",
            permissions={"dataset:read", "report:write"},
            level=30,
        )
        assert role.name == "custom_analyst"
        assert role.is_system_role is False
        assert role.has_permission("dataset:read")
