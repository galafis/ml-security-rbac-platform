"""
Unit tests for the AuthorizationEngine (RBAC).

Author: Gabriel Demetrios Lafis
"""

from src.auth.authorization import AuthorizationEngine
from src.models.user import User, UserStatus
from src.models.resource import Resource, ResourceType, AccessLevel, Permission


class TestRBACPermissions:
    """Tests for role-based permission evaluation."""

    def test_admin_has_all_permissions(self, authorization_engine, admin_user, sample_model_resource):
        result = authorization_engine.check_permission(
            admin_user, sample_model_resource, Permission.DELETE
        )
        assert result.allowed is True

    def test_viewer_can_read(self, authorization_engine, viewer_user, sample_model_resource):
        result = authorization_engine.check_permission(
            viewer_user, sample_model_resource, Permission.READ
        )
        assert result.allowed is True

    def test_viewer_cannot_write(self, authorization_engine, viewer_user, sample_model_resource):
        result = authorization_engine.check_permission(
            viewer_user, sample_model_resource, Permission.WRITE
        )
        assert result.allowed is False

    def test_viewer_cannot_delete(self, authorization_engine, viewer_user, sample_model_resource):
        result = authorization_engine.check_permission(
            viewer_user, sample_model_resource, Permission.DELETE
        )
        assert result.allowed is False

    def test_engineer_can_write_model(self, authorization_engine, engineer_user, sample_model_resource):
        result = authorization_engine.check_permission(
            engineer_user, sample_model_resource, Permission.WRITE
        )
        assert result.allowed is True

    def test_engineer_can_execute_model(self, authorization_engine, engineer_user, sample_model_resource):
        result = authorization_engine.check_permission(
            engineer_user, sample_model_resource, Permission.EXECUTE
        )
        assert result.allowed is True

    def test_data_scientist_can_write_dataset(self, authorization_engine, data_scientist_user, sample_dataset_resource):
        result = authorization_engine.check_permission(
            data_scientist_user, sample_dataset_resource, Permission.WRITE
        )
        assert result.allowed is True

    def test_owner_has_full_access(self, authorization_engine, data_scientist_user, sample_dataset_resource):
        """Owner should have full access regardless of role."""
        result = authorization_engine.check_permission(
            data_scientist_user, sample_dataset_resource, Permission.DELETE
        )
        # data_scientist doesn't have dataset:delete, but is the owner
        assert result.allowed is True
        assert result.reason == "User is the resource owner"

    def test_inactive_user_denied(self, authorization_engine, sample_model_resource):
        inactive_user = User(
            username="inactive",
            email="inactive@test.com",
            status=UserStatus.INACTIVE,
            roles=["ml_admin"],
        )
        result = authorization_engine.check_permission(
            inactive_user, sample_model_resource, Permission.READ
        )
        assert result.allowed is False
        assert "not active" in result.reason

    def test_restricted_resource_needs_admin_permission(self, authorization_engine, viewer_user):
        restricted_res = Resource(
            name="secret-model",
            resource_type=ResourceType.MODEL,
            owner_id="other-owner",
            access_level=AccessLevel.RESTRICTED,
        )
        result = authorization_engine.check_permission(
            viewer_user, restricted_res, Permission.READ
        )
        # viewer has model:read but not model:admin needed for restricted
        assert result.allowed is False

    def test_admin_can_access_restricted(self, authorization_engine, admin_user):
        restricted_res = Resource(
            name="secret-model",
            resource_type=ResourceType.MODEL,
            owner_id="other-owner",
            access_level=AccessLevel.RESTRICTED,
        )
        result = authorization_engine.check_permission(
            admin_user, restricted_res, Permission.READ
        )
        assert result.allowed is True


class TestSimplePermissionCheck:
    """Tests for the string-based permission check."""

    def test_admin_simple_check(self, authorization_engine, admin_user):
        result = authorization_engine.check_permission_simple(
            admin_user, "model", "delete"
        )
        assert result.allowed is True

    def test_viewer_simple_check_read(self, authorization_engine, viewer_user):
        result = authorization_engine.check_permission_simple(
            viewer_user, "model", "read"
        )
        assert result.allowed is True

    def test_viewer_simple_check_write_denied(self, authorization_engine, viewer_user):
        result = authorization_engine.check_permission_simple(
            viewer_user, "model", "write"
        )
        assert result.allowed is False
