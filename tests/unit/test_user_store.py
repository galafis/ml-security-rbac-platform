"""
Unit tests for the UserStore (SQLite persistence).

Author: Gabriel Demetrios Lafis
"""

from src.models.user import User, UserStatus
from src.models.resource import Resource, ResourceType, AccessLevel
from src.auth.authenticator import Authenticator


class TestUserCRUD:
    """Tests for user create / read / update / delete."""

    def test_create_and_retrieve_user(self, store):
        user = User(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            hashed_password=Authenticator.hash_password("P@ssw0rd!234"),
            status=UserStatus.ACTIVE,
            roles=["ml_viewer"],
        )
        store.create_user(user)

        retrieved = store.get_user_by_username("testuser")
        assert retrieved is not None
        assert retrieved.id == user.id
        assert retrieved.email == "test@example.com"
        assert retrieved.roles == ["ml_viewer"]

    def test_get_user_by_email(self, store):
        user = User(username="emailuser", email="email@test.com", status=UserStatus.ACTIVE)
        store.create_user(user)
        result = store.get_user_by_email("email@test.com")
        assert result is not None
        assert result.username == "emailuser"

    def test_get_nonexistent_user_returns_none(self, store):
        assert store.get_user_by_id("nonexistent-id") is None
        assert store.get_user_by_username("nonexistent") is None

    def test_update_user(self, store):
        user = User(username="updatable", email="up@test.com", status=UserStatus.ACTIVE)
        store.create_user(user)
        user.full_name = "Updated Name"
        user.roles = ["ml_engineer"]
        store.update_user(user)
        updated = store.get_user_by_id(user.id)
        assert updated is not None
        assert updated.full_name == "Updated Name"
        assert updated.roles == ["ml_engineer"]

    def test_delete_user(self, store):
        user = User(username="deletable", email="del@test.com", status=UserStatus.ACTIVE)
        store.create_user(user)
        assert store.delete_user(user.id) is True
        assert store.get_user_by_id(user.id) is None

    def test_list_users(self, store):
        for i in range(5):
            store.create_user(User(username=f"user{i}", email=f"u{i}@test.com", status=UserStatus.ACTIVE))
        users = store.list_users(limit=10)
        assert len(users) == 5


class TestResourceCRUD:
    """Tests for resource create / read / update / delete."""

    def test_create_and_retrieve_resource(self, store):
        res = Resource(
            name="my-model",
            resource_type=ResourceType.MODEL,
            owner_id="owner-1",
            access_level=AccessLevel.INTERNAL,
            tags=["production", "v2"],
        )
        store.create_resource(res)
        retrieved = store.get_resource_by_id(res.id)
        assert retrieved is not None
        assert retrieved.name == "my-model"
        assert retrieved.tags == ["production", "v2"]

    def test_list_resources_by_type(self, store):
        store.create_resource(Resource(name="m1", resource_type=ResourceType.MODEL, owner_id="o1"))
        store.create_resource(Resource(name="d1", resource_type=ResourceType.DATASET, owner_id="o1"))
        store.create_resource(Resource(name="m2", resource_type=ResourceType.MODEL, owner_id="o1"))

        models = store.list_resources(resource_type="model")
        assert len(models) == 2

    def test_delete_resource(self, store):
        res = Resource(name="deletable", resource_type=ResourceType.DATASET, owner_id="o1")
        store.create_resource(res)
        assert store.delete_resource(res.id) is True
        assert store.get_resource_by_id(res.id) is None
