"""
Integration tests for the FastAPI server.

Author: Gabriel Demetrios Lafis
"""

import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.api.server import create_app


@pytest.fixture
def client(tmp_path):
    db_path = str(tmp_path / "test_api.db")
    app = create_app(db_path=db_path, jwt_secret="test-api-secret")
    return TestClient(app)


@pytest.fixture
def registered_user(client):
    """Register a user and return (client, user_data, tokens)."""
    reg_resp = client.post("/auth/register", json={
        "username": "apiuser",
        "email": "api@test.com",
        "password": "SecureP@ss123!",
        "full_name": "API User",
        "roles": ["ml_admin"],
    })
    assert reg_resp.status_code == 201

    login_resp = client.post("/auth/login", json={
        "username": "apiuser",
        "password": "SecureP@ss123!",
    })
    assert login_resp.status_code == 200
    tokens = login_resp.json()
    return tokens


class TestHealthEndpoint:

    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


class TestAuthEndpoints:

    def test_register_user(self, client):
        resp = client.post("/auth/register", json={
            "username": "newuser",
            "email": "new@test.com",
            "password": "N3wP@ssword!",
            "full_name": "New User",
        })
        assert resp.status_code == 201
        assert resp.json()["username"] == "newuser"

    def test_register_duplicate_username(self, client):
        client.post("/auth/register", json={
            "username": "dupuser", "email": "dup1@test.com", "password": "P@ssw0rd!234",
        })
        resp = client.post("/auth/register", json={
            "username": "dupuser", "email": "dup2@test.com", "password": "P@ssw0rd!234",
        })
        assert resp.status_code == 409

    def test_login_success(self, client):
        client.post("/auth/register", json={
            "username": "loginuser", "email": "login@test.com", "password": "L0gin!Pass#",
        })
        resp = client.post("/auth/login", json={
            "username": "loginuser", "password": "L0gin!Pass#",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

    def test_login_wrong_password(self, client):
        client.post("/auth/register", json={
            "username": "failuser", "email": "fail@test.com", "password": "C0rrect!Pass",
        })
        resp = client.post("/auth/login", json={
            "username": "failuser", "password": "Wrong!Pass1",
        })
        assert resp.status_code == 401

    def test_get_current_user(self, client, registered_user):
        resp = client.get("/users/me", headers={
            "Authorization": f"Bearer {registered_user['access_token']}",
        })
        assert resp.status_code == 200
        assert resp.json()["username"] == "apiuser"


class TestResourceEndpoints:

    def test_create_resource(self, client, registered_user):
        resp = client.post("/resources", json={
            "name": "test-model",
            "resource_type": "model",
            "description": "A test model",
        }, headers={"Authorization": f"Bearer {registered_user['access_token']}"})
        assert resp.status_code == 201
        assert resp.json()["name"] == "test-model"

    def test_list_resources(self, client, registered_user):
        headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
        client.post("/resources", json={
            "name": "r1", "resource_type": "model",
        }, headers=headers)
        client.post("/resources", json={
            "name": "r2", "resource_type": "dataset",
        }, headers=headers)
        resp = client.get("/resources", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_unauthenticated_request_rejected(self, client):
        resp = client.get("/users/me")
        assert resp.status_code == 401
