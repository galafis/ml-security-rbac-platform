#!/usr/bin/env python3
"""
ML Security RBAC Platform - Interactive Demo

Creates users with different roles, authenticates them, tests access control
decisions, and displays the resulting audit log.

Run:
    python main.py

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

import os
import sys
import textwrap

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.auth.authenticator import Authenticator
from src.auth.authorization import AuthorizationEngine, AuthorizationResult
from src.models.user import User, UserStatus
from src.models.resource import Resource, ResourceType, AccessLevel, Permission
from src.storage.user_store import UserStore
from src.audit.audit_logger import AuditLogger
from src.api_keys.manager import APIKeyManager
from src.middleware.rate_limiter import RateLimiter, RateLimitExceeded


SEPARATOR = "=" * 72


def _banner(title: str) -> None:
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


def _result_line(description: str, result: AuthorizationResult) -> None:
    icon = "[ALLOW]" if result.allowed else "[DENY] "
    print(f"  {icon} {description}")
    print(f"         Reason: {result.reason}")


def main() -> None:
    # ----- setup ----------------------------------------------------------
    db_path = "data/demo_security.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    store = UserStore(db_path=db_path)
    auth = Authenticator(secret_key="demo-secret-key-for-local-testing-only")
    authz = AuthorizationEngine()
    audit = AuditLogger(store=store)
    key_mgr = APIKeyManager(store=store)
    limiter = RateLimiter(max_requests=10, window_seconds=60)

    # ----- 1. Create users ------------------------------------------------
    _banner("1. Creating users with different roles")

    users_spec = [
        ("admin_alice", "alice@company.com", "Alice Admin", ["ml_admin"]),
        ("ds_bob", "bob@company.com", "Bob DataScientist", ["data_scientist"]),
        ("eng_carol", "carol@company.com", "Carol MLEngineer", ["ml_engineer"]),
        ("viewer_dave", "dave@company.com", "Dave Viewer", ["ml_viewer"]),
        ("auditor_eve", "eve@company.com", "Eve Auditor", ["auditor"]),
    ]

    created_users: dict[str, User] = {}
    for uname, email, full_name, roles in users_spec:
        pw_hash = auth.hash_password("SecureP@ss123!")
        user = User(
            username=uname,
            email=email,
            full_name=full_name,
            hashed_password=pw_hash,
            status=UserStatus.ACTIVE,
            roles=roles,
        )
        store.create_user(user)
        created_users[uname] = user
        print(f"  Created: {uname:16s} roles={roles}")

    # ----- 2. Authenticate ------------------------------------------------
    _banner("2. Authenticating users (JWT)")

    tokens: dict[str, str] = {}
    for uname in created_users:
        user = created_users[uname]
        ok = auth.verify_password("SecureP@ss123!", user.hashed_password or "")
        access = auth.create_access_token(user.id, user.username, user.roles)
        refresh = auth.create_refresh_token(user.id)
        tokens[uname] = access
        audit.log_auth_event(user.id, user.username, "login", success=ok)
        print(f"  {uname:16s} -> token={access[:30]}...")

    # ----- 3. Validate & refresh tokens -----------------------------------
    _banner("3. Token validation & refresh")

    sample_token = tokens["admin_alice"]
    payload = auth.validate_access_token(sample_token)
    print(f"  Validate admin_alice token: {'VALID' if payload else 'INVALID'}")
    if payload:
        print(f"    sub={payload['sub'][:12]}... roles={payload['roles']}")

    refresh = auth.create_refresh_token(created_users["admin_alice"].id)
    new_access = auth.refresh_access_token(refresh, "admin_alice", ["ml_admin"])
    print(f"  Refreshed token: {new_access[:30] if new_access else 'FAILED'}...")

    # ----- 4. Create resources --------------------------------------------
    _banner("4. Creating ML resources")

    resources_spec = [
        ("fraud-detection-v2", ResourceType.MODEL, "eng_carol", AccessLevel.CONFIDENTIAL),
        ("customer-transactions", ResourceType.DATASET, "ds_bob", AccessLevel.INTERNAL),
        ("hyperparameter-sweep", ResourceType.EXPERIMENT, "ds_bob", AccessLevel.INTERNAL),
        ("prediction-api", ResourceType.ENDPOINT, "eng_carol", AccessLevel.PUBLIC),
        ("credit-risk-model", ResourceType.MODEL, "admin_alice", AccessLevel.RESTRICTED),
    ]

    created_resources: dict[str, Resource] = {}
    for rname, rtype, owner_uname, alevel in resources_spec:
        res = Resource(
            name=rname,
            resource_type=rtype,
            owner_id=created_users[owner_uname].id,
            access_level=alevel,
            description=f"Demo resource: {rname}",
        )
        store.create_resource(res)
        created_resources[rname] = res
        print(f"  Created: {rname:25s} type={rtype.value:12s} level={alevel.value}")

    # ----- 5. Access control tests ----------------------------------------
    _banner("5. Testing RBAC access control")

    test_cases = [
        # (user, resource, action, description)
        ("admin_alice", "fraud-detection-v2", Permission.DELETE, "Admin deletes any model"),
        ("ds_bob", "customer-transactions", Permission.WRITE, "DS writes own dataset"),
        ("ds_bob", "fraud-detection-v2", Permission.WRITE, "DS writes someone else's model"),
        ("eng_carol", "prediction-api", Permission.EXECUTE, "Engineer executes own endpoint"),
        ("viewer_dave", "customer-transactions", Permission.READ, "Viewer reads dataset"),
        ("viewer_dave", "customer-transactions", Permission.WRITE, "Viewer tries to write dataset"),
        ("eng_carol", "hyperparameter-sweep", Permission.EXECUTE, "Engineer executes experiment"),
        ("viewer_dave", "fraud-detection-v2", Permission.DELETE, "Viewer tries to delete model"),
        ("ds_bob", "credit-risk-model", Permission.READ, "DS reads restricted model"),
        ("admin_alice", "credit-risk-model", Permission.READ, "Admin reads restricted model"),
    ]

    for uname, rname, action, desc in test_cases:
        user = created_users[uname]
        resource = created_resources[rname]
        result = authz.check_permission(user, resource, action)
        _result_line(desc, result)
        audit.log_access(
            user.id, user.username,
            resource.resource_type.value, resource.id,
            action.value, result.allowed,
            reason=result.reason,
        )

    # ----- 6. API key management ------------------------------------------
    _banner("6. API key management")

    key_result = key_mgr.create_key(
        user_id=created_users["eng_carol"].id,
        name="ci-pipeline-key",
        scopes=["model:read", "endpoint:execute"],
        ttl_days=90,
    )
    print(f"  Created API key: {key_result['key'][:20]}...")
    print(f"  Prefix: {key_result['key_prefix']}")

    validated = key_mgr.validate_key(key_result["key"])
    print(f"  Validated: {'OK' if validated else 'FAILED'}")

    keys = key_mgr.list_keys(created_users["eng_carol"].id)
    print(f"  Carol's keys: {len(keys)}")

    key_mgr.revoke_key(key_result["key"])
    validated_after = key_mgr.validate_key(key_result["key"])
    print(f"  After revocation: {'OK' if validated_after else 'REVOKED'}")

    # ----- 7. Rate limiter ------------------------------------------------
    _banner("7. Rate limiting demo")

    test_limiter = RateLimiter(max_requests=5, window_seconds=60)
    client_id = "demo-user"

    for i in range(7):
        allowed = test_limiter.allow(client_id)
        remaining = test_limiter.get_remaining(client_id)
        print(f"  Request {i+1}: {'ALLOWED' if allowed else 'BLOCKED':8s} (remaining={remaining})")

    # ----- 8. Audit log hash chain ----------------------------------------
    _banner("8. Audit log integrity verification")

    chain_valid = audit.verify_chain()
    print(f"  Hash chain integrity: {'VALID' if chain_valid else 'COMPROMISED'}")

    entries = audit.get_entries(limit=5)
    print(f"  Total audit entries: {len(audit._entries)}")
    print(f"  Last 5 entries:")
    for e in entries[:5]:
        print(f"    [{e.get('result', '?'):7s}] {e.get('username', '?'):16s} "
              f"{e.get('action', '?'):16s} {e.get('resource_type', '')}")

    # ----- Summary --------------------------------------------------------
    _banner("Demo Complete")
    print(textwrap.dedent("""\
        The ML Security RBAC Platform demo has completed successfully.

        To start the API server:
            uvicorn src.api.server:app --reload --port 8000

        Then interact via:
            POST http://localhost:8000/auth/register
            POST http://localhost:8000/auth/login
            GET  http://localhost:8000/users/me
            POST http://localhost:8000/resources
            GET  http://localhost:8000/audit/logs
    """))


if __name__ == "__main__":
    main()
