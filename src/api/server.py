"""
FastAPI application for the ML Security RBAC Platform.

Endpoints:
    POST   /auth/register         - Register a new user
    POST   /auth/login            - Authenticate and receive JWT tokens
    POST   /auth/refresh          - Refresh an access token
    POST   /auth/api-keys         - Create an API key
    GET    /auth/api-keys         - List API keys for the current user
    DELETE /auth/api-keys/{hash}  - Revoke an API key

    GET    /users/me              - Current user profile
    GET    /users                 - List users (admin only)

    POST   /resources             - Create a resource
    GET    /resources             - List resources
    GET    /resources/{id}        - Get a resource
    PUT    /resources/{id}        - Update a resource
    DELETE /resources/{id}        - Delete a resource

    GET    /audit/logs            - Retrieve audit log entries

    GET    /health                - Health check

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional, Any

from fastapi import FastAPI, HTTPException, Depends, Request, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.auth.authenticator import Authenticator
from src.auth.authorization import AuthorizationEngine
from src.models.user import User, UserStatus
from src.models.resource import Resource, ResourceType, AccessLevel, Permission
from src.storage.user_store import UserStore
from src.audit.audit_logger import AuditLogger
from src.api_keys.manager import APIKeyManager
from src.middleware.rate_limiter import RateLimiter, RateLimitExceeded
from src.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Application singletons (created in ``create_app()``)
# ---------------------------------------------------------------------------

_store: Optional[UserStore] = None
_auth: Optional[Authenticator] = None
_authz: Optional[AuthorizationEngine] = None
_audit: Optional[AuditLogger] = None
_api_keys: Optional[APIKeyManager] = None
_limiter: Optional[RateLimiter] = None


# ---------------------------------------------------------------------------
# Pydantic request / response schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: str = Field(..., min_length=5, max_length=128)
    password: str = Field(..., min_length=8)
    full_name: str = Field(default="")
    roles: list[str] = Field(default_factory=lambda: ["ml_viewer"])


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class CreateResourceRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    resource_type: str = Field(..., description="model | dataset | experiment | endpoint")
    access_level: str = Field(default="internal")
    description: str = Field(default="")
    tags: list[str] = Field(default_factory=list)


class UpdateResourceRequest(BaseModel):
    name: Optional[str] = None
    access_level: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list[str]] = None


class CreateAPIKeyRequest(BaseModel):
    name: str = Field(default="default", max_length=128)
    scopes: list[str] = Field(default_factory=list)
    ttl_days: Optional[int] = Field(default=None, ge=1, le=365)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------

def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


async def _get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> User:
    """
    Extract and validate the current user from JWT or API key.
    """
    assert _auth is not None
    assert _store is not None
    assert _limiter is not None

    # Rate limit
    client_id = _get_client_ip(request)
    try:
        _limiter.check(client_id)
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail=str(exc),
            headers={"Retry-After": str(int(exc.retry_after) + 1)},
        )

    user: Optional[User] = None

    # Try JWT first
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        payload = _auth.validate_access_token(token)
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        user = _store.get_user_by_id(payload["sub"])

    # Fallback to API key
    elif x_api_key:
        assert _api_keys is not None
        record = _api_keys.validate_key(x_api_key)
        if record is None:
            raise HTTPException(status_code=401, detail="Invalid or expired API key")
        user = _store.get_user_by_id(record["user_id"])

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide Bearer token or X-API-Key header.",
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is not active")

    return user


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    db_path: str = "data/ml_security.db",
    jwt_secret: str = "change-me-in-production-use-256-bit-secret-key",
    rate_limit_requests: int = 120,
    rate_limit_window: int = 60,
) -> FastAPI:
    """
    Build and return the configured FastAPI application.
    """
    global _store, _auth, _authz, _audit, _api_keys, _limiter

    _store = UserStore(db_path=db_path)
    _auth = Authenticator(secret_key=jwt_secret)
    _authz = AuthorizationEngine()
    _audit = AuditLogger(store=_store)
    _api_keys = APIKeyManager(store=_store)
    _limiter = RateLimiter(max_requests=rate_limit_requests, window_seconds=rate_limit_window)

    app = FastAPI(
        title="ML Security RBAC Platform",
        description="Role-Based Access Control for Machine Learning systems",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- Health ------------------------------------------------------------

    @app.get("/health", tags=["system"])
    async def health_check():
        return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

    # -- Auth routes -------------------------------------------------------

    @app.post("/auth/register", tags=["auth"], status_code=201)
    async def register(body: RegisterRequest, request: Request):
        ip = _get_client_ip(request)

        if _store.get_user_by_username(body.username):
            raise HTTPException(status_code=409, detail="Username already exists")
        if _store.get_user_by_email(body.email):
            raise HTTPException(status_code=409, detail="Email already registered")

        valid, violations = Authenticator.validate_password_strength(body.password, min_length=8)
        if not valid:
            raise HTTPException(status_code=400, detail={"errors": violations})

        hashed = Authenticator.hash_password(body.password)
        user = User(
            username=body.username,
            email=body.email,
            full_name=body.full_name,
            hashed_password=hashed,
            status=UserStatus.ACTIVE,
            roles=body.roles,
            password_changed_at=datetime.now(timezone.utc),
        )
        _store.create_user(user)

        _audit.log_auth_event(
            user_id=user.id,
            username=user.username,
            event="register",
            ip_address=ip,
        )

        return {"message": "User registered", "user_id": user.id, "username": user.username}

    @app.post("/auth/login", response_model=TokenResponse, tags=["auth"])
    async def login(body: LoginRequest, request: Request):
        ip = _get_client_ip(request)
        user = _store.get_user_by_username(body.username)

        if user is None or not Authenticator.verify_password(body.password, user.hashed_password or ""):
            if user:
                locked = user.record_failed_login()
                _store.update_user(user)
                if locked:
                    _audit.log_auth_event(user.id, user.username, "account_locked", ip, False)
            _audit.log_auth_event(
                user_id=user.id if user else "unknown",
                username=body.username,
                event="login",
                ip_address=ip,
                success=False,
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is not active")

        user.record_login()
        _store.update_user(user)

        access = _auth.create_access_token(user.id, user.username, user.roles)
        refresh = _auth.create_refresh_token(user.id)

        _audit.log_auth_event(user.id, user.username, "login", ip, True)

        return TokenResponse(access_token=access, refresh_token=refresh)

    @app.post("/auth/refresh", tags=["auth"])
    async def refresh_token(body: RefreshRequest, request: Request):
        payload = _auth.validate_refresh_token(body.refresh_token)
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        user = _store.get_user_by_id(payload["sub"])
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")

        new_access = _auth.create_access_token(user.id, user.username, user.roles)
        return {"access_token": new_access, "token_type": "bearer"}

    # -- API key routes ----------------------------------------------------

    @app.post("/auth/api-keys", tags=["api-keys"], status_code=201)
    async def create_api_key(
        body: CreateAPIKeyRequest,
        request: Request,
        user: User = Depends(_get_current_user),
    ):
        result = _api_keys.create_key(
            user_id=user.id,
            name=body.name,
            scopes=body.scopes,
            ttl_days=body.ttl_days,
        )
        _audit.log(
            user.id, user.username, "api_key_create",
            ip_address=_get_client_ip(request),
            details={"key_prefix": result["key_prefix"]},
        )
        return result

    @app.get("/auth/api-keys", tags=["api-keys"])
    async def list_api_keys(user: User = Depends(_get_current_user)):
        return _api_keys.list_keys(user.id)

    @app.delete("/auth/api-keys/{key_hash}", tags=["api-keys"])
    async def revoke_api_key(
        key_hash: str,
        request: Request,
        user: User = Depends(_get_current_user),
    ):
        success = _api_keys.revoke_key_by_hash(key_hash)
        if not success:
            raise HTTPException(status_code=404, detail="API key not found")
        _audit.log(
            user.id, user.username, "api_key_revoke",
            ip_address=_get_client_ip(request),
            details={"key_hash": key_hash},
        )
        return {"message": "API key revoked"}

    # -- User routes -------------------------------------------------------

    @app.get("/users/me", tags=["users"])
    async def get_current_user_profile(user: User = Depends(_get_current_user)):
        return user.to_dict()

    @app.get("/users", tags=["users"])
    async def list_users(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        user: User = Depends(_get_current_user),
    ):
        result = _authz.check_permission_simple(user, "user", "read")
        # admins can list users
        is_admin = any(r == "ml_admin" for r in user.roles)
        if not is_admin and not result.allowed:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        users = _store.list_users(limit=limit, offset=offset)
        return [u.to_dict() for u in users]

    # -- Resource routes ---------------------------------------------------

    @app.post("/resources", tags=["resources"], status_code=201)
    async def create_resource(
        body: CreateResourceRequest,
        request: Request,
        user: User = Depends(_get_current_user),
    ):
        try:
            rtype = ResourceType(body.resource_type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid resource_type. Must be one of: {[t.value for t in ResourceType]}",
            )

        perm_check = _authz.check_permission_simple(user, body.resource_type, "write")
        if not perm_check.allowed:
            _audit.log_access(user.id, user.username, body.resource_type, "", "write", False, _get_client_ip(request), perm_check.reason)
            raise HTTPException(status_code=403, detail=perm_check.reason)

        try:
            alevel = AccessLevel(body.access_level)
        except ValueError:
            alevel = AccessLevel.INTERNAL

        resource = Resource(
            name=body.name,
            resource_type=rtype,
            owner_id=user.id,
            access_level=alevel,
            description=body.description,
            tags=body.tags,
        )
        _store.create_resource(resource)

        _audit.log_access(
            user.id, user.username, body.resource_type, resource.id,
            "create", True, _get_client_ip(request),
        )
        return resource.to_dict()

    @app.get("/resources", tags=["resources"])
    async def list_resources(
        resource_type: Optional[str] = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        user: User = Depends(_get_current_user),
    ):
        resources = _store.list_resources(resource_type=resource_type, limit=limit, offset=offset)
        return [r.to_dict() for r in resources]

    @app.get("/resources/{resource_id}", tags=["resources"])
    async def get_resource(
        resource_id: str,
        request: Request,
        user: User = Depends(_get_current_user),
    ):
        resource = _store.get_resource_by_id(resource_id)
        if resource is None:
            raise HTTPException(status_code=404, detail="Resource not found")

        perm = _authz.check_permission(user, resource, Permission.READ)
        if not perm.allowed:
            _audit.log_access(user.id, user.username, resource.resource_type.value, resource_id, "read", False, _get_client_ip(request), perm.reason)
            raise HTTPException(status_code=403, detail=perm.reason)

        _audit.log_access(user.id, user.username, resource.resource_type.value, resource_id, "read", True, _get_client_ip(request))
        return resource.to_dict()

    @app.put("/resources/{resource_id}", tags=["resources"])
    async def update_resource(
        resource_id: str,
        body: UpdateResourceRequest,
        request: Request,
        user: User = Depends(_get_current_user),
    ):
        resource = _store.get_resource_by_id(resource_id)
        if resource is None:
            raise HTTPException(status_code=404, detail="Resource not found")

        perm = _authz.check_permission(user, resource, Permission.WRITE)
        if not perm.allowed:
            _audit.log_access(user.id, user.username, resource.resource_type.value, resource_id, "write", False, _get_client_ip(request), perm.reason)
            raise HTTPException(status_code=403, detail=perm.reason)

        if body.name is not None:
            resource.name = body.name
        if body.access_level is not None:
            try:
                resource.access_level = AccessLevel(body.access_level)
            except ValueError:
                pass
        if body.description is not None:
            resource.description = body.description
        if body.tags is not None:
            resource.tags = body.tags

        _store.update_resource(resource)

        _audit.log_access(user.id, user.username, resource.resource_type.value, resource_id, "write", True, _get_client_ip(request))
        return resource.to_dict()

    @app.delete("/resources/{resource_id}", tags=["resources"])
    async def delete_resource(
        resource_id: str,
        request: Request,
        user: User = Depends(_get_current_user),
    ):
        resource = _store.get_resource_by_id(resource_id)
        if resource is None:
            raise HTTPException(status_code=404, detail="Resource not found")

        perm = _authz.check_permission(user, resource, Permission.DELETE)
        if not perm.allowed:
            _audit.log_access(user.id, user.username, resource.resource_type.value, resource_id, "delete", False, _get_client_ip(request), perm.reason)
            raise HTTPException(status_code=403, detail=perm.reason)

        _store.delete_resource(resource_id)

        _audit.log_access(user.id, user.username, resource.resource_type.value, resource_id, "delete", True, _get_client_ip(request))
        return {"message": "Resource deleted"}

    # -- Audit routes ------------------------------------------------------

    @app.get("/audit/logs", tags=["audit"])
    async def get_audit_logs(
        user_id: Optional[str] = Query(default=None),
        action: Optional[str] = Query(default=None),
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        user: User = Depends(_get_current_user),
    ):
        # Only admins and auditors can view audit logs
        allowed_roles = {"ml_admin", "auditor"}
        if not allowed_roles.intersection(user.roles):
            raise HTTPException(status_code=403, detail="Audit log access requires admin or auditor role")

        entries = _audit.get_entries(user_id=user_id, action=action, limit=limit)
        return entries

    return app


# ---------------------------------------------------------------------------
# Module-level app instance (for ``uvicorn src.api.server:app``)
# ---------------------------------------------------------------------------

app = create_app()
