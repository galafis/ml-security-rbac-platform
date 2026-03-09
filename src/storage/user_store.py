"""
SQLite-backed storage for users, roles, resources, and API keys.

Provides CRUD operations with connection pooling, automatic schema
creation, and JSON-serialised complex fields (roles, permissions, tags).

Author: Gabriel Demetrios Lafis
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.models.user import User, UserStatus
from src.models.resource import Resource, ResourceType, AccessLevel
from src.utils.logger import get_logger

logger = get_logger(__name__)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT UNIQUE NOT NULL,
    email           TEXT UNIQUE NOT NULL,
    full_name       TEXT NOT NULL DEFAULT '',
    hashed_password TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    roles           TEXT NOT NULL DEFAULT '[]',
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    last_login      TEXT,
    password_changed_at TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    mfa_enabled     INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS resources (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    owner_id        TEXT NOT NULL,
    access_level    TEXT NOT NULL DEFAULT 'internal',
    description     TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '[]',
    parent_id       TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    metadata        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash    TEXT PRIMARY KEY,
    key_prefix  TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    scopes      TEXT NOT NULL DEFAULT '[]',
    is_active   INTEGER NOT NULL DEFAULT 1,
    expires_at  TEXT,
    created_at  TEXT NOT NULL,
    last_used   TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    username    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    result      TEXT NOT NULL DEFAULT 'allow',
    ip_address  TEXT NOT NULL DEFAULT '',
    details     TEXT NOT NULL DEFAULT '{}',
    hash_chain  TEXT NOT NULL DEFAULT ''
);
"""


class UserStore:
    """
    SQLite-backed persistence for the ML Security RBAC Platform.

    Thread-safe via a reentrant lock and ``check_same_thread=False``.
    """

    def __init__(self, db_path: str = "data/ml_security.db") -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # -- lifecycle ---------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript(_SCHEMA_SQL)
                conn.commit()
            finally:
                conn.close()

    # ======================================================================
    # USER CRUD
    # ======================================================================

    def create_user(self, user: User) -> User:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO users
                        (id, username, email, full_name, hashed_password, status,
                         roles, failed_login_attempts, last_login,
                         password_changed_at, created_at, updated_at,
                         mfa_enabled, metadata)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        user.id,
                        user.username,
                        user.email,
                        user.full_name,
                        user.hashed_password,
                        user.status.value,
                        json.dumps(user.roles),
                        user.failed_login_attempts,
                        user.last_login.isoformat() if user.last_login else None,
                        user.password_changed_at.isoformat() if user.password_changed_at else None,
                        user.created_at.isoformat(),
                        user.updated_at.isoformat(),
                        int(user.mfa_enabled),
                        json.dumps(user.metadata),
                    ),
                )
                conn.commit()
                return user
            finally:
                conn.close()

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                return self._row_to_user(row) if row else None
            finally:
                conn.close()

    def get_user_by_username(self, username: str) -> Optional[User]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                return self._row_to_user(row) if row else None
            finally:
                conn.close()

    def get_user_by_email(self, email: str) -> Optional[User]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                return self._row_to_user(row) if row else None
            finally:
                conn.close()

    def update_user(self, user: User) -> User:
        user.updated_at = datetime.now(timezone.utc)
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    UPDATE users SET
                        username=?, email=?, full_name=?, hashed_password=?,
                        status=?, roles=?, failed_login_attempts=?,
                        last_login=?, password_changed_at=?, updated_at=?,
                        mfa_enabled=?, metadata=?
                    WHERE id=?
                    """,
                    (
                        user.username,
                        user.email,
                        user.full_name,
                        user.hashed_password,
                        user.status.value,
                        json.dumps(user.roles),
                        user.failed_login_attempts,
                        user.last_login.isoformat() if user.last_login else None,
                        user.password_changed_at.isoformat() if user.password_changed_at else None,
                        user.updated_at.isoformat(),
                        int(user.mfa_enabled),
                        json.dumps(user.metadata),
                        user.id,
                    ),
                )
                conn.commit()
                return user
            finally:
                conn.close()

    def delete_user(self, user_id: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute("DELETE FROM users WHERE id=?", (user_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def list_users(self, limit: int = 100, offset: int = 0) -> list[User]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
                return [self._row_to_user(r) for r in rows]
            finally:
                conn.close()

    # ======================================================================
    # RESOURCE CRUD
    # ======================================================================

    def create_resource(self, resource: Resource) -> Resource:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO resources
                        (id, name, resource_type, owner_id, access_level,
                         description, tags, parent_id, created_at, updated_at, metadata)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        resource.id,
                        resource.name,
                        resource.resource_type.value,
                        resource.owner_id,
                        resource.access_level.value,
                        resource.description,
                        json.dumps(resource.tags),
                        resource.parent_id,
                        resource.created_at.isoformat(),
                        resource.updated_at.isoformat(),
                        json.dumps(resource.metadata),
                    ),
                )
                conn.commit()
                return resource
            finally:
                conn.close()

    def get_resource_by_id(self, resource_id: str) -> Optional[Resource]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute("SELECT * FROM resources WHERE id=?", (resource_id,)).fetchone()
                return self._row_to_resource(row) if row else None
            finally:
                conn.close()

    def list_resources(
        self,
        resource_type: Optional[str] = None,
        owner_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Resource]:
        with self._lock:
            conn = self._get_conn()
            try:
                query = "SELECT * FROM resources WHERE 1=1"
                params: list = []
                if resource_type:
                    query += " AND resource_type=?"
                    params.append(resource_type)
                if owner_id:
                    query += " AND owner_id=?"
                    params.append(owner_id)
                query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_resource(r) for r in rows]
            finally:
                conn.close()

    def update_resource(self, resource: Resource) -> Resource:
        resource.updated_at = datetime.now(timezone.utc)
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    UPDATE resources SET
                        name=?, resource_type=?, owner_id=?, access_level=?,
                        description=?, tags=?, parent_id=?, updated_at=?, metadata=?
                    WHERE id=?
                    """,
                    (
                        resource.name,
                        resource.resource_type.value,
                        resource.owner_id,
                        resource.access_level.value,
                        resource.description,
                        json.dumps(resource.tags),
                        resource.parent_id,
                        resource.updated_at.isoformat(),
                        json.dumps(resource.metadata),
                        resource.id,
                    ),
                )
                conn.commit()
                return resource
            finally:
                conn.close()

    def delete_resource(self, resource_id: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute("DELETE FROM resources WHERE id=?", (resource_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # ======================================================================
    # API KEY storage
    # ======================================================================

    def store_api_key(
        self,
        key_hash: str,
        key_prefix: str,
        user_id: str,
        name: str,
        scopes: list[str],
        expires_at: Optional[datetime] = None,
    ) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO api_keys
                        (key_hash, key_prefix, user_id, name, scopes,
                         is_active, expires_at, created_at)
                    VALUES (?,?,?,?,?,1,?,?)
                    """,
                    (
                        key_hash,
                        key_prefix,
                        user_id,
                        name,
                        json.dumps(scopes),
                        expires_at.isoformat() if expires_at else None,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def get_api_key_record(self, key_hash: str) -> Optional[dict]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute("SELECT * FROM api_keys WHERE key_hash=?", (key_hash,)).fetchone()
                if row is None:
                    return None
                return dict(row)
            finally:
                conn.close()

    def revoke_api_key(self, key_hash: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    "UPDATE api_keys SET is_active=0 WHERE key_hash=?", (key_hash,)
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def list_api_keys_for_user(self, user_id: str) -> list[dict]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT key_hash, key_prefix, name, scopes, is_active, expires_at, created_at, last_used "
                    "FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
                    (user_id,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def update_api_key_last_used(self, key_hash: str) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE api_keys SET last_used=? WHERE key_hash=?",
                    (datetime.now(timezone.utc).isoformat(), key_hash),
                )
                conn.commit()
            finally:
                conn.close()

    # ======================================================================
    # AUDIT LOG storage
    # ======================================================================

    def insert_audit_entry(
        self,
        user_id: str,
        username: str,
        action: str,
        resource_type: str,
        resource_id: str,
        result: str,
        ip_address: str,
        details: dict,
        hash_chain: str = "",
    ) -> int:
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    """
                    INSERT INTO audit_log
                        (timestamp, user_id, username, action, resource_type,
                         resource_id, result, ip_address, details, hash_chain)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        datetime.now(timezone.utc).isoformat(),
                        user_id,
                        username,
                        action,
                        resource_type,
                        resource_id,
                        result,
                        ip_address,
                        json.dumps(details),
                        hash_chain,
                    ),
                )
                conn.commit()
                return cur.lastrowid or 0
            finally:
                conn.close()

    def get_audit_logs(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        with self._lock:
            conn = self._get_conn()
            try:
                query = "SELECT * FROM audit_log WHERE 1=1"
                params: list = []
                if user_id:
                    query += " AND user_id=?"
                    params.append(user_id)
                if action:
                    query += " AND action=?"
                    params.append(action)
                query += " ORDER BY id DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                rows = conn.execute(query, params).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ======================================================================
    # Row -> Model helpers
    # ======================================================================

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> User:
        def _parse_dt(val: Optional[str]) -> Optional[datetime]:
            if val is None:
                return None
            return datetime.fromisoformat(val)

        return User(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            full_name=row["full_name"],
            hashed_password=row["hashed_password"],
            status=UserStatus(row["status"]),
            roles=json.loads(row["roles"]),
            failed_login_attempts=row["failed_login_attempts"],
            last_login=_parse_dt(row["last_login"]),
            password_changed_at=_parse_dt(row["password_changed_at"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            mfa_enabled=bool(row["mfa_enabled"]),
            metadata=json.loads(row["metadata"]),
        )

    @staticmethod
    def _row_to_resource(row: sqlite3.Row) -> Resource:
        return Resource(
            id=row["id"],
            name=row["name"],
            resource_type=ResourceType(row["resource_type"]),
            owner_id=row["owner_id"],
            access_level=AccessLevel(row["access_level"]),
            description=row["description"],
            tags=json.loads(row["tags"]),
            parent_id=row["parent_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=json.loads(row["metadata"]),
        )
