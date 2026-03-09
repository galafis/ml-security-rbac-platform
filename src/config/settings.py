"""
Application configuration management.

Centralized configuration using Pydantic settings with environment
variable support and hierarchical config structure.

Author: Gabriel Demetrios Lafis
"""

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class DatabaseConfig(BaseSettings):
    """PostgreSQL database configuration."""

    model_config = {"env_prefix": "DB_"}

    host: str = Field(default="localhost", description="Database host")
    port: int = Field(default=5432, description="Database port")
    name: str = Field(default="ml_security_rbac", description="Database name")
    user: str = Field(default="postgres", description="Database user")
    password: str = Field(default="postgres", description="Database password")
    pool_size: int = Field(default=10, description="Connection pool size")
    max_overflow: int = Field(default=20, description="Max overflow connections")
    echo: bool = Field(default=False, description="Echo SQL statements")

    @property
    def url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.name}"
        )

    @property
    def sync_url(self) -> str:
        return (
            f"postgresql://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.name}"
        )


class AuthConfig(BaseSettings):
    """Authentication configuration."""

    model_config = {"env_prefix": "AUTH_"}

    jwt_secret_key: str = Field(
        default="change-me-in-production-use-256-bit-secret-key",
        description="JWT signing secret (HMAC-SHA256)",
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=30, description="Access token TTL in minutes"
    )
    refresh_token_expire_days: int = Field(
        default=7, description="Refresh token TTL in days"
    )
    password_min_length: int = Field(default=12, description="Minimum password length")
    password_require_uppercase: bool = Field(default=True)
    password_require_lowercase: bool = Field(default=True)
    password_require_digit: bool = Field(default=True)
    password_require_special: bool = Field(default=True)
    password_max_age_days: int = Field(
        default=90, description="Password rotation interval"
    )
    max_login_attempts: int = Field(default=5, description="Lockout threshold")
    lockout_duration_minutes: int = Field(default=30, description="Account lockout time")
    bcrypt_rounds: int = Field(default=12, description="bcrypt work factor")

    # Azure AD / OIDC SSO
    azure_tenant_id: str = Field(default="", description="Azure AD tenant ID")
    azure_client_id: str = Field(default="", description="Azure AD client ID")
    azure_client_secret: str = Field(default="", description="Azure AD client secret")
    azure_redirect_uri: str = Field(
        default="http://localhost:8000/api/v1/auth/sso/callback",
        description="OAuth2 redirect URI",
    )
    azure_authority: str = Field(default="", description="Azure AD authority URL")

    @property
    def azure_authority_url(self) -> str:
        if self.azure_authority:
            return self.azure_authority
        return f"https://login.microsoftonline.com/{self.azure_tenant_id}"


class RBACConfig(BaseSettings):
    """Role-based access control configuration."""

    model_config = {"env_prefix": "RBAC_"}

    enable_hierarchical_roles: bool = Field(
        default=True, description="Enable role hierarchy"
    )
    max_roles_per_user: int = Field(default=10, description="Max roles per user")
    cache_ttl_seconds: int = Field(
        default=300, description="Permission cache TTL"
    )
    default_role: str = Field(
        default="ml_viewer", description="Default role for new users"
    )


class AuditConfig(BaseSettings):
    """Audit logging configuration."""

    model_config = {"env_prefix": "AUDIT_"}

    enable_hash_chain: bool = Field(
        default=True, description="Enable tamper-detection hash chain"
    )
    retention_days: int = Field(default=365, description="Audit log retention")
    batch_size: int = Field(default=100, description="Batch write size")
    enable_anomaly_detection: bool = Field(
        default=True, description="Enable access anomaly detection"
    )
    anomaly_threshold: float = Field(
        default=2.0, description="Standard deviations for anomaly"
    )


class EncryptionConfig(BaseSettings):
    """Encryption configuration."""

    model_config = {"env_prefix": "ENCRYPTION_"}

    master_key: str = Field(
        default="change-me-use-a-base64-encoded-256-bit-key-here",
        description="Base64-encoded master encryption key",
    )
    key_rotation_days: int = Field(default=90, description="Key rotation interval")
    algorithm: str = Field(default="AES-256-GCM", description="Encryption algorithm")
    key_derivation_iterations: int = Field(
        default=100_000, description="PBKDF2 iterations"
    )


class RedisConfig(BaseSettings):
    """Redis configuration for caching and token blacklist."""

    model_config = {"env_prefix": "REDIS_"}

    host: str = Field(default="localhost", description="Redis host")
    port: int = Field(default=6379, description="Redis port")
    password: Optional[str] = Field(default=None, description="Redis password")
    db: int = Field(default=0, description="Redis database number")
    ssl: bool = Field(default=False, description="Use TLS")

    @property
    def url(self) -> str:
        auth = f":{self.password}@" if self.password else ""
        scheme = "rediss" if self.ssl else "redis"
        return f"{scheme}://{auth}{self.host}:{self.port}/{self.db}"


class SecurityConfig(BaseSettings):
    """Root security configuration aggregating all sub-configs."""

    model_config = {"env_prefix": "SECURITY_"}

    app_name: str = Field(
        default="ML Security RBAC Platform", description="Application name"
    )
    app_version: str = Field(default="1.0.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    environment: str = Field(default="development", description="Environment name")
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="CORS allowed origins",
    )
    log_level: str = Field(default="INFO", description="Application log level")

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    rbac: RBACConfig = Field(default_factory=RBACConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    encryption: EncryptionConfig = Field(default_factory=EncryptionConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)


@lru_cache(maxsize=1)
def get_settings() -> SecurityConfig:
    """Get cached application settings singleton."""
    return SecurityConfig()
