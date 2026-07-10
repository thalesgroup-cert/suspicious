"""
Pydantic schema for /app/settings.json (M8).

Validation runs at Django boot from suspicious.settings. The goal is to
turn typos / missing required keys into a hard, clearly-explained
startup failure rather than a vague AttributeError or KeyError at the
first call site that needs the value.

The schema mirrors the dict shape of settings.json. Unknown keys are
allowed at every level so older or experimental sections do not block a
deploy. Required values are limited to those the codebase actually
crashes without (SECRET_KEY, the primary DB credentials).
"""

from __future__ import annotations

from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Sub-schemas
# ---------------------------------------------------------------------------


class _Permissive(BaseModel):
    """Allow unknown keys without rejecting the document."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)


class AppConfig(_Permissive):
    secret_key: str = Field(..., min_length=16, description="Django SECRET_KEY")
    debug: bool = False
    allowed_hosts: List[str] = Field(default_factory=lambda: ["localhost"])
    csrf_trusted_origins: List[str] = Field(
        default_factory=lambda: ["https://localhost"]
    )

    @field_validator("secret_key")
    @classmethod
    def _reject_placeholder(cls, value: str) -> str:
        sentinels = {"changeme", "placeholder", "secret", "django-insecure"}
        lowered = value.lower()
        if any(s in lowered for s in sentinels) and len(value) < 50:
            raise ValueError(
                "secret_key looks like a placeholder. Generate a real one "
                "with `python -c 'import secrets; print(secrets.token_urlsafe(64))'`."
            )
        return value


class DatabaseReplicaConfig(_Permissive):
    host: Optional[str] = None
    port: Optional[Any] = None
    name: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None


class DatabaseConfig(_Permissive):
    name: str = Field(..., min_length=1)
    user: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    host: str = "localhost"
    port: Any = "3306"
    options: dict = Field(default_factory=dict)
    replica: Optional[DatabaseReplicaConfig] = None
    replica_read_apps: Optional[List[str]] = None


class LdapConfig(_Permissive):
    server_uri: Optional[str] = None
    base_dn: Optional[str] = None


class OidcConfig(_Permissive):
    enabled: bool = False


class AuthenticationConfig(_Permissive):
    ldap: LdapConfig = Field(default_factory=LdapConfig)
    oidc: OidcConfig = Field(default_factory=OidcConfig)


class S3Config(_Permissive):
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    endpoint_url: Optional[str] = None
    bucket_name: Optional[str] = None
    fast_metadata: bool = False


class StorageConfig(_Permissive):
    s3: S3Config = Field(default_factory=S3Config)


class CortexIntegrationConfig(_Permissive):
    url: Optional[str] = None
    api_key: Optional[str] = None
    webhook_secret: str = ""


class ChromaDbIntegrationConfig(_Permissive):
    host: Optional[str] = None


class IntegrationsConfig(_Permissive):
    cortex: CortexIntegrationConfig = Field(default_factory=CortexIntegrationConfig)
    chromadb: ChromaDbIntegrationConfig = Field(default_factory=ChromaDbIntegrationConfig)


class FeaturesConfig(_Permissive):
    pass


class EmailConfig(_Permissive):
    pass


class RedisConfig(_Permissive):
    cache_host: str = "redis_cache"
    broker_host: str = "redis_broker"


class OpenTelemetryConfig(_Permissive):
    enabled: bool = False


class ObservabilityConfig(_Permissive):
    opentelemetry: OpenTelemetryConfig = Field(default_factory=OpenTelemetryConfig)


# ---------------------------------------------------------------------------
# Top-level schema
# ---------------------------------------------------------------------------


class SuspiciousConfig(_Permissive):
    app: AppConfig
    database: DatabaseConfig
    authentication: AuthenticationConfig = Field(default_factory=AuthenticationConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    integrations: IntegrationsConfig = Field(default_factory=IntegrationsConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)


# ---------------------------------------------------------------------------
# Public helper
# ---------------------------------------------------------------------------


class ConfigValidationError(RuntimeError):
    """Raised when settings.json fails schema validation."""


def validate_config(raw: dict, source: str = "/app/settings.json") -> dict:
    """
    Validate a parsed settings.json document.

    Returns the validated config as a dict (same shape as the input, with
    defaults filled in). Raises ConfigValidationError with a human-readable
    message on failure so the deploy fails fast at boot rather than at the
    first call site that needs a missing key.
    """
    try:
        validated = SuspiciousConfig.model_validate(raw)
    except Exception as exc:
        raise ConfigValidationError(
            f"Invalid Suspicious configuration in {source}:\n{exc}"
        ) from exc

    return validated.model_dump(mode="python")
