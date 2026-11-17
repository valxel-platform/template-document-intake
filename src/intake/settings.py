"""Settings, from the environment (prefix INTAKE_). Auth has no defaults: without an issuer the
service refuses to start rather than take documents from anyone."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="INTAKE_")

    config_path: str = "intake.yaml"
    contracts_dir: str = "contracts"
    environment: str = "dev"
    product: str = ""
    port: int = 8080
    # Callers: the IdP's JWT access tokens (audience = this service), the scopes for each kind of
    # access, and the claim naming the caller's tenants. Every document belongs to one tenant.
    oidc_issuer: str = ""
    oidc_jwks_url: str = ""
    audience: str = "document-intake"
    upload_scope: str = "documents:write"
    read_scope: str = "documents:read"
    review_scope: str = "documents:review"
    tenant_claim: str = "organization"
    rate_per_minute: int = 60
    rate_burst: int = 20
    # Storage: "s3" (deployed) or "memory" (local and tests). Uploads land in quarantine; only
    # scanned, checked files move to the clean bucket, encrypted with the product's KMS key.
    storage: str = "memory"
    quarantine_bucket: str = ""
    clean_bucket: str = ""
    kms_key_id: str = ""
    upload_url_ttl_s: int = 300
    download_url_ttl_s: int = 60
    # Malware scanning: "clamd" (deployed: the platform's ClamAV) or "none" (local only).
    scanner: str = "none"
    clamd_host: str = "clamav.platform-security.svc.cluster.local"
    clamd_port: int = 3310
    # Extraction through the product's LLM gateway (it decides which models the data class allows).
    gateway_url: str = ""
    gateway_key: str = ""
    extraction_model: str = ""
    database_url: str = ""
    kafka_bootstrap: str = ""
    kafka_config: dict[str, str] = {}
    audit_sink: str = "log"
    audit_kafka_bootstrap: str = ""
    audit_topic: str = "audit.v1"
    audit_kafka_config: dict[str, str] = {}
    audit_required: bool | None = None
    flags_url: str = ""
    flags_environment: str = ""
    flags_namespace: str = ""
    flags_token: str = ""
    flags_timeout_s: float = 0.25
    flags_cache_s: float = 30.0
