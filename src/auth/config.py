"""
Authentication configuration for OIDC providers.

Supports dynamic provider registration:
- Generic OIDC provider (mock-oidc for development, or any OIDC-compliant IdP)
- Microsoft Entra ID (formerly Azure AD)
- Okta

Providers are registered based on which environment variables are set.
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """
    Authentication settings for OIDC/SSO providers.

    Supports multiple identity providers with dynamic registration.
    Providers are only registered when their credentials are configured.
    Uses OIDC discovery (.well-known/openid-configuration) for automatic
    endpoint configuration.
    """

    # Session configuration
    session_secret: str

    # Generic OIDC provider (mock-oidc in dev, or any single OIDC provider)
    oidc_provider_name: str = ""          # e.g., "mock-oidc"
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_discovery_url: str = ""          # Internal URL (container-to-container)
    oidc_external_base_url: str = ""      # External URL (browser-facing)

    # Entra ID (Microsoft) configuration
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_tenant_id: str = ""

    # Okta configuration
    okta_client_id: str = ""
    okta_client_secret: str = ""
    okta_domain: str = ""  # e.g., "dev-12345.okta.com"

    # JWT token configuration
    jwt_secret_key: str = ""  # Secret key for signing tokens (HS256)
    refresh_token_expire_days: int = 7  # Refresh token lifetime (7 days)
    access_token_expire_minutes: int = 60  # Access token lifetime (1 hour)

    # Redis configuration
    redis_url: str = "redis://redis:6379/0"  # Redis connection URL

    # Session timeout configuration
    session_absolute_timeout_hours: int = 8  # Maximum session lifetime (8 hours)
    session_idle_timeout_minutes: int = 30   # Idle timeout (30 minutes)

    # CORS configuration
    cors_origins: list[str] = [
        "http://localhost:3000",  # Next.js dev server
        "http://localhost:3001",  # Alternative dev port
        "http://localhost:8001",  # Sandbox API
        "http://localhost:8080",  # Swagger Editor
    ]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    cors_allow_headers: list[str] = [
        "Authorization",
        "Content-Type",
        "X-Organization-ID",
        "X-Organization-Name",
        "X-Tenant-ID"
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        import os
        # Add production frontend URL from environment if set
        if frontend_url := os.getenv("FRONTEND_URL"):
            if frontend_url not in self.cors_origins:
                self.cors_origins.append(frontend_url)
        # Add mock OIDC external URL to CORS origins if set
        if self.oidc_external_base_url and self.oidc_external_base_url not in self.cors_origins:
            self.cors_origins.append(self.oidc_external_base_url)

    @property
    def entra_discovery_url(self) -> str:
        """Return the OIDC discovery URL for Microsoft Entra ID."""
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0/.well-known/openid-configuration"

    @property
    def okta_discovery_url(self) -> str:
        """Return the OIDC discovery URL for Okta."""
        return f"https://{self.okta_domain}/.well-known/openid-configuration"

    @property
    def oidc_providers(self) -> list[dict]:
        """Build the list of OIDC providers from environment variables.

        Returns a list of provider config dicts. Only providers with
        valid credentials are included.
        """
        providers = []

        # Register generic OIDC provider (mock-oidc in dev, or any provider)
        if self.oidc_provider_name and self.oidc_client_id:
            providers.append({
                "name": self.oidc_provider_name,
                "client_id": self.oidc_client_id,
                "client_secret": self.oidc_client_secret,
                "discovery_url": self.oidc_discovery_url,
                "external_base_url": self.oidc_external_base_url,
            })

        # Register Entra ID if configured
        if self.entra_client_id and self.entra_tenant_id:
            providers.append({
                "name": "entra",
                "client_id": self.entra_client_id,
                "client_secret": self.entra_client_secret,
                "discovery_url": self.entra_discovery_url,
                "external_base_url": "",
            })

        # Register Okta if configured
        if self.okta_client_id and self.okta_domain:
            providers.append({
                "name": "okta",
                "client_id": self.okta_client_id,
                "client_secret": self.okta_client_secret,
                "discovery_url": self.okta_discovery_url,
                "external_base_url": "",
            })

        return providers

    @property
    def registered_provider_names(self) -> list[str]:
        """Return list of registered provider names for whitelist validation."""
        return [p["name"] for p in self.oidc_providers]

    def get_provider_config(self, name: str) -> Optional[dict]:
        """Get configuration for a specific provider by name."""
        return next((p for p in self.oidc_providers if p["name"] == name), None)

    class Config:
        env_file = ".env"
        extra = "ignore"


# Singleton settings instance
settings = Settings()
