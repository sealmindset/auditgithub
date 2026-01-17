"""
Authentication configuration for OIDC providers.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Authentication settings for OIDC/SSO providers.

    Supports multiple identity providers:
    - Microsoft Entra ID (formerly Azure AD)
    - Okta

    Uses OIDC discovery (.well-known/openid-configuration) for automatic
    endpoint configuration.
    """

    # Session configuration
    session_secret: str

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
        # Add production frontend URL from environment if set
        import os
        if frontend_url := os.getenv("FRONTEND_URL"):
            if frontend_url not in self.cors_origins:
                self.cors_origins.append(frontend_url)

    @property
    def entra_discovery_url(self) -> str:
        """
        Return the OIDC discovery URL for Microsoft Entra ID.

        Format: https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration
        """
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0/.well-known/openid-configuration"

    @property
    def okta_discovery_url(self) -> str:
        """
        Return the OIDC discovery URL for Okta.

        Format: https://{domain}/.well-known/openid-configuration
        """
        return f"https://{self.okta_domain}/.well-known/openid-configuration"

    class Config:
        env_file = ".env"
        extra = "ignore"


# Singleton settings instance
settings = Settings()
