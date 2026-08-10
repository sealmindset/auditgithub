"""Configuration for the mock OIDC server."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class MockOIDCSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MOCK_OIDC_",
        extra="ignore",
    )

    # Server
    host: str = "0.0.0.0"
    port: int = 10090

    # Issuer URLs (split for Docker networking)
    # Browser-facing base URL (authorization endpoint, logout)
    external_base_url: str = "http://localhost:3007"
    # Container-facing base URL (token, userinfo, jwks)
    internal_base_url: str = "http://mock-oidc:10090"

    # Default client credentials
    default_client_id: str = "mock-oidc-client"
    default_client_secret: str = "mock-oidc-secret"

    # Token lifetimes (seconds)
    access_token_lifetime: int = 3600       # 1 hour
    id_token_lifetime: int = 3600           # 1 hour
    refresh_token_lifetime: int = 86400     # 24 hours
    auth_code_lifetime: int = 600           # 10 minutes

    # Security (relaxed for local dev)
    strict_redirect_uri: bool = False
    require_client_secret: bool = False


settings = MockOIDCSettings()
