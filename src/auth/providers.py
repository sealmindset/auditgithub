"""
OAuth provider registry for OIDC authentication.

Dynamically registers identity providers based on environment configuration:
- Generic OIDC provider (mock-oidc for development)
- Entra ID (Microsoft) with automatic endpoint discovery
- Okta with automatic endpoint discovery

Providers are only registered when their credentials are configured.
"""

from authlib.integrations.starlette_client import OAuth
from .config import settings
import logging

logger = logging.getLogger(__name__)

# Global OAuth registry
oauth = OAuth()


def init_oauth():
    """
    Initialize OAuth providers dynamically from configuration.

    Registers providers based on which environment variables are set:
    - OIDC_PROVIDER_NAME + OIDC_CLIENT_ID → generic provider (mock-oidc, etc.)
    - ENTRA_CLIENT_ID + ENTRA_TENANT_ID → Microsoft Entra ID
    - OKTA_CLIENT_ID + OKTA_DOMAIN → Okta

    Both production providers use server_metadata_url for automatic OIDC discovery,
    which fetches configuration from .well-known/openid-configuration endpoints.
    """
    providers = settings.oidc_providers

    if not providers:
        logger.warning("No OIDC providers configured. Authentication will rely on API keys or AUTH_DISABLED bypass.")
        return

    for provider_config in providers:
        name = provider_config["name"]
        try:
            oauth.register(
                name=name,
                client_id=provider_config["client_id"],
                client_secret=provider_config["client_secret"],
                server_metadata_url=provider_config["discovery_url"],
                client_kwargs={
                    'scope': 'openid profile email'
                }
            )
            logger.info(f"Registered OIDC provider: {name} (discovery: {provider_config['discovery_url']})")
        except Exception as e:
            logger.error(f"Failed to register OIDC provider '{name}': {e}")

    logger.info(f"OIDC providers registered: {settings.registered_provider_names}")
