"""
OAuth provider registry for OIDC authentication.

Registers multiple identity providers (Entra ID, Okta) with automatic
OIDC discovery via server_metadata_url.
"""

from authlib.integrations.starlette_client import OAuth
from .config import settings


# Global OAuth registry
oauth = OAuth()


def init_oauth():
    """
    Initialize OAuth providers with OIDC discovery.

    Registers:
    - Entra ID (Microsoft) with automatic endpoint discovery
    - Okta with automatic endpoint discovery

    Both providers use server_metadata_url for automatic OIDC discovery,
    which fetches configuration from .well-known/openid-configuration endpoints.
    """
    # Register Microsoft Entra ID provider
    oauth.register(
        name='entra',
        client_id=settings.entra_client_id,
        client_secret=settings.entra_client_secret,
        server_metadata_url=settings.entra_discovery_url,
        client_kwargs={
            'scope': 'openid profile email'
        }
    )

    # Register Okta provider
    oauth.register(
        name='okta',
        client_id=settings.okta_client_id,
        client_secret=settings.okta_client_secret,
        server_metadata_url=settings.okta_discovery_url,
        client_kwargs={
            'scope': 'openid profile email'
        }
    )
