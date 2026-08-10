"""FastAPI application entry point for mock OIDC server."""

from fastapi import FastAPI

from mock_oidc.crypto import KeyPair
from mock_oidc.routes.authorize import create_authorize_router
from mock_oidc.routes.clients import create_clients_router
from mock_oidc.routes.debug import create_debug_router
from mock_oidc.routes.discovery import create_discovery_router
from mock_oidc.routes.health import create_health_router
from mock_oidc.routes.jwks import create_jwks_router
from mock_oidc.routes.logout import create_logout_router
from mock_oidc.routes.token import create_token_router
from mock_oidc.routes.userinfo import create_userinfo_router
from mock_oidc.routes.users import create_users_router
from mock_oidc.store import OIDCStore

store = OIDCStore()
key_pair = KeyPair()

app = FastAPI(
    title="Mock OIDC Server",
    version="0.1.0",
    description="Lightweight mock OIDC/OAuth2 server for Zapper local development.",
)

app.include_router(create_discovery_router(store))
app.include_router(create_authorize_router(store))
app.include_router(create_token_router(store, key_pair))
app.include_router(create_userinfo_router(store))
app.include_router(create_jwks_router(key_pair))
app.include_router(create_clients_router(store))
app.include_router(create_users_router(store))
app.include_router(create_logout_router(store))
app.include_router(create_health_router(store))
app.include_router(create_debug_router(store))
