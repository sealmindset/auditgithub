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
import httpx

logger = logging.getLogger(__name__)

# Global OAuth registry
oauth = OAuth()

# Startup health check results — populated by verify_oidc_providers()
oidc_health: dict = {}


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


async def verify_oidc_providers() -> dict:
    """
    Verify all configured OIDC providers are reachable and return valid discovery documents.

    Checks each provider's discovery URL and validates the response contains
    required OIDC fields (issuer, authorization_endpoint, token_endpoint, jwks_uri).

    Returns:
        dict: Per-provider health status with details on any failures.
              {
                "provider_name": {
                    "status": "healthy" | "unreachable" | "invalid_config" | "not_configured",
                    "discovery_url": "...",
                    "error": "..." (only on failure),
                    "issuer": "..." (only on success),
                }
              }
    """
    global oidc_health
    providers = settings.oidc_providers
    results = {}

    if not providers:
        results["_summary"] = "no_providers_configured"
        oidc_health = results
        return results

    required_fields = {"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for provider_config in providers:
            name = provider_config["name"]
            discovery_url = provider_config["discovery_url"]
            entry = {"discovery_url": discovery_url}

            if not discovery_url:
                entry["status"] = "invalid_config"
                entry["error"] = "Discovery URL is empty — check environment variables"
                results[name] = entry
                continue

            try:
                resp = await client.get(discovery_url)
                resp.raise_for_status()
                doc = resp.json()

                # Validate required OIDC fields
                missing = required_fields - set(doc.keys())
                if missing:
                    entry["status"] = "invalid_config"
                    entry["error"] = (
                        f"Discovery document missing required fields: {', '.join(sorted(missing))}. "
                        "This is an OIDC provider configuration issue, not an AGH code issue."
                    )
                else:
                    entry["status"] = "healthy"
                    entry["issuer"] = doc.get("issuer", "")

                    # Validate JWKS endpoint is also reachable
                    try:
                        jwks_resp = await client.get(doc["jwks_uri"])
                        jwks_resp.raise_for_status()
                        jwks_data = jwks_resp.json()
                        if "keys" not in jwks_data or not jwks_data["keys"]:
                            entry["status"] = "invalid_config"
                            entry["error"] = (
                                f"JWKS endpoint ({doc['jwks_uri']}) returned no keys. "
                                "OIDC provider may not have signing keys configured."
                            )
                    except httpx.HTTPError as jwks_err:
                        entry["status"] = "unreachable"
                        entry["error"] = (
                            f"Discovery OK but JWKS endpoint unreachable: {doc['jwks_uri']} — {jwks_err}. "
                            "Check network connectivity to the OIDC provider's JWKS endpoint."
                        )

            except httpx.ConnectError as e:
                entry["status"] = "unreachable"
                entry["error"] = (
                    f"Cannot connect to OIDC discovery URL: {discovery_url} — {e}. "
                    "Check that the OIDC provider is running and the URL is correct."
                )
            except httpx.TimeoutException:
                entry["status"] = "unreachable"
                entry["error"] = (
                    f"Timeout connecting to OIDC discovery URL: {discovery_url}. "
                    "The OIDC provider may be down or unreachable from this network."
                )
            except httpx.HTTPStatusError as e:
                entry["status"] = "unreachable"
                entry["error"] = (
                    f"OIDC discovery URL returned HTTP {e.response.status_code}: {discovery_url}. "
                    "Check the provider configuration and that the URL is correct."
                )
            except Exception as e:
                entry["status"] = "unreachable"
                entry["error"] = f"Unexpected error checking OIDC provider: {type(e).__name__}: {e}"

            results[name] = entry

            # Log the result
            if entry["status"] == "healthy":
                logger.info(f"OIDC provider '{name}' is healthy (issuer: {entry.get('issuer', 'N/A')})")
            else:
                logger.error(f"OIDC provider '{name}' check FAILED: {entry['error']}")

    # Summary
    statuses = [v["status"] for k, v in results.items() if k != "_summary"]
    if all(s == "healthy" for s in statuses):
        results["_summary"] = "all_healthy"
    elif any(s == "healthy" for s in statuses):
        results["_summary"] = "partial"
    else:
        results["_summary"] = "all_failed"

    oidc_health = results
    return results
