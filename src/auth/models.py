"""
User model for authentication.

Represents an authenticated user with identity information from OIDC provider.
"""

from pydantic import BaseModel


class User(BaseModel):
    """
    Authenticated user model.

    Fields:
        email: User's email address from OIDC claims
        name: User's display name from OIDC claims
        sub: Subject claim (unique user ID from identity provider)
        provider: Identity provider name ("entra" or "okta")

    Usage:
        user = User(
            email="user@example.com",
            name="John Doe",
            sub="00u1234567890abcdef",
            provider="okta"
        )
    """

    email: str
    name: str
    sub: str  # Subject claim (unique user ID)
    provider: str  # "entra" or "okta"
    role: str = "user"  # RBAC role from session (super_admin, admin, manager, analyst, user)
    access_type: str = "both"  # ui_only, api_only, both
