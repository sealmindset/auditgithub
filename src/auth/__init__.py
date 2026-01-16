"""
AuditGitHub Authentication Module

Provides OIDC/SSO authentication with support for multiple identity providers
(Entra ID and Okta).
"""

from .providers import oauth, init_oauth
from .dependencies import get_current_user

__all__ = ['oauth', 'init_oauth', 'get_current_user']
