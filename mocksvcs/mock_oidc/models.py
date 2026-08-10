"""Pydantic request/response schemas for the mock OIDC server."""

from __future__ import annotations

from pydantic import BaseModel, Field


# ---- Client Schemas ----

class ClientCreate(BaseModel):
    client_id: str | None = None
    client_secret: str | None = None
    redirect_uris: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(default_factory=lambda: ["authorization_code"])
    response_types: list[str] = Field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: str = "client_secret_post"
    scope: str = "openid profile email"


class ClientUpdate(BaseModel):
    client_secret: str | None = None
    redirect_uris: list[str] | None = None
    grant_types: list[str] | None = None
    response_types: list[str] | None = None
    token_endpoint_auth_method: str | None = None
    scope: str | None = None


# ---- User Schemas ----

class UserCreate(BaseModel):
    sub: str
    email: str | None = None
    name: str | None = None
    email_verified: bool = True
    preferred_username: str | None = None


class UserUpdate(BaseModel):
    email: str | None = None
    name: str | None = None
    email_verified: bool | None = None
    preferred_username: str | None = None


# ---- Token Schemas ----

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str = "openid profile email"


class TokenIntrospectResponse(BaseModel):
    active: bool
    sub: str | None = None
    client_id: str | None = None
    scope: str | None = None
    token_type: str | None = None
    exp: int | None = None


# ---- Health ----

class HealthResponse(BaseModel):
    status: str = "healthy"
    service: str = "mock-oidc"
    version: str = "0.1.0"
    clients: int = 0
    users: int = 0
