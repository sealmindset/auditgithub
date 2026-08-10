"""In-memory store for users, clients, auth codes, and tokens."""

from __future__ import annotations

import secrets
import threading
import time
from typing import Any

from mock_oidc.config import settings


class OIDCStore:
    """Thread-safe in-memory store for the mock OIDC server.

    Manages clients, users, authorization codes, and issued tokens.
    Pre-seeds a default client and three test users on initialization.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Clients: {client_id: {client_id, client_secret, redirect_uris, grant_types, ...}}
        self._clients: dict[str, dict[str, Any]] = {}

        # Users: {sub: {sub, email, name, ...}}
        self._users: dict[str, dict[str, Any]] = {}

        # Auth codes: {code: {client_id, sub, redirect_uri, scope, nonce, created_at}}
        self._auth_codes: dict[str, dict[str, Any]] = {}

        # Tokens: {token_hash: {sub, client_id, scope, token_type, created_at, expires_at}}
        self._tokens: dict[str, dict[str, Any]] = {}

        # Refresh tokens: {refresh_token: {sub, client_id, scope, created_at, expires_at}}
        self._refresh_tokens: dict[str, dict[str, Any]] = {}

        self._seed()

    def _seed(self) -> None:
        """Pre-seed default client and test users."""
        self._clients[settings.default_client_id] = {
            "client_id": settings.default_client_id,
            "client_secret": settings.default_client_secret,
            "redirect_uris": [
                "http://localhost:3000/api/proxy/auth/callback/mock-oidc",
                "http://localhost:3000/api/auth/callback",
                "http://localhost:3001/api/v1/auth/callback",
            ],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": "openid profile email",
        }

        for user in [
            {"sub": "mock-super-admin", "email": "ravance@gmail.com", "name": "Rob Vance (Super Admin)"},
            {"sub": "mock-admin", "email": "rob.vance@sleepnumber.com", "name": "Rob Vance (Admin)"},
            {"sub": "mock-superadmin-zapper", "email": "superadmin@zapper.local", "name": "Super Admin"},
            {"sub": "mock-admin-zapper", "email": "admin@zapper.local", "name": "Mock Admin"},
            {"sub": "mock-manager", "email": "manager@auditgithub.local", "name": "Mock Manager"},
            {"sub": "mock-manager-zapper", "email": "manager@zapper.local", "name": "Mock Manager (Zapper)"},
            {"sub": "mock-analyst", "email": "analyst@auditgithub.local", "name": "Mock Analyst"},
            {"sub": "mock-analyst-zapper", "email": "analyst@zapper.local", "name": "Mock Analyst (Zapper)"},
            {"sub": "mock-user", "email": "user@auditgithub.local", "name": "Mock User"},
            {"sub": "mock-user-zapper", "email": "user@zapper.local", "name": "Mock User (Zapper)"},
        ]:
            self._users[user["sub"]] = {
                **user,
                "email_verified": True,
                "preferred_username": user["email"],
            }

    # ---- Clients ----

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._clients.get(client_id)

    def list_clients(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._clients.values())

    def create_client(self, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            client_id = data.get("client_id", secrets.token_urlsafe(16))
            client = {
                "client_id": client_id,
                "client_secret": data.get("client_secret", secrets.token_urlsafe(32)),
                "redirect_uris": data.get("redirect_uris", []),
                "grant_types": data.get("grant_types", ["authorization_code"]),
                "response_types": data.get("response_types", ["code"]),
                "token_endpoint_auth_method": data.get(
                    "token_endpoint_auth_method", "client_secret_post"
                ),
                "scope": data.get("scope", "openid profile email"),
            }
            self._clients[client_id] = client
            return client

    def update_client(self, client_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            if client_id not in self._clients:
                return None
            self._clients[client_id].update(data)
            self._clients[client_id]["client_id"] = client_id  # Immutable
            return self._clients[client_id]

    def delete_client(self, client_id: str) -> bool:
        with self._lock:
            return self._clients.pop(client_id, None) is not None

    # ---- Users ----

    def get_user(self, sub: str) -> dict[str, Any] | None:
        with self._lock:
            return self._users.get(sub)

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._users.values())

    def create_user(self, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            sub = data["sub"]
            user = {
                "sub": sub,
                "email": data.get("email", f"{sub}@auditgithub.local"),
                "name": data.get("name", sub),
                "email_verified": data.get("email_verified", True),
                "preferred_username": data.get("preferred_username", data.get("email", f"{sub}@auditgithub.local")),
            }
            self._users[sub] = user
            return user

    def update_user(self, sub: str, data: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            if sub not in self._users:
                return None
            self._users[sub].update(data)
            self._users[sub]["sub"] = sub  # Immutable
            return self._users[sub]

    def delete_user(self, sub: str) -> bool:
        with self._lock:
            return self._users.pop(sub, None) is not None

    # ---- Auth Codes ----

    def create_auth_code(
        self,
        client_id: str,
        sub: str,
        redirect_uri: str,
        scope: str = "openid profile email",
        nonce: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "",
    ) -> str:
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._auth_codes[code] = {
                "client_id": client_id,
                "sub": sub,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "created_at": time.time(),
            }
        return code

    def consume_auth_code(self, code: str) -> dict[str, Any] | None:
        """Consume an auth code (one-time use). Returns None if invalid or expired."""
        with self._lock:
            data = self._auth_codes.pop(code, None)
        if data is None:
            return None
        if time.time() - data["created_at"] > settings.auth_code_lifetime:
            return None
        return data

    # ---- Tokens ----

    def store_token(
        self,
        access_token: str,
        sub: str,
        client_id: str,
        scope: str = "openid profile email",
    ) -> None:
        now = time.time()
        with self._lock:
            self._tokens[access_token] = {
                "sub": sub,
                "client_id": client_id,
                "scope": scope,
                "token_type": "Bearer",
                "created_at": now,
                "expires_at": now + settings.access_token_lifetime,
            }

    def get_token_info(self, access_token: str) -> dict[str, Any] | None:
        with self._lock:
            info = self._tokens.get(access_token)
        if info is None:
            return None
        if time.time() > info["expires_at"]:
            return None
        return info

    def revoke_token(self, token: str) -> bool:
        with self._lock:
            removed_access = self._tokens.pop(token, None) is not None
            removed_refresh = self._refresh_tokens.pop(token, None) is not None
        return removed_access or removed_refresh

    def store_refresh_token(
        self,
        refresh_token: str,
        sub: str,
        client_id: str,
        scope: str = "openid profile email",
    ) -> None:
        now = time.time()
        with self._lock:
            self._refresh_tokens[refresh_token] = {
                "sub": sub,
                "client_id": client_id,
                "scope": scope,
                "created_at": now,
                "expires_at": now + settings.refresh_token_lifetime,
            }

    def consume_refresh_token(self, refresh_token: str) -> dict[str, Any] | None:
        with self._lock:
            data = self._refresh_tokens.pop(refresh_token, None)
        if data is None:
            return None
        if time.time() > data["expires_at"]:
            return None
        return data

    def list_tokens(self) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            result = []
            for token, info in self._tokens.items():
                result.append({
                    "token_prefix": token[:12] + "...",
                    "sub": info["sub"],
                    "client_id": info["client_id"],
                    "scope": info["scope"],
                    "active": now < info["expires_at"],
                    "expires_at": info["expires_at"],
                })
            return result

    # ---- Stats / Reset ----

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "clients": len(self._clients),
                "users": len(self._users),
                "auth_codes_pending": len(self._auth_codes),
                "access_tokens": len(self._tokens),
                "refresh_tokens": len(self._refresh_tokens),
            }

    def clear(self) -> dict[str, int]:
        with self._lock:
            counts = {
                "clients_cleared": len(self._clients),
                "users_cleared": len(self._users),
                "auth_codes_cleared": len(self._auth_codes),
                "tokens_cleared": len(self._tokens),
                "refresh_tokens_cleared": len(self._refresh_tokens),
            }
            self._clients.clear()
            self._users.clear()
            self._auth_codes.clear()
            self._tokens.clear()
            self._refresh_tokens.clear()
        # Re-seed defaults after clearing
        self._seed()
        return counts
