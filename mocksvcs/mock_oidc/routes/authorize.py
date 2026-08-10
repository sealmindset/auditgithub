"""Authorization endpoint — HTML user picker with auto-redirect."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import HTMLResponse, RedirectResponse

if TYPE_CHECKING:
    from mock_oidc.store import OIDCStore


def create_authorize_router(store: OIDCStore) -> APIRouter:
    """Create authorization router with user picker UI."""
    r = APIRouter()

    @r.get("/authorize", response_model=None)
    async def authorize(
        response_type: str = Query("code"),
        client_id: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query("openid profile email"),
        state: str = Query(""),
        nonce: str = Query(""),
        login_hint: str = Query(""),
        code_challenge: str = Query(""),
        code_challenge_method: str = Query(""),
    ) -> HTMLResponse | RedirectResponse:
        """OIDC Authorization Endpoint.

        If login_hint is provided and matches a user sub, auto-redirects
        with an auth code (useful for automated testing). Otherwise,
        renders an HTML user-picker page.
        """
        # Validate client
        client = store.get_client(client_id)
        if client is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown client_id: {client_id}",
            )

        if response_type != "code":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported response_type: {response_type}",
            )

        # Auto-select user if login_hint matches
        if login_hint:
            user = store.get_user(login_hint)
            if user:
                code = store.create_auth_code(
                    client_id=client_id,
                    sub=user["sub"],
                    redirect_uri=redirect_uri,
                    scope=scope,
                    nonce=nonce,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                )
                params = {"code": code}
                if state:
                    params["state"] = state
                return RedirectResponse(
                    url=f"{redirect_uri}?{urlencode(params)}",
                    status_code=302,
                )

        # Render user picker HTML
        users = store.list_users()
        user_buttons = ""
        for user in users:
            user_buttons += f"""
            <button type="submit" name="sub" value="{user['sub']}"
                    style="display:block; width:100%; padding:12px 16px;
                           margin:8px 0; border:1px solid #ddd; border-radius:8px;
                           background:#fff; cursor:pointer; text-align:left;
                           font-size:14px;">
                <strong>{user['name']}</strong><br>
                <span style="color:#666; font-size:12px;">{user['email']}</span>
            </button>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Mock OIDC Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif;
               display: flex; justify-content: center; align-items: center;
               min-height: 100vh; margin: 0; background: #f5f5f5; }}
        .card {{ background: #fff; padding: 32px; border-radius: 12px;
                 box-shadow: 0 2px 8px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }}
        h2 {{ margin-top: 0; color: #333; }}
        .subtitle {{ color: #666; font-size: 13px; margin-bottom: 16px; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>Mock OIDC Login</h2>
        <p class="subtitle">Select a user to sign in as:</p>
        <form method="POST" action="/authorize/select">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="scope" value="{scope}">
            <input type="hidden" name="state" value="{state}">
            <input type="hidden" name="nonce" value="{nonce}">
            <input type="hidden" name="code_challenge" value="{code_challenge}">
            <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
            {user_buttons}
        </form>
    </div>
</body>
</html>"""
        return HTMLResponse(content=html)

    @r.post("/authorize/select")
    async def authorize_select(
        sub: str = Query(""),
        client_id: str = Query(""),
        redirect_uri: str = Query(""),
        scope: str = Query("openid profile email"),
        state: str = Query(""),
        nonce: str = Query(""),
    ) -> RedirectResponse:
        """Handle user selection from the picker form."""
        # FastAPI will also check Form data, but for form POST we need to
        # accept from the form body. Use request form parsing.
        from fastapi import Form as _  # noqa: F401 — just documenting intent

        # This endpoint is called via HTML form POST; values come as form fields.
        # FastAPI query params also capture form fields for non-JSON content types
        # when they match parameter names. We handle this via the dependency below.
        pass

    # Override the POST handler to properly extract form data
    r.routes.pop()  # Remove the placeholder above

    from fastapi import Form

    @r.post("/authorize/select")
    async def authorize_select_form(
        sub: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        scope: str = Form("openid profile email"),
        state: str = Form(""),
        nonce: str = Form(""),
        code_challenge: str = Form(""),
        code_challenge_method: str = Form(""),
    ) -> RedirectResponse:
        """Handle user selection from the picker form."""
        user = store.get_user(sub)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown user: {sub}",
            )

        code = store.create_auth_code(
            client_id=client_id,
            sub=sub,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        params = {"code": code}
        if state:
            params["state"] = state
        return RedirectResponse(
            url=f"{redirect_uri}?{urlencode(params)}",
            status_code=302,
        )

    return r
