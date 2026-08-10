"""End session (logout) endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, RedirectResponse

if TYPE_CHECKING:
    from mock_oidc.store import OIDCStore


def create_logout_router(store: OIDCStore) -> APIRouter:
    """Create logout router."""
    r = APIRouter()

    @r.get("/logout", response_model=None)
    async def logout(
        post_logout_redirect_uri: str = Query(""),
        id_token_hint: str = Query(""),
        state: str = Query(""),
    ) -> RedirectResponse | HTMLResponse:
        """OIDC end session endpoint.

        If post_logout_redirect_uri is provided, redirects there.
        Otherwise, shows a simple logged-out page.
        """
        if post_logout_redirect_uri:
            url = post_logout_redirect_uri
            if state:
                url += f"?state={state}"
            return RedirectResponse(url=url, status_code=302)

        return HTMLResponse(
            content="""<!DOCTYPE html>
<html>
<head><title>Logged Out</title></head>
<body style="font-family: sans-serif; text-align: center; padding-top: 80px;">
    <h2>You have been logged out</h2>
    <p>You can close this window.</p>
</body>
</html>"""
        )

    return r
