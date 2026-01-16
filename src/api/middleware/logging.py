"""
Request Logging Middleware for Cribl Integration.

Provides request lifecycle logging with automatic correlation IDs and context propagation:
- REQUEST_START: Logs request entry with method, path, client IP, user agent, request_id
- REQUEST_END: Logs request completion with status, duration, bytes sent
- REQUEST_ERROR: Logs unhandled exceptions with full traceback

Features:
- UUID request_id generation for correlation
- X-Request-ID response header injection
- Client IP extraction from X-Forwarded-For
- Automatic context propagation via set_log_context()
"""

import time
import uuid
import traceback
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from loguru import logger

from src.api.utils.cribl_logger import set_log_context, clear_log_context


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log request lifecycle events to Cribl with correlation IDs.

    Generates a unique request_id for each request and logs:
    - REQUEST_START: Initial request details
    - REQUEST_END: Response status and duration
    - REQUEST_ERROR: Unhandled exceptions with traceback

    Context propagation:
    - Calls set_log_context() with request_id, org_id, user_id, session_id
    - All downstream logs automatically include this context
    - Calls clear_log_context() after response sent
    """

    async def dispatch(self, request: Request, call_next):
        """
        Process request and log lifecycle events.

        Args:
            request: FastAPI Request object
            call_next: Next middleware/handler in chain

        Returns:
            Response with X-Request-ID header
        """
        # Generate correlation ID
        request_id = str(uuid.uuid4())

        # Extract client IP (check X-Forwarded-For first, then request.client)
        client_ip = self._get_client_ip(request)

        # Extract user agent
        user_agent = request.headers.get("User-Agent", "unknown")

        # Log REQUEST_START
        start_time = time.time()
        logger.bind(
            event_type="REQUEST_START",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=client_ip,
            user_agent=user_agent
        ).info(f"REQUEST_START: {request.method} {request.url.path}")

        # Set log context for downstream logs
        context = {
            "request_id": request_id,
        }

        # Extract org context if available (set by OrganizationContextMiddleware)
        if hasattr(request.state, "org_id"):
            context["org_id"] = request.state.org_id
        if hasattr(request.state, "org_name"):
            context["org_name"] = request.state.org_name

        # Extract user context if available (set by auth middleware)
        if hasattr(request.state, "user"):
            user = request.state.user
            if hasattr(user, "sub"):
                context["user_id"] = user.sub
            elif isinstance(user, dict) and "sub" in user:
                context["user_id"] = user["sub"]

        # Extract session ID from cookies
        session_id = request.cookies.get("session")
        if session_id:
            context["session_id"] = session_id

        set_log_context(**context)

        try:
            # Process request
            response = await call_next(request)

            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000

            # Extract response size if available
            content_length = response.headers.get("content-length", "unknown")

            # Categorize performance
            if duration_ms < 100:
                perf_category = "FAST"
            elif duration_ms < 500:
                perf_category = "NORMAL"
            elif duration_ms < 2000:
                perf_category = "SLOW"
            else:
                perf_category = "CRITICAL"

            # Log REQUEST_END
            logger.bind(
                event_type="REQUEST_END",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
                perf_category=perf_category,
                bytes_sent=content_length
            ).info(f"Request completed: {request.method} {request.url.path} - {response.status_code} ({round(duration_ms, 2)}ms, {perf_category})")

            # Add slow request WARNING log for SLOW/CRITICAL requests
            if perf_category in ["SLOW", "CRITICAL"]:
                logger.bind(
                    event_type="SLOW_REQUEST",
                    request_id=request_id,
                    duration_ms=round(duration_ms, 2)
                ).warning(f"Slow request detected: {request.method} {request.url.path} took {round(duration_ms, 2)}ms")

            # Inject X-Request-ID header for client correlation
            response.headers["X-Request-ID"] = request_id

            return response

        except Exception as e:
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000

            # Get full traceback
            tb = traceback.format_exc()

            # Log REQUEST_ERROR
            logger.bind(
                event_type="REQUEST_ERROR",
                request_id=request_id,
                error_type=type(e).__name__,
                error_message=str(e),
                traceback=tb,
                duration_ms=round(duration_ms, 2)
            ).error(f"REQUEST_ERROR: {request.method} {request.url.path} - {type(e).__name__}: {str(e)}")

            # Re-raise to let FastAPI handle error response
            raise

        finally:
            # Clear log context after request completes
            clear_log_context()

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request.

        Checks X-Forwarded-For header first (for proxy/load balancer scenarios),
        then falls back to request.client.host.

        Args:
            request: FastAPI Request object

        Returns:
            str: Client IP address or "unknown"
        """
        # Check X-Forwarded-For header (contains comma-separated IPs, first is client)
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            # Take first IP in the chain (client IP)
            return x_forwarded_for.split(",")[0].strip()

        # Fall back to request.client.host
        if request.client:
            return request.client.host

        return "unknown"
