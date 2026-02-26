"""
Common response models used across all routers.

Provides standard error responses, pagination, and success models
for consistent OpenAPI documentation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime


class ErrorResponse(BaseModel):
    """Standard error response body."""
    detail: str = Field(
        ...,
        description="Error message describing what went wrong",
        examples=["Resource not found"],
    )


class ValidationErrorDetail(BaseModel):
    """Individual field validation error."""
    loc: List[str] = Field(..., description="Location of the validation error")
    msg: str = Field(..., description="Error message")
    type: str = Field(..., description="Error type")


class ValidationErrorResponse(BaseModel):
    """Validation error response (HTTP 422)."""
    detail: List[ValidationErrorDetail] = Field(..., description="List of validation errors")


class SuccessResponse(BaseModel):
    """Generic success response."""
    success: bool = Field(True, description="Whether the operation succeeded")
    message: str = Field(
        ...,
        description="Human-readable result message",
        examples=["Operation completed successfully"],
    )


class DeleteResponse(BaseModel):
    """Response for deletion operations."""
    detail: str = Field(
        ...,
        description="Deletion confirmation message",
        examples=["Resource deleted successfully"],
    )


class PaginatedResponse(BaseModel):
    """Base for paginated list responses."""
    total: int = Field(..., description="Total number of records matching the query")
    skip: int = Field(0, description="Number of records skipped")
    limit: int = Field(100, description="Maximum records returned")


class HealthCheckResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Overall health status", examples=["healthy"])
    timestamp: str = Field(..., description="Check timestamp in ISO format")
    checks: dict = Field(..., description="Individual dependency health statuses")
    multi_tenant: bool = Field(..., description="Whether multi-tenant mode is enabled")


# =============================================================================
# Standard error response dicts for use in `responses={}` parameter
# =============================================================================

STANDARD_ERRORS = {
    400: {"model": ErrorResponse, "description": "Bad request - validation or business logic error"},
    401: {"model": ErrorResponse, "description": "Unauthorized - authentication required"},
    403: {"model": ErrorResponse, "description": "Forbidden - insufficient permissions"},
    404: {"model": ErrorResponse, "description": "Not found - resource does not exist"},
    409: {"model": ErrorResponse, "description": "Conflict - resource already exists"},
    429: {"model": ErrorResponse, "description": "Too many requests - rate limit exceeded"},
    500: {"model": ErrorResponse, "description": "Internal server error"},
}

# Convenience subsets for common endpoint patterns
CRUD_ERRORS = {k: v for k, v in STANDARD_ERRORS.items() if k in (400, 401, 403, 404, 500)}
LIST_ERRORS = {k: v for k, v in STANDARD_ERRORS.items() if k in (400, 401, 403, 500)}
CREATE_ERRORS = {k: v for k, v in STANDARD_ERRORS.items() if k in (400, 401, 403, 409, 500)}
DELETE_ERRORS = {k: v for k, v in STANDARD_ERRORS.items() if k in (401, 403, 404, 500)}
AUTH_ERRORS = {k: v for k, v in STANDARD_ERRORS.items() if k in (400, 401, 403, 500)}
