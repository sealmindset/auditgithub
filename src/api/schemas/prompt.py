"""
Prompt Management System - Pydantic Schemas

Request/response models for all prompt management API endpoints.
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Any
from datetime import datetime


# =============================================================================
# Prompt Schemas
# =============================================================================

class PromptBase(BaseModel):
    """Common fields for prompt create/update."""
    name: str = Field(..., min_length=1, max_length=256, description="Human-friendly prompt name")
    description: Optional[str] = Field(None, description="What this prompt does and when it's used")
    category: str = Field(..., description="Prompt category: system, user, template, agent, skill, mcp")
    subcategory: Optional[str] = Field(None, max_length=64, description="e.g. security-analysis, remediation")
    agent_id: Optional[str] = Field(None, max_length=128, description="Agent that uses this prompt")
    provider: Optional[str] = Field(None, max_length=64, description="Target provider: claude, openai, gemini, ollama, any")
    model: Optional[str] = Field(None, max_length=128, description="Target model: claude-sonnet-4-5, gpt-4o, etc.")


class PromptCreate(PromptBase):
    """Request body for POST /prompts"""
    slug: str = Field(..., min_length=1, max_length=128, pattern=r'^[a-z0-9][a-z0-9-]*[a-z0-9]$',
                      description="URL-safe unique identifier (lowercase, hyphens only)")
    content: str = Field(..., min_length=1, description="The prompt text content")
    system_message: Optional[str] = Field(None, description="System message (if separate from content)")
    parameters: Optional[dict] = Field(default_factory=dict, description="LLM parameters: temperature, max_tokens, etc.")
    input_schema: Optional[dict] = Field(None, description="Expected input variable definitions")
    output_schema: Optional[dict] = Field(None, description="Expected output format definition")
    tags: Optional[List[str]] = Field(default_factory=list, description="Tags for organization")
    change_summary: Optional[str] = Field("Initial version", description="Description of this version")

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "slug": "triage-finding-system",
            "name": "Triage Finding System Prompt",
            "description": "Analyzes security findings and assigns severity ratings",
            "category": "system",
            "subcategory": "security-analysis",
            "agent_id": "triage-agent",
            "provider": "claude",
            "model": "claude-sonnet-4-5",
            "content": "You are a senior security engineer. Analyze the provided finding...",
            "parameters": {"temperature": 0.2, "max_tokens": 2048},
            "tags": ["security", "triage"]
        }
    })


class PromptUpdate(BaseModel):
    """Request body for PUT /prompts/:slug — creates a new version."""
    name: Optional[str] = Field(None, max_length=256)
    description: Optional[str] = None
    category: Optional[str] = Field(None, max_length=64)
    subcategory: Optional[str] = Field(None, max_length=64)
    agent_id: Optional[str] = Field(None, max_length=128)
    provider: Optional[str] = Field(None, max_length=64)
    model: Optional[str] = Field(None, max_length=128)
    content: str = Field(..., min_length=1, description="Updated prompt content")
    system_message: Optional[str] = None
    parameters: Optional[dict] = None
    input_schema: Optional[dict] = None
    output_schema: Optional[dict] = None
    tags: Optional[List[str]] = None
    change_summary: str = Field(..., min_length=1, description="Why this version was created")


class PromptResponse(BaseModel):
    """Response model for a single prompt."""
    id: str = Field(..., description="UUID")
    api_id: Optional[int] = None
    slug: str
    name: str
    description: Optional[str] = None
    category: str
    subcategory: Optional[str] = None
    agent_id: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    current_version: int
    is_active: bool
    is_locked: bool
    locked_by: Optional[str] = None
    locked_reason: Optional[str] = None
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    tags: List[str] = Field(default_factory=list)
    usage_count: Optional[int] = Field(None, description="Total runtime invocations")
    version_count: Optional[int] = Field(None, description="Total versions")

    model_config = ConfigDict(from_attributes=True)


class PromptListResponse(BaseModel):
    """Paginated list of prompts."""
    items: List[PromptResponse]
    total: int
    skip: int
    limit: int


# =============================================================================
# Version Schemas
# =============================================================================

class PromptVersionResponse(BaseModel):
    """Response model for a prompt version."""
    id: str
    prompt_id: str
    version: int
    content: str
    system_message: Optional[str] = None
    parameters: Optional[dict] = None
    model: Optional[str] = None
    input_schema: Optional[dict] = None
    output_schema: Optional[dict] = None
    change_summary: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PromptVersionListResponse(BaseModel):
    """List of versions for a prompt."""
    items: List[PromptVersionResponse]
    total: int


class PromptDiffResponse(BaseModel):
    """Diff between two versions."""
    slug: str
    version_from: int
    version_to: int
    content_diff: Optional[str] = None
    system_message_diff: Optional[str] = None
    parameters_diff: Optional[dict] = None
    model_changed: Optional[dict] = Field(None, description="{ old: str, new: str }")


class PromptRestoreRequest(BaseModel):
    """Request to restore a prompt to a previous version."""
    change_summary: Optional[str] = Field("Restored from previous version", description="Reason for restore")


# =============================================================================
# Usage Schemas
# =============================================================================

class PromptUsageResponse(BaseModel):
    """Response model for a prompt usage entry."""
    id: str
    prompt_id: str
    usage_type: str
    location: str
    description: Optional[str] = None
    is_primary: bool = False
    last_called_at: Optional[datetime] = None
    call_count: int = 0
    avg_latency_ms: Optional[int] = None
    avg_tokens_in: Optional[int] = None
    avg_tokens_out: Optional[int] = None
    total_tokens: int = 0
    error_count: int = 0
    last_model_used: Optional[str] = None
    last_provider_used: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PromptUsageCreate(BaseModel):
    """Register a new usage location for a prompt."""
    usage_type: str = Field(..., description="code_reference, runtime_call, agent_binding, mcp_tool, skill")
    location: str = Field(..., max_length=512, description="File path, agent name, or tool name")
    description: Optional[str] = None
    is_primary: bool = False


# =============================================================================
# Tag Schemas
# =============================================================================

class TagCount(BaseModel):
    """A tag with its usage count."""
    tag: str
    count: int


class TagListResponse(BaseModel):
    """All tags with counts."""
    items: List[TagCount]


class TagAddRequest(BaseModel):
    """Add a tag to a prompt."""
    tag: str = Field(..., min_length=1, max_length=64, pattern=r'^[a-z0-9][a-z0-9-]*[a-z0-9]$')


# =============================================================================
# Test Case Schemas
# =============================================================================

class PromptTestCaseCreate(BaseModel):
    """Create a saved test case."""
    name: str = Field(..., min_length=1, max_length=256)
    input_data: dict = Field(..., description="Test input variables")
    expected_output: Optional[str] = None
    notes: Optional[str] = None


class PromptTestCaseResponse(BaseModel):
    """Response for a test case."""
    id: str
    prompt_id: str
    name: str
    input_data: dict
    expected_output: Optional[str] = None
    notes: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PromptTestRunRequest(BaseModel):
    """Execute a prompt with test input."""
    input_data: dict = Field(..., description="Variables to inject into the prompt template")
    provider: Optional[str] = Field(None, description="Override provider for this test run")
    model: Optional[str] = Field(None, description="Override model for this test run")


class PromptTestRunResponse(BaseModel):
    """Result of a test execution."""
    output: str
    model_used: str
    provider_used: str
    tokens_in: int
    tokens_out: int
    latency_ms: int


# =============================================================================
# Audit Log Schemas
# =============================================================================

class PromptAuditLogResponse(BaseModel):
    """Response for an audit log entry."""
    id: str
    action: str
    prompt_id: str
    prompt_slug: str
    version: Optional[int] = None
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    old_value: Optional[dict] = None
    new_value: Optional[dict] = None
    ip_address: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PromptAuditLogListResponse(BaseModel):
    """Paginated audit log."""
    items: List[PromptAuditLogResponse]
    total: int
    skip: int
    limit: int


# =============================================================================
# Agent & Analytics Schemas
# =============================================================================

class AgentSummary(BaseModel):
    """Summary of an agent and its prompts."""
    agent_id: str
    prompt_count: int
    active_count: int
    total_calls: int
    prompts: List[PromptResponse] = Field(default_factory=list)


class AgentListResponse(BaseModel):
    """List of agents with prompt counts."""
    items: List[AgentSummary]


class PromptAnalyticsOverview(BaseModel):
    """System-wide analytics summary."""
    total_prompts: int
    active_prompts: int
    total_versions: int
    total_agents: int
    total_calls: int
    total_tokens: int
    versions_today: int
    error_rate: float
    category_breakdown: dict = Field(default_factory=dict)
    provider_breakdown: dict = Field(default_factory=dict)
    model_breakdown: dict = Field(default_factory=dict)
    top_prompts: List[PromptResponse] = Field(default_factory=list)
    recent_changes: List[PromptAuditLogResponse] = Field(default_factory=list)


# =============================================================================
# Import/Export Schemas
# =============================================================================

class PromptExportItem(BaseModel):
    """Single prompt in export format."""
    slug: str
    name: str
    description: Optional[str] = None
    category: str
    subcategory: Optional[str] = None
    agent_id: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    content: str
    system_message: Optional[str] = None
    parameters: Optional[dict] = None
    input_schema: Optional[dict] = None
    output_schema: Optional[dict] = None
    tags: List[str] = Field(default_factory=list)


class PromptImportRequest(BaseModel):
    """Bulk import request."""
    prompts: List[PromptExportItem]
    overwrite: bool = Field(False, description="Overwrite existing prompts with same slug")


class PromptImportResponse(BaseModel):
    """Bulk import result."""
    created: int
    updated: int
    skipped: int
    errors: List[str] = Field(default_factory=list)
