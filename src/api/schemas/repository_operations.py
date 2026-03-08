"""
Repository Operations Context - Pydantic Schemas

Request/response models for repository operations context endpoints
(deployment, hosting, compliance, infrastructure, AI discovery).
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Any
from datetime import datetime


# =============================================================================
# Shared sub-models
# =============================================================================

class EnvironmentUrl(BaseModel):
    """An environment URL entry (e.g., production, staging)."""
    name: str = Field(..., description="Environment name, e.g. production, staging")
    url: str = Field(..., description="URL for the environment")
    is_primary: bool = Field(False, description="Whether this is the primary environment URL")


class DiscoverySuggestion(BaseModel):
    """A single AI-suggested value for an operations field."""
    field: str = Field(..., description="The operations field name this suggestion applies to")
    value: str = Field(..., description="The suggested value")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0 - 1.0")
    evidence: str = Field(..., description="Evidence or reasoning for the suggestion")
    accepted: Optional[bool] = Field(None, description="Whether the suggestion was accepted, rejected, or pending (null)")


# =============================================================================
# Repository Operations Schemas
# =============================================================================

class RepositoryOperationsBase(BaseModel):
    """All writable fields for repository operations context."""
    # Deployment Status
    deployment_status: Optional[str] = Field(None, max_length=32, description="production, staging, development, deprecated, archived, decommissioned, unknown")
    deployment_status_notes: Optional[str] = None

    # Environment URLs
    environment_urls: Optional[List[EnvironmentUrl]] = Field(None, description="Array of environment URL entries")

    # Hosting & Platform
    hosting_platform: Optional[str] = Field(None, max_length=64, description="aws, azure, gcp, on-prem, hybrid, heroku, vercel, other")
    hosting_detail: Optional[str] = Field(None, description="e.g. AWS ECS Fargate in us-east-1")
    deployment_method: Optional[str] = Field(None, max_length=64, description="kubernetes, ecs, lambda, vm, container, serverless, static, other")
    deployment_method_detail: Optional[str] = None

    # Team & Ownership
    team_owner: Optional[str] = Field(None, max_length=256)
    team_contact_email: Optional[str] = Field(None, max_length=256)
    team_slack_channel: Optional[str] = Field(None, max_length=256)

    # Business Criticality
    business_criticality: Optional[str] = Field(None, max_length=32, description="critical, high, medium, low")
    business_criticality_notes: Optional[str] = None

    # Compliance & Governance
    compliance_frameworks: Optional[List[str]] = Field(None, description="e.g. ['SOC2', 'PCI-DSS', 'HIPAA']")
    data_classification: Optional[str] = Field(None, max_length=32, description="public, internal, confidential, restricted")
    regulatory_notes: Optional[str] = None
    last_compliance_audit_at: Optional[datetime] = None

    # Infrastructure
    cicd_platform: Optional[str] = Field(None, max_length=64, description="github-actions, jenkins, gitlab-ci, azure-devops, circleci, other")
    cicd_pipeline_url: Optional[str] = None
    container_registry: Optional[str] = Field(None, max_length=128)
    iac_type: Optional[str] = Field(None, max_length=64, description="terraform, bicep, cloudformation, pulumi, ansible, none, other")
    iac_path: Optional[str] = Field(None, description="Path within repo to IaC files")
    monitoring_url: Optional[str] = None
    alerting_url: Optional[str] = None
    logging_url: Optional[str] = None

    # Metadata
    custom_metadata: Optional[dict] = Field(None, description="Flexible key-value pairs")
    notes: Optional[str] = None


class RepositoryOperationsCreate(RepositoryOperationsBase):
    """Request body for creating repository operations context (PUT upsert)."""
    pass


class RepositoryOperationsUpdate(BaseModel):
    """Request body for partial update (PATCH) - all fields optional."""
    # Deployment Status
    deployment_status: Optional[str] = Field(None, max_length=32)
    deployment_status_notes: Optional[str] = None

    # Environment URLs
    environment_urls: Optional[List[EnvironmentUrl]] = None

    # Hosting & Platform
    hosting_platform: Optional[str] = Field(None, max_length=64)
    hosting_detail: Optional[str] = None
    deployment_method: Optional[str] = Field(None, max_length=64)
    deployment_method_detail: Optional[str] = None

    # Team & Ownership
    team_owner: Optional[str] = Field(None, max_length=256)
    team_contact_email: Optional[str] = Field(None, max_length=256)
    team_slack_channel: Optional[str] = Field(None, max_length=256)

    # Business Criticality
    business_criticality: Optional[str] = Field(None, max_length=32)
    business_criticality_notes: Optional[str] = None

    # Compliance & Governance
    compliance_frameworks: Optional[List[str]] = None
    data_classification: Optional[str] = Field(None, max_length=32)
    regulatory_notes: Optional[str] = None
    last_compliance_audit_at: Optional[datetime] = None

    # Infrastructure
    cicd_platform: Optional[str] = Field(None, max_length=64)
    cicd_pipeline_url: Optional[str] = None
    container_registry: Optional[str] = Field(None, max_length=128)
    iac_type: Optional[str] = Field(None, max_length=64)
    iac_path: Optional[str] = None
    monitoring_url: Optional[str] = None
    alerting_url: Optional[str] = None
    logging_url: Optional[str] = None

    # Metadata
    custom_metadata: Optional[dict] = None
    notes: Optional[str] = None


class RepositoryOperationsResponse(BaseModel):
    """Response model for repository operations context."""
    id: Optional[str] = None
    repository_id: str

    # Deployment Status
    deployment_status: Optional[str] = "unknown"
    deployment_status_notes: Optional[str] = None

    # Environment URLs
    environment_urls: Optional[List[EnvironmentUrl]] = []

    # Hosting & Platform
    hosting_platform: Optional[str] = None
    hosting_detail: Optional[str] = None
    deployment_method: Optional[str] = None
    deployment_method_detail: Optional[str] = None

    # Team & Ownership
    team_owner: Optional[str] = None
    team_contact_email: Optional[str] = None
    team_slack_channel: Optional[str] = None

    # Business Criticality
    business_criticality: Optional[str] = "medium"
    business_criticality_notes: Optional[str] = None

    # Compliance & Governance
    compliance_frameworks: Optional[List[str]] = []
    data_classification: Optional[str] = None
    regulatory_notes: Optional[str] = None
    last_compliance_audit_at: Optional[datetime] = None

    # Infrastructure
    cicd_platform: Optional[str] = None
    cicd_pipeline_url: Optional[str] = None
    container_registry: Optional[str] = None
    iac_type: Optional[str] = None
    iac_path: Optional[str] = None
    monitoring_url: Optional[str] = None
    alerting_url: Optional[str] = None
    logging_url: Optional[str] = None

    # AI Discovery
    last_discovery_at: Optional[datetime] = None
    last_discovery_status: Optional[str] = None
    discovery_confidence: Optional[float] = None

    # Metadata
    custom_metadata: Optional[dict] = {}
    notes: Optional[str] = None

    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# Discovery Run Schemas
# =============================================================================

class DiscoveryRunResponse(BaseModel):
    """Response model for an AI discovery run."""
    id: str
    repository_id: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    suggestions: Optional[List[DiscoverySuggestion]] = []
    evidence_files: Optional[List[str]] = []
    triggered_by: Optional[str] = None
    error_message: Optional[str] = None
    tokens_used: Optional[int] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SuggestionAcceptance(BaseModel):
    """A single suggestion acceptance/rejection decision."""
    field: str = Field(..., description="The operations field name")
    accepted: bool = Field(..., description="Whether to accept the suggestion")
    override_value: Optional[str] = Field(None, description="Override value instead of the suggested one")


class AcceptSuggestionsRequest(BaseModel):
    """Request body for accepting/rejecting discovery suggestions."""
    decisions: List[SuggestionAcceptance] = Field(..., description="List of accept/reject decisions")
