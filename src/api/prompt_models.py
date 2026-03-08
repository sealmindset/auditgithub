"""
Prompt Management System - SQLAlchemy Models

Provides centralized storage for all AI prompts, version history,
usage tracking, tagging, test cases, and audit logging.
"""

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, ForeignKey, Text,
    BigInteger, Numeric, Sequence, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func, text
from src.api.database import Base


class Prompt(Base):
    """
    Registry of all managed AI prompts, agent instructions, skills, and MCP configs.
    Each prompt has a unique slug and tracks its current version.
    """
    __tablename__ = "prompts"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('prompts_api_id_seq'), unique=True)
    slug = Column(String(128), unique=True, nullable=False, index=True)
    name = Column(String(256), nullable=False)
    description = Column(Text)

    # Classification
    category = Column(String(64), nullable=False, index=True)
    # system | user | template | agent | skill | mcp
    subcategory = Column(String(64))
    # e.g. security-analysis, remediation, triage, discovery

    # Binding
    agent_id = Column(String(128), index=True)
    # Which agent uses this (null = global/shared)

    # Provider & Model targeting
    provider = Column(String(64))
    # claude | openai | gemini | ollama | anthropic_foundry | any
    model = Column(String(128))
    # e.g. claude-sonnet-4-5, gpt-4o, gemini-1.5-pro (null = default)

    # State
    current_version = Column(Integer, nullable=False, default=1)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    is_locked = Column(Boolean, nullable=False, default=False)
    locked_by = Column(String(255))  # user sub
    locked_reason = Column(Text)

    # Migration tracking (where this prompt was extracted from)
    source_file = Column(String(512))
    source_line = Column(Integer)

    # Audit
    created_by = Column(String(255))  # user sub
    updated_by = Column(String(255))  # user sub
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    versions = relationship("PromptVersion", back_populates="prompt", order_by="PromptVersion.version.desc()")
    usages = relationship("PromptUsage", back_populates="prompt")
    tags = relationship("PromptTag", back_populates="prompt")
    test_cases = relationship("PromptTestCase", back_populates="prompt")

    def __repr__(self):
        return f"<Prompt(slug='{self.slug}', v{self.current_version}, active={self.is_active})>"


class PromptVersion(Base):
    """
    Immutable version history for prompts. Every edit creates a new row.
    Content is never updated — only new versions are appended.
    """
    __tablename__ = "prompt_versions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    prompt_id = Column(UUID(as_uuid=True), ForeignKey("prompts.id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, nullable=False)

    # Prompt content
    content = Column(Text, nullable=False)
    system_message = Column(Text)

    # LLM parameters for this version
    parameters = Column(JSONB, default={})
    # { temperature, max_tokens, top_p, stop_sequences, etc. }

    # Model override (version-level, overrides prompt-level default)
    model = Column(String(128))
    # e.g. claude-opus-4-6, gpt-5 — null means use prompt-level default

    # Schema definitions
    input_schema = Column(JSONB)
    # { "finding_title": "str", "tool_source": "str", ... }
    output_schema = Column(JSONB)
    # { "severity": "critical|high|medium|low|info", ... }

    # Change tracking
    change_summary = Column(Text)

    # Audit
    created_by = Column(String(255))  # user sub
    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    prompt = relationship("Prompt", back_populates="versions")

    __table_args__ = (
        UniqueConstraint('prompt_id', 'version', name='uq_prompt_version'),
        Index('idx_prompt_versions_lookup', 'prompt_id', 'version'),
    )

    def __repr__(self):
        return f"<PromptVersion(prompt_id='{self.prompt_id}', v{self.version})>"


class PromptUsage(Base):
    """
    Tracks where each prompt is used — both code references and runtime calls.
    Updated by the usage tracking middleware on every AI provider invocation.
    """
    __tablename__ = "prompt_usages"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    prompt_id = Column(UUID(as_uuid=True), ForeignKey("prompts.id", ondelete="CASCADE"), nullable=False)

    # Where it's used
    usage_type = Column(String(64), nullable=False)
    # code_reference | runtime_call | agent_binding | mcp_tool | skill
    location = Column(String(512), nullable=False)
    # File path, agent name, MCP tool name, etc.
    description = Column(Text)
    is_primary = Column(Boolean, default=False)

    # Runtime metrics (updated on each call)
    last_called_at = Column(DateTime)
    call_count = Column(BigInteger, default=0)
    avg_latency_ms = Column(Integer)
    avg_tokens_in = Column(Integer)
    avg_tokens_out = Column(Integer)
    total_tokens = Column(BigInteger, default=0)
    error_count = Column(BigInteger, default=0)

    # Model tracking (which model was actually used at runtime)
    last_model_used = Column(String(128))
    last_provider_used = Column(String(64))

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    prompt = relationship("Prompt", back_populates="usages")

    __table_args__ = (
        Index('idx_prompt_usages_prompt', 'prompt_id'),
        Index('idx_prompt_usages_type', 'usage_type'),
    )

    def __repr__(self):
        return f"<PromptUsage(prompt_id='{self.prompt_id}', type='{self.usage_type}', calls={self.call_count})>"


class PromptTag(Base):
    """Flexible tagging system for prompt organization and filtering."""
    __tablename__ = "prompt_tags"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    prompt_id = Column(UUID(as_uuid=True), ForeignKey("prompts.id", ondelete="CASCADE"), nullable=False)
    tag = Column(String(64), nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    prompt = relationship("Prompt", back_populates="tags")

    __table_args__ = (
        UniqueConstraint('prompt_id', 'tag', name='uq_prompt_tag'),
        Index('idx_prompt_tags_tag', 'tag'),
    )

    def __repr__(self):
        return f"<PromptTag(prompt_id='{self.prompt_id}', tag='{self.tag}')>"


class PromptTestCase(Base):
    """Saved test inputs and expected outputs for regression testing prompts."""
    __tablename__ = "prompt_test_cases"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    prompt_id = Column(UUID(as_uuid=True), ForeignKey("prompts.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(256), nullable=False)
    input_data = Column(JSONB, nullable=False)
    expected_output = Column(Text)
    notes = Column(Text)
    created_by = Column(String(255))
    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    prompt = relationship("Prompt", back_populates="test_cases")

    def __repr__(self):
        return f"<PromptTestCase(prompt_id='{self.prompt_id}', name='{self.name}')>"


class PromptAuditLog(Base):
    """
    Immutable, append-only audit log for all prompt management actions.
    Never updated or deleted — only inserted.
    """
    __tablename__ = "prompt_audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    action = Column(String(64), nullable=False)
    # created | updated | restored | activated | deactivated | locked | unlocked | deleted | tested | imported

    prompt_id = Column(UUID(as_uuid=True), nullable=False)
    prompt_slug = Column(String(128), nullable=False)
    version = Column(Integer)

    user_id = Column(String(255))
    user_email = Column(String(256))

    old_value = Column(JSONB)
    new_value = Column(JSONB)

    ip_address = Column(String(45))
    user_agent = Column(Text)

    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        Index('idx_prompt_audit_prompt', 'prompt_id'),
        Index('idx_prompt_audit_user', 'user_id'),
        Index('idx_prompt_audit_action', 'action'),
        Index('idx_prompt_audit_created', 'created_at'),
    )

    def __repr__(self):
        return f"<PromptAuditLog(action='{self.action}', slug='{self.prompt_slug}', v{self.version})>"
