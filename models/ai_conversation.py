"""
AI Conversation Models
Manages conversation history for the Ask AI feature
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Boolean, Enum as SQLEnum
from sqlalchemy.orm import relationship
from database import Base
import enum


class MessageRole(str, enum.Enum):
    """Message role types"""
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


class CitationType(str, enum.Enum):
    """Citation source types"""
    REPOSITORY = "repository"
    SCAN_RESULT = "scan_result"
    VULNERABILITY = "vulnerability"
    WEB = "web"
    DOCUMENTATION = "documentation"


class AIConversation(Base):
    """AI conversation session"""
    __tablename__ = "ai_conversations"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(String(100), unique=True, index=True, nullable=False)

    # Context
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)

    # Conversation metadata
    title = Column(String(500))  # Auto-generated from first user message
    focus = Column(String(100))  # e.g., "security_architecture", "zero_trust", "vulnerabilities"

    # Status
    is_active = Column(Boolean, default=True)
    message_count = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_message_at = Column(DateTime)

    # Relationships
    project = relationship("Project", back_populates="ai_conversations")
    repository = relationship("Repository", back_populates="ai_conversations")
    organization = relationship("Organization", back_populates="ai_conversations")
    messages = relationship("AIMessage", back_populates="conversation", cascade="all, delete-orphan")


class AIMessage(Base):
    """Individual message in an AI conversation"""
    __tablename__ = "ai_messages"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String(100), unique=True, index=True, nullable=False)
    conversation_id = Column(Integer, ForeignKey("ai_conversations.id"), nullable=False)

    # Message content
    role = Column(SQLEnum(MessageRole), nullable=False)
    content = Column(Text, nullable=False)

    # AI metadata (for assistant messages)
    thinking = Column(Text)  # Internal reasoning/thought process
    needs_clarification = Column(Boolean, default=False)
    clarification_question = Column(Text)

    # Context used (for assistant messages)
    context_used = Column(JSON)  # List of context sources used
    tokens_used = Column(Integer)  # Token count for this message

    # Quality metrics
    confidence_score = Column(Integer)  # 0-100
    web_search_performed = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    conversation = relationship("AIConversation", back_populates="messages")
    citations = relationship("AICitation", back_populates="message", cascade="all, delete-orphan")


class AICitation(Base):
    """Citation/reference for an AI message"""
    __tablename__ = "ai_citations"

    id = Column(Integer, primary_key=True, index=True)
    citation_id = Column(String(100), unique=True, index=True, nullable=False)
    message_id = Column(Integer, ForeignKey("ai_messages.id"), nullable=False)

    # Citation details
    type = Column(SQLEnum(CitationType), nullable=False)
    source = Column(String(500), nullable=False)  # e.g., "scan_sast.py", "OWASP ZAP Report"
    reference = Column(String(1000), nullable=False)  # e.g., "Line 45-67", "CVE-2024-1234"
    excerpt = Column(Text)  # Relevant excerpt from the source
    url = Column(String(2000))  # URL if applicable (for web sources)

    # Metadata
    relevance_score = Column(Integer)  # 0-100

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    message = relationship("AIMessage", back_populates="citations")


# Add relationships to existing models
def add_relationships():
    """Add relationships to existing models"""
    from models.project import Project
    from models.repository import Repository
    from models.organization import Organization

    # Add to Project model
    if not hasattr(Project, 'ai_conversations'):
        Project.ai_conversations = relationship("AIConversation", back_populates="project")

    # Add to Repository model
    if not hasattr(Repository, 'ai_conversations'):
        Repository.ai_conversations = relationship("AIConversation", back_populates="repository")

    # Add to Organization model
    if not hasattr(Organization, 'ai_conversations'):
        Organization.ai_conversations = relationship("AIConversation", back_populates="organization")
