from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text, JSON, Numeric
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func, text
from .database import Base

class Repository(Base):
    __tablename__ = "repositories"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, unique=True, server_default=text("nextval('repositories_api_id_seq')"))
    name = Column(String, unique=True, nullable=False)
    full_name = Column(String)
    url = Column(Text)
    description = Column(Text)
    default_branch = Column(String)
    language = Column(String)
    owner_type = Column(String)
    owner_id = Column(String)
    business_criticality = Column(String)
    last_scanned_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    scan_runs = relationship("ScanRun", back_populates="repository")
    findings = relationship("Finding", back_populates="repository")

class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, unique=True, server_default=text("nextval('scan_runs_api_id_seq')"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    scan_type = Column(String)
    status = Column(String)
    triggered_by = Column(String)
    trigger_reference = Column(String)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Integer)
    findings_count = Column(Integer)
    new_findings_count = Column(Integer)
    resolved_findings_count = Column(Integer)
    architecture_overview = Column(Text)
    scan_config = Column(JSONB)
    error_message = Column(Text)
    created_at = Column(DateTime, server_default=func.now())

    repository = relationship("Repository", back_populates="scan_runs")
    findings = relationship("Finding", back_populates="scan_run")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, unique=True, server_default=text("nextval('findings_api_id_seq')"))
    finding_uuid = Column(UUID(as_uuid=True), unique=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    scan_run_id = Column(UUID(as_uuid=True), ForeignKey("scan_runs.id"))
    
    scanner_name = Column(String)
    finding_type = Column(String)
    severity = Column(String)
    title = Column(Text, nullable=False)
    description = Column(Text)
    
    file_path = Column(Text)
    line_start = Column(Integer)
    line_end = Column(Integer)
    code_snippet = Column(Text)
    
    cve_id = Column(String)
    cwe_id = Column(String)
    package_name = Column(String)
    package_version = Column(String)
    fixed_version = Column(String)
    
    status = Column(String, default='open')
    resolution = Column(String)
    resolution_notes = Column(Text)
    
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    assigned_at = Column(DateTime)
    jira_ticket_key = Column(String)
    jira_ticket_url = Column(Text)
    
    ai_remediation_text = Column(Text)
    ai_remediation_diff = Column(Text)
    ai_confidence_score = Column(Numeric(3, 2))
    
    first_seen_at = Column(DateTime, server_default=func.now())
    last_seen_at = Column(DateTime, server_default=func.now())
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="findings")
    scan_run = relationship("ScanRun", back_populates="findings")
    assignee = relationship("User", back_populates="assigned_findings")
    history = relationship("FindingHistory", back_populates="finding")
    comments = relationship("FindingComment", back_populates="finding")

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, unique=True, server_default=text("nextval('users_api_id_seq')"))
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    full_name = Column(String)
    role = Column(String)
    github_username = Column(String)
    jira_username = Column(String)
    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())

    assigned_findings = relationship("Finding", back_populates="assignee")

class FindingHistory(Base):
    __tablename__ = "finding_history"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, unique=True, server_default=text("nextval('finding_history_api_id_seq')"))
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"))
    changed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    change_type = Column(String)
    old_value = Column(Text)
    new_value = Column(Text)
    comment = Column(Text)
    metadata = Column(JSONB)
    created_at = Column(DateTime, server_default=func.now())

    finding = relationship("Finding", back_populates="history")

class FindingComment(Base):
    __tablename__ = "finding_comments"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, unique=True, server_default=text("nextval('finding_comments_api_id_seq')"))
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"))
    author_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    comment_text = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now())

    finding = relationship("Finding", back_populates="comments")
