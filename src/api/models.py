from sqlalchemy import Column, String, Integer, BigInteger, Boolean, DateTime, ForeignKey, Text, JSON, Numeric, Sequence, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func, text
from .database import Base


# =============================================================================
# ORGANIZATION - Multi-tenant root entity
# =============================================================================

class Organization(Base):
    """
    Represents a GitHub organization in the multi-tenant system.
    All data (repositories, findings, etc.) is scoped to an organization.
    """
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('organizations_api_id_seq'), unique=True)
    
    name = Column(String(255), unique=True, nullable=False)  # Internal name (e.g., "sealmindset")
    github_org = Column(String(255), nullable=False)  # GitHub organization name
    display_name = Column(String(255))  # Human-readable name
    database_name = Column(String(255))  # Per-org database name
    
    is_default = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<Organization(name='{self.name}', github_org='{self.github_org}')>"


# =============================================================================
# REPOSITORY - Core entity
# =============================================================================

class Repository(Base):
    __tablename__ = "repositories"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('repositories_api_id_seq'), unique=True)
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    
    name = Column(String, nullable=False)  # Unique within organization (see __table_args__)
    full_name = Column(String)
    url = Column(Text)
    description = Column(Text)
    default_branch = Column(String)
    language = Column(String)
    owner_type = Column(String)
    owner_id = Column(String)
    business_criticality = Column(String)
    last_scanned_at = Column(DateTime)

    # GitHub API metadata
    pushed_at = Column(DateTime)  # Last push to any branch (from GitHub API)
    github_created_at = Column(DateTime)  # Repo creation date on GitHub
    github_updated_at = Column(DateTime)  # Last metadata update on GitHub
    stargazers_count = Column(Integer, default=0)
    watchers_count = Column(Integer, default=0)
    forks_count = Column(Integer, default=0)
    open_issues_count = Column(Integer, default=0)
    size_kb = Column(Integer, default=0)  # Repository size in KB
    is_fork = Column(Boolean, default=False)
    is_archived = Column(Boolean, default=False)
    is_disabled = Column(Boolean, default=False)
    is_private = Column(Boolean, default=True)
    visibility = Column(String)  # public, private, internal
    topics = Column(JSONB)  # Array of topic tags
    license_name = Column(String)  # e.g., "MIT", "Apache-2.0"
    has_wiki = Column(Boolean, default=False)
    has_pages = Column(Boolean, default=False)
    has_discussions = Column(Boolean, default=False)

    # Self-annealing: Track problematic repos
    failure_count = Column(Integer, default=0)
    last_failure_at = Column(DateTime)
    last_failure_reason = Column(String)

    # Architecture
    architecture_report = Column(Text)
    architecture_diagram = Column(Text) # Python code for diagrams library
    architecture_preprocessed = Column(Text)  # JSON string with preprocessed architecture data
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", backref="repositories")
    scan_runs = relationship("ScanRun", back_populates="repository")
    findings = relationship("Finding", back_populates="repository")
    file_commits = relationship("FileCommit", back_populates="repository")
    contributors = relationship("Contributor", back_populates="repository")
    languages = relationship("LanguageStat", back_populates="repository")
    dependencies = relationship("Dependency", back_populates="repository")
    api_endpoints = relationship("APIEndpoint", back_populates="repository", cascade="all, delete-orphan")
    openapi_spec = relationship("OpenAPISpec", back_populates="repository", uselist=False, cascade="all, delete-orphan")

    # Unique constraint: name must be unique within an organization
    __table_args__ = (
        UniqueConstraint('organization_id', 'name', name='unique_repo_name_per_org'),
    )


class FileCommit(Base):
    """Tracks the last commit information for specific files in a repository.
    Used to provide file-level 'Last Commit' data for findings.
    """
    __tablename__ = "file_commits"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    file_path = Column(Text, nullable=False)
    
    # Commit information from GitHub API
    last_commit_sha = Column(String(40))
    last_commit_date = Column(DateTime)
    last_commit_author = Column(String)
    last_commit_message = Column(Text)
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="file_commits")

    __table_args__ = (
        UniqueConstraint('repository_id', 'file_path', name='uq_file_commits_repo_path'),
    )


# =============================================================================
# SCAN SCHEDULE - Intelligent scanning scheduler
# =============================================================================

class ScanSchedule(Base):
    """
    Defines when a repository should be scanned.
    AI-generated schedules adapt to commit patterns; manual overrides are locked.
    """
    __tablename__ = "scan_schedules"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('scan_schedules_api_id_seq'), unique=True)

    # Multi-tenant scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False)

    # Schedule configuration
    schedule_type = Column(String(20), nullable=False, default="ai")  # 'ai' or 'manual'
    frequency = Column(String(20), nullable=False)  # 'daily', 'weekly', 'bi-weekly', 'monthly'
    day_of_week = Column(Integer)  # 0=Monday, 6=Sunday (for weekly/bi-weekly)
    time_window = Column(String(20), nullable=False)  # 'morning', 'afternoon', 'evening', 'night'

    # Scan arguments (defaults: --target <org> --repo <repo> --overridescan)
    scan_arguments = Column(JSONB, default=lambda: {"overridescan": True})

    # Execution tracking
    next_scheduled_at = Column(DateTime)
    last_executed_at = Column(DateTime)
    last_execution_status = Column(String(20))  # 'success', 'failed', 'running'

    # AI analysis metadata (null for manual schedules)
    ai_reasoning = Column(Text)  # Why AI chose this schedule
    ai_confidence = Column(Numeric(3, 2))  # 0.00-1.00 confidence score
    ai_analyzed_at = Column(DateTime)

    # Lock status
    is_locked = Column(Boolean, default=False)  # True if manually overridden
    locked_at = Column(DateTime)
    locked_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", backref="scan_schedules")
    repository = relationship("Repository", backref="scan_schedule", uselist=False)
    locked_by_user = relationship("User", foreign_keys=[locked_by])

    __table_args__ = (
        UniqueConstraint('repository_id', name='unique_schedule_per_repo'),
    )


class ScheduleOverride(Base):
    """
    Audit log for schedule overrides.
    Tracks when users manually change AI-generated schedules.
    """
    __tablename__ = "schedule_overrides"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('schedule_overrides_api_id_seq'), unique=True)

    schedule_id = Column(UUID(as_uuid=True), ForeignKey("scan_schedules.id", ondelete="CASCADE"), nullable=False)

    # What changed
    previous_frequency = Column(String(20))
    previous_day_of_week = Column(Integer)
    previous_time_window = Column(String(20))
    previous_scan_arguments = Column(JSONB)

    new_frequency = Column(String(20))
    new_day_of_week = Column(Integer)
    new_time_window = Column(String(20))
    new_scan_arguments = Column(JSONB)

    # Who changed it
    override_reason = Column(Text)
    overridden_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    schedule = relationship("ScanSchedule", backref="override_history")
    user = relationship("User", foreign_keys=[overridden_by])


# =============================================================================
# SCAN RUN - Scan execution records
# =============================================================================

class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('scan_runs_api_id_seq'), unique=True)
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    
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
    api_id = Column(Integer, Sequence('findings_api_id_seq'), unique=True)
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    
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
    
    # For secrets: whether the secret was verified as active/valid by TruffleHog
    is_verified_by_scanner = Column(Boolean, default=False)
    # For secrets: whether we independently validated the token is live/active
    is_validated_active = Column(Boolean, default=None, nullable=True)
    validation_message = Column(String, nullable=True)
    validated_at = Column(DateTime, nullable=True)
    
    # Investigation/Incident Response tracking
    investigation_status = Column(String, nullable=True)  # null, 'triage', 'incident_response', 'resolved'
    investigation_started_at = Column(DateTime, nullable=True)
    investigation_resolved_at = Column(DateTime, nullable=True)
    
    # Risk-based prioritization (Phase 1.1)
    risk_score = Column(Integer, nullable=True)  # 0-100 computed risk score
    risk_factors = Column(JSONB, nullable=True)  # Breakdown of score components
    
    # Snooze functionality (Phase 1.2)
    snoozed_until = Column(DateTime, nullable=True)
    snooze_reason = Column(String, nullable=True)
    
    # MTTR tracking (Phase 2.2)
    remediation_started_at = Column(DateTime, nullable=True)
    remediation_completed_at = Column(DateTime, nullable=True)
    
    # AI Triage (Phase 3.2)
    ai_triage_recommendation = Column(String, nullable=True)  # true_positive, false_positive, needs_review
    ai_triage_confidence = Column(Numeric(3, 2), nullable=True)
    ai_triage_reasoning = Column(Text, nullable=True)
    
    # Deduplication (Phase 3.1)
    duplicate_group_id = Column(UUID(as_uuid=True), nullable=True)
    is_primary_in_group = Column(Boolean, default=True)
    
    # Report inclusion - manually include in Critical Insights section
    include_in_report = Column(Boolean, default=False, nullable=True)
    
    # Mobile security findings (MobSF)
    is_mobile_finding = Column(Boolean, default=False, nullable=True)
    
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
    remediations = relationship("Remediation", back_populates="finding")
    journal_entries = relationship("JournalEntry", back_populates="finding", order_by="desc(JournalEntry.created_at)")

class Remediation(Base):
    __tablename__ = "remediations"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('remediations_api_id_seq'), unique=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"))
    
    remediation_text = Column(Text)
    diff = Column(Text)
    confidence = Column(Numeric(3, 2))
    
    created_at = Column(DateTime, server_default=func.now())
    
    finding = relationship("Finding", back_populates="remediations")

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('users_api_id_seq'), unique=True)
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
    api_id = Column(Integer, Sequence('finding_history_api_id_seq'), unique=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"))
    changed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    change_type = Column(String)
    old_value = Column(Text)
    new_value = Column(Text)
    comment = Column(Text)
    change_metadata = Column(JSONB)
    created_at = Column(DateTime, server_default=func.now())

    finding = relationship("Finding", back_populates="history")

class FindingComment(Base):
    __tablename__ = "finding_comments"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('finding_comments_api_id_seq'), unique=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"))
    author_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    comment_text = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now())

    finding = relationship("Finding", back_populates="comments")


class JournalEntry(Base):
    """Investigation journal entries for tracking analyst notes and communications."""
    __tablename__ = "journal_entries"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    
    # Entry content
    entry_text = Column(Text, nullable=False)
    entry_type = Column(String, default='note')  # 'note', 'status_change', 'ai_response', 'communication'
    
    # Author tracking (optional - for future user auth)
    author_name = Column(String, default='Analyst')
    author_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    # AI interaction tracking
    is_ai_generated = Column(Boolean, default=False)
    ai_prompt = Column(Text, nullable=True)  # The question asked to AI
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    
    # Relationships
    finding = relationship("Finding", back_populates="journal_entries")
    author = relationship("User")


class SystemConfig(Base):
    __tablename__ = "system_config"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    key = Column(String, unique=True, nullable=False)
    value = Column(Text)
    description = Column(Text)
    is_encrypted = Column(Boolean, default=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class ArchitectureVersion(Base):
    __tablename__ = "architecture_versions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    version_number = Column(Integer, nullable=False)
    report_content = Column(Text)
    diagram_code = Column(Text)
    description = Column(Text)
    created_at = Column(DateTime, server_default=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    repository = relationship("Repository", back_populates="architecture_versions")
    creator = relationship("User")

class Contributor(Base):
    __tablename__ = "contributors"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    name = Column(String, nullable=False)
    email = Column(String)
    github_username = Column(String)
    commits = Column(Integer, default=0)
    commit_percentage = Column(Numeric(5, 2))
    last_commit_at = Column(DateTime)
    languages = Column(JSONB)  # Store inferred languages as JSON array

    # Enhanced file tracking with severity data
    # Format: [{"path": "src/api.py", "severity": "high", "findings_count": 3}, ...]
    files_contributed = Column(JSONB, default=[])
    folders_contributed = Column(JSONB, default=[])  # ["src", "tests", "config", ...]

    # Risk and AI analysis
    risk_score = Column(Integer, default=0)  # 0-100 calculated risk
    ai_summary = Column(Text)  # AI-generated contributor analysis

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="contributors")

class LanguageStat(Base):
    __tablename__ = "language_stats"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    name = Column(String, nullable=False)
    files = Column(Integer, default=0)
    lines = Column(Integer, default=0) # Code lines
    blanks = Column(Integer, default=0)
    comments = Column(Integer, default=0)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="languages")

class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    name = Column(String, nullable=False)
    version = Column(String)
    type = Column(String) # e.g. npm, pypi, go
    package_manager = Column(String)
    license = Column(String)
    locations = Column(JSONB) # List of file paths
    source = Column(String) # Developer/Vendor
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="dependencies")


class APIEndpoint(Base):
    """Discovered API endpoint from code analysis."""
    __tablename__ = "api_endpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    
    # Endpoint details
    endpoint_url = Column(String, nullable=False)  # Full URL or path pattern
    http_method = Column(String)  # GET, POST, PUT, DELETE, etc.
    direction = Column(String, nullable=False)  # 'serves' or 'outbound'
    auth_method = Column(String)  # bearer, api-key, basic, oauth2, none, etc.
    
    # Code location
    file_path = Column(Text)
    line_number = Column(Integer)
    code_snippet = Column(Text)
    
    # Framework detection
    framework = Column(String)  # fastapi, flask, express, spring, etc.
    
    # Metadata from semgrep
    rule_id = Column(String)
    confidence = Column(String)  # high, medium, low
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    repository = relationship("Repository", back_populates="api_endpoints")


class OpenAPISpec(Base):
    """Stored OpenAPI specifications for repositories."""
    __tablename__ = "openapi_specs"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), unique=True)
    
    # OpenAPI content
    spec_content = Column(Text)  # YAML or JSON content
    spec_format = Column(String, default='yaml')  # yaml or json
    version = Column(String, default='3.0.3')  # OpenAPI version
    
    # Generation metadata
    generated_at = Column(DateTime, server_default=func.now())
    endpoint_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    repository = relationship("Repository", back_populates="openapi_spec")

from sqlalchemy import UniqueConstraint

# ... (imports are at top of file, need to ensure UniqueConstraint is imported or use sqlalchemy.UniqueConstraint if I can't add import easily)

class ComponentAnalysis(Base):
    __tablename__ = "component_analysis"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    package_name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    package_manager = Column(String, nullable=False)
    
    analysis_text = Column(Text)
    vulnerability_summary = Column(Text)
    severity = Column(String)
    exploitability = Column(String)
    fixed_version = Column(String)
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Unique constraint to ensure we don't analyze the same package version multiple times
    __table_args__ = (
        UniqueConstraint('package_name', 'version', 'package_manager', name='uq_component_analysis'),
    )

# Update Repository relationship
Repository.architecture_versions = relationship("ArchitectureVersion", back_populates="repository", order_by="desc(ArchitectureVersion.version_number)")
Repository.contributors = relationship("Contributor", back_populates="repository", cascade="all, delete-orphan")
Repository.languages = relationship("LanguageStat", back_populates="repository", cascade="all, delete-orphan")
Repository.dependencies = relationship("Dependency", back_populates="repository", cascade="all, delete-orphan")


# =============================================================================
# CONTRIBUTOR PROFILE - Unified Identity Management
# =============================================================================

class ContributorProfile(Base):
    """
    Unified contributor identity that aggregates all aliases (emails, usernames).
    Designed to integrate with Entra ID for employment status verification.
    """
    __tablename__ = "contributor_profiles"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Canonical identity (preferred display)
    display_name = Column(String, nullable=False)  # "Isaac Springer"
    primary_email = Column(String, unique=True)  # Preferred email (usually corporate domain)
    primary_github_username = Column(String)  # Primary GitHub handle
    
    # Entra ID / Azure AD integration
    entra_id_object_id = Column(String, unique=True)  # Azure AD Object ID (GUID)
    entra_id_upn = Column(String)  # User Principal Name (email-like identifier)
    entra_id_employee_id = Column(String)  # Employee ID from HR system
    entra_id_job_title = Column(String)
    entra_id_department = Column(String)
    entra_id_manager_upn = Column(String)  # Manager's UPN for escalation
    
    # Employment status
    employment_status = Column(String, default='unknown')  # active, inactive, terminated, contractor, unknown
    employment_verified_at = Column(DateTime)  # Last time we verified with Entra ID
    employment_start_date = Column(DateTime)
    employment_end_date = Column(DateTime)  # Termination date if known
    
    # Aggregated stats (computed from all linked Contributors)
    total_repos = Column(Integer, default=0)
    total_commits = Column(Integer, default=0)
    last_activity_at = Column(DateTime)  # Most recent commit across all repos
    first_activity_at = Column(DateTime)  # Earliest known commit
    
    # Risk assessment
    risk_score = Column(Integer, default=0)  # 0-100 calculated risk
    is_stale = Column(Boolean, default=False)  # No activity in 90+ days
    has_elevated_access = Column(Boolean, default=False)  # Has access to sensitive repos
    files_with_findings = Column(Integer, default=0)
    critical_files_count = Column(Integer, default=0)
    
    # AI analysis
    ai_identity_confidence = Column(Numeric(3, 2))  # Confidence in identity merging
    ai_summary = Column(Text)  # AI-generated profile analysis
    
    # Metadata
    is_verified = Column(Boolean, default=False)  # Manually verified by admin
    verified_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    verified_at = Column(DateTime)
    notes = Column(Text)  # Admin notes
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    aliases = relationship("ContributorAlias", back_populates="profile", cascade="all, delete-orphan")
    verifier = relationship("User")


class ContributorAlias(Base):
    """
    An alias (email, username, name variation) linked to a ContributorProfile.
    Allows tracking all the different identities a single person has used.
    """
    __tablename__ = "contributor_aliases"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    profile_id = Column(UUID(as_uuid=True), ForeignKey("contributor_profiles.id"), nullable=False)
    
    # Identity information
    alias_type = Column(String, nullable=False)  # 'email', 'github_username', 'name'
    alias_value = Column(String, nullable=False)  # The actual value
    is_primary = Column(Boolean, default=False)  # Is this the preferred alias of its type?
    
    # Source tracking
    source = Column(String)  # 'git_log', 'github_api', 'entra_id', 'manual'
    first_seen_at = Column(DateTime)
    last_seen_at = Column(DateTime)
    
    # Match metadata
    match_confidence = Column(Numeric(3, 2))  # How confident was the matching algorithm
    match_reason = Column(String)  # 'exact_email', 'same_full_name', 'github_matches_email', etc.
    
    created_at = Column(DateTime, server_default=func.now())
    
    # Relationships
    profile = relationship("ContributorProfile", back_populates="aliases")
    
    __table_args__ = (
        UniqueConstraint('alias_type', 'alias_value', name='uq_contributor_alias'),
    )


# Add link from Contributor to ContributorProfile
Contributor.profile_id = Column(UUID(as_uuid=True), ForeignKey("contributor_profiles.id"), nullable=True)
Contributor.profile = relationship("ContributorProfile", backref="contributors")


# =============================================================================
# MULTI-TENANT ARCHITECTURE
# =============================================================================

class Tenant(Base):
    """
    Represents a tenant (GitHub organization) in the multi-tenant system.
    
    Each tenant has:
    - A unique slug for URL-safe identification
    - Connection details for their isolated database
    - Schema version tracking for migration sync
    """
    __tablename__ = "tenants"
    
    # Primary Key
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Identification
    slug = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    github_org = Column(String(255), nullable=False)
    
    # Database Connection
    database_host = Column(String(255), default="db")
    database_port = Column(Integer, default=5432)
    database_name = Column(String(100), nullable=False)
    database_user = Column(String(100), default="auditgh")
    database_password = Column(String(255), default="auditgh_secret")
    
    # Status
    is_active = Column(Boolean, default=True)
    is_provisioned = Column(Boolean, default=False)
    
    # Schema Version Tracking
    schema_version = Column(String(50))
    last_migration_at = Column(DateTime)
    migration_status = Column(String(20), default="pending")  # pending, current, behind, error
    migration_error = Column(Text)
    
    # Metadata
    description = Column(Text)
    settings = Column(Text)  # JSON string for tenant-specific settings
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    @property
    def database_url(self) -> str:
        """Generate the SQLAlchemy database URL for this tenant."""
        return (
            f"postgresql://{self.database_user}:{self.database_password}"
            f"@{self.database_host}:{self.database_port}/{self.database_name}"
        )
    
    def __repr__(self):
        return f"<Tenant(slug='{self.slug}', github_org='{self.github_org}', active={self.is_active})>"


# =============================================================================
# API AUDIT ENHANCEMENTS
# =============================================================================

class APIPathDictionary(Base):
    """
    Dictionary of words/phrases used in API paths for fuzzing.
    """
    __tablename__ = "api_audit_path_dictionary"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    word = Column(String(100), unique=True, nullable=False, index=True)
    category = Column(String(50), nullable=True)  # e.g., 'common', 'financial', 'tech'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<APIPathDictionary(word='{self.word}')>"


class APIURILibrary(Base):
    """
    Library of full URIs/URLs for AI learning and schema understanding.
    """
    __tablename__ = "api_audit_uri_library"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    uri = Column(Text, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    source = Column(String(50), default="manual")  # 'manual', 'discovery', 'imported'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<APIURILibrary(uri='{self.uri[:50]}...')>"


class CredentialUrlTestResult(Base):
    """
    Stores comprehensive results from the AI Credential-URL Testing Agent.
    Includes authentication status, discovered paths, OSINT findings, and AI analysis.
    Multi-tenant: Scoped to organization via organization_id.
    """
    __tablename__ = "credential_url_test_results"

    # Primary identifiers
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('credential_url_test_results_api_id_seq'), unique=True)
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"))
    
    # Target Information
    target_url = Column(Text, nullable=False)
    credential_type = Column(String(100))
    credential_value = Column(Text)
    credential_environment = Column(String(50))
    confidence_score = Column(Integer)
    
    # Authentication Results
    auth_status = Column(String(20), default='not_tested')  # 'yes', 'failed', 'not_tested'
    auth_status_code = Column(Integer)
    auth_response_time_ms = Column(Integer)
    auth_error_message = Column(Text)
    auth_headers_used = Column(JSONB, default=[])
    
    # Raw Request/Response capture
    auth_request_method = Column(String(10), default='GET')
    auth_request_url = Column(Text)
    auth_request_headers = Column(JSONB, default={})
    auth_request_body = Column(Text, default='')
    auth_response_headers = Column(JSONB, default={})
    auth_response_body = Column(Text, default='')
    auth_response_body_truncated = Column(Boolean, default=False)
    
    # Service Detection
    detected_service = Column(String(100))
    service_detection_score = Column(Integer, default=0)
    
    # Path Discovery Results
    discovered_paths = Column(JSONB, default=[])  # [{method, path, status_code, sample_data, success}]
    discovered_paths_count = Column(Integer, default=0)
    hidden_paths_found = Column(Integer, default=0)
    
    # Data Sampling
    sample_data_retrieved = Column(JSONB, default=[])
    data_sensitivity_indicators = Column(JSONB, default=[])  # PII, credentials, etc.
    
    # OSINT Results
    osint_findings = Column(JSONB, default=[])  # [{url, type, description, relevance}]
    github_repos_found = Column(Integer, default=0)
    documentation_links_found = Column(Integer, default=0)
    
    # AI Analysis
    ai_overview = Column(Text)  # Executive summary
    ai_risk_assessment = Column(Text)
    ai_recommendations = Column(JSONB, default=[])
    threat_level = Column(String(20))  # 'critical', 'high', 'medium', 'low', 'info'
    
    # Test Configuration
    test_mode = Column(String(20), default='cautious')  # 'none', 'cautious', 'insane'
    
    # Metadata
    tested_at = Column(DateTime)
    test_duration_seconds = Column(Integer)
    llm_provider = Column(String(50))
    llm_model = Column(String(100))
    raw_llm_responses = Column(JSONB, default=[])
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", backref="credential_url_test_results")
    repository = relationship("Repository", backref="credential_url_test_results")

    def __repr__(self):
        return f"<CredentialUrlTestResult(target_url='{self.target_url[:50]}...', auth_status='{self.auth_status}')>"


class CredentialUrlTestStatus(Base):
    """
    Tracks auto-test initialization status per project.
    Prevents re-testing on every page load - only tests on first load.
    Multi-tenant: Scoped to organization via organization_id.
    """
    __tablename__ = "credential_url_test_status"

    # Primary identifiers
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('credential_url_test_status_api_id_seq'), unique=True)
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"))
    
    # Status tracking
    initial_test_completed = Column(Boolean, default=False)
    initial_test_at = Column(DateTime)
    total_correlations_tested = Column(Integer, default=0)
    total_correlations_found = Column(Integer, default=0)
    last_test_at = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", backref="credential_url_test_statuses")
    repository = relationship("Repository", backref="credential_url_test_status")

    def __repr__(self):
        return f"<CredentialUrlTestStatus(repo_id='{self.repository_id}', initial_completed={self.initial_test_completed})>"


class CriblConfig(Base):
    """Configuration for Cribl Stream log management integration. Singleton table."""
    __tablename__ = "cribl_config"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(BigInteger, unique=True, nullable=False, autoincrement=True)
    
    # Connection settings
    ingest_url = Column(String(500))
    auth_token = Column(String(500))
    verify_ssl = Column(Boolean, default=True)
    
    # Feature toggles
    enabled = Column(Boolean, default=False)
    log_levels = Column(ARRAY(String), default=['INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    include_app_context = Column(Boolean, default=True)
    include_security_audit = Column(Boolean, default=True)
    minio_fallback = Column(Boolean, default=True)
    
    # MinIO settings (for local storage/fallback)
    minio_endpoint = Column(String(500), default='http://minio:9000')
    minio_bucket = Column(String(100), default='auditgh-logs')
    minio_access_key = Column(String(200))
    minio_secret_key = Column(String(200))
    
    # Test status
    last_test_at = Column(DateTime)
    last_test_status = Column(String(50), default='PENDING')
    last_test_message = Column(Text)
    
    # Audit fields
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<CriblConfig(enabled={self.enabled}, ingest_url='{self.ingest_url}')>"

