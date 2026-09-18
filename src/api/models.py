from sqlalchemy import Column, String, Integer, BigInteger, Boolean, DateTime, Float, ForeignKey, Text, JSON, Numeric, Sequence, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func, text
from .database import Base
import uuid


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
    
    name = Column(String(255), unique=True, nullable=False)  # Internal name (e.g., "my-org")
    github_org = Column(String(255), nullable=False)  # GitHub organization name
    display_name = Column(String(255))  # Human-readable name
    database_name = Column(String(255))  # Per-org database name
    
    is_default = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<Organization(name='{self.name}', github_org='{self.github_org}')>"


class OrganizationCredential(Base):
    """
    A credential AuditGithub owns, rather than borrows from the operator's shell.

    Before this table, every GitHub call read GITHUB_TOKEN from the process
    environment. That meant the tool's effective privilege was whatever the last
    person to export a variable happened to hold, it was identical across all three
    orgs, and nothing recorded what that privilege actually was. The consequence was
    concrete: three private Digital repositories are invisible in the sleepnumber
    scan and org-level runner enumeration returns 403, because the borrowed token is
    an org member and not an owner — a fact discoverable only by watching scans fail.

    So: one row per (organization, credential type), value encrypted at rest via
    src/api/secrets_store.py, and the granted privilege recorded as data next to it.
    A hunt that cannot see a surface must be able to say so, which requires knowing
    what it was allowed to see.

    organization_id is nullable. NULL means tenant-wide rather than per-org, which is
    how the Microsoft Graph application credential is held — one Entra app serves all
    three GitHub orgs because they live in a single tenant.
    """
    __tablename__ = "organization_credentials"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('organization_credentials_api_id_seq'), unique=True)

    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )

    # github_pat | github_app | graph_app | generic
    credential_type = Column(String(64), nullable=False)
    # Distinguishes multiple credentials of the same type (e.g. "read-only", "owner")
    name = Column(String(128), nullable=False, default="default")
    description = Column(Text)

    # Fernet ciphertext, prefixed "enc:v1:". Never read this column directly —
    # go through secrets_store.decrypt so an unreadable value raises instead of
    # being handed to an HTTP client as if it were a token.
    encrypted_value = Column(Text)
    is_encrypted = Column(Boolean, default=True, nullable=False)
    # Fingerprint of the master key used, so a key rotation is diagnosable rather
    # than presenting as mass authentication failure.
    key_fingerprint = Column(String(32))

    # Non-secret companions to the secret — a client ID is not confidential, and
    # keeping it in plaintext means the UI can show which app is configured without
    # a decrypt.
    client_id = Column(String(128))
    tenant_id_value = Column(String(128))

    # Recorded privilege, not inferred privilege.
    # For github_pat: owner | member | outside_collaborator | unknown
    privilege_level = Column(String(64), default="unknown")
    # Token scopes as reported by the provider (GitHub returns them in the
    # X-OAuth-Scopes response header), stored verbatim.
    scopes = Column(JSONB, server_default='[]')
    # Surfaces this credential is known NOT to reach, from observed failures.
    # e.g. ["actions:org-runners (403)", "repo:private/digital-* (404)"]
    known_gaps = Column(JSONB, server_default='[]')

    # Length only — enough to classify and to detect truncation, never the value.
    value_length = Column(Integer)
    value_suffix = Column(String(8))

    expires_at = Column(DateTime, nullable=True)
    last_verified_at = Column(DateTime, nullable=True)
    # ok | unauthorized | forbidden | expired | error | unverified
    last_verification_status = Column(String(32), default="unverified")
    last_verification_detail = Column(Text)

    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    organization = relationship("Organization")

    __table_args__ = (
        # Per-org uniqueness. NULLs compare as distinct in Postgres, so this does
        # not constrain tenant-wide rows — those are covered by the partial unique
        # index created in migration 022.
        UniqueConstraint('organization_id', 'credential_type', 'name',
                         name='uq_org_credential'),
        Index('idx_org_credentials_org', 'organization_id'),
        Index('idx_org_credentials_type', 'credential_type'),
    )

    def __repr__(self):
        return (f"<OrganizationCredential(type='{self.credential_type}', "
                f"name='{self.name}', privilege='{self.privilege_level}')>")


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
    operations = relationship("RepositoryOperations", back_populates="repository", uselist=False, cascade="all, delete-orphan")

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


class CommitAnalysis(Base):
    """
    Cached commit analysis results for AI scheduling decisions.
    Stores patterns, file types, and contributor activity to avoid repeated GitHub API calls.
    """
    __tablename__ = "commit_analyses"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)

    # Analysis results (JSONB for flexibility)
    analysis_data = Column(JSONB, nullable=False)

    # Cache metadata
    commit_count = Column(Integer, nullable=False, default=0)
    last_commit_sha = Column(String(40))  # Track newest commit analyzed
    is_dormant = Column(Boolean, default=False)

    # Timestamps
    analyzed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)  # Cache TTL

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    repository = relationship("Repository", backref="commit_analyses")
    organization = relationship("Organization")

    # Indexes and constraints
    __table_args__ = (
        Index("ix_commit_analyses_repository_id", "repository_id"),
        Index("ix_commit_analyses_expires_at", "expires_at"),
        UniqueConstraint("repository_id", name="uq_commit_analyses_repository"),
    )


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

    # Rule identity (migration 023). Several scanners emit their rule ID only
    # inside the title; src/services/remediation_classifier.py recovers it.
    # rule_id_is_stable is False when the recovered value is a check name in
    # prose rather than an identifier, and so may be reworded upstream.
    rule_id = Column(String, nullable=True)
    rule_id_is_stable = Column(Boolean, nullable=True)
    # grype reports GitHub advisories, which are not CVEs and do not belong in cve_id
    ghsa_id = Column(String, nullable=True)

    # Remediation category (migration 023). NULL means not yet classified,
    # which is distinct from every value in the taxonomy including false_positive.
    remediation_category = Column(String, nullable=True)
    category_source = Column(String, default='none')  # rule | ai | human | none
    category_confidence = Column(Float, nullable=True)
    category_rationale = Column(Text, nullable=True)
    category_assigned_at = Column(DateTime, nullable=True)

    # Kept and counted, but left out of the actionable work list. Distinct from
    # deletion (the evidence survives) and from false_positive (excluding a
    # filename-only match says the scanner never opened the file, not that the
    # file is clean). Reason is always recorded; an exclusion with no stated
    # basis is indistinguishable from data loss.
    excluded_from_actionable = Column(Boolean, default=False)
    exclusion_reason = Column(Text, nullable=True)

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


class RemediationAction(Base):
    """One piece of work, covering one or many findings.

    Distinct from Remediation above, which is per-finding AI-generated text.
    An action is the unit that gets estimated, owned, and filed as an
    AuditBoard issue: upgrading lodash once closes every lodash finding in the
    organization, and estimating that work forty times would overstate it forty
    times over.

    Scope is per-organization, so an action spans the repositories of one org.
    """

    __tablename__ = "remediation_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('remediation_actions_api_id_seq'), unique=True)

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)

    # Deterministic, e.g. "upgrade:npm:lodash:4.17.21". Re-running the grouper
    # produces the same key, which is what makes the AuditBoard push idempotent.
    action_key = Column(String, nullable=False)

    category = Column(String, nullable=False)
    title = Column(String, nullable=False)
    remediation_text = Column(Text)

    # Estimated, not measured. Never converted to hours — see src/services/effort.py.
    effort_band = Column(String)
    effort_score = Column(Integer)
    effort_reasons = Column(JSONB, default=list)
    # Drivers that could not be measured. Non-empty means the band rests partly
    # on absent data, and the report says so next to it.
    effort_unknowns = Column(JSONB, default=list)

    # Measured drivers, refreshed by the grouper. Never hand-edited.
    findings_count = Column(Integer, default=0)
    files_count = Column(Integer, default=0)
    repos_count = Column(Integer, default=0)
    severity_counts = Column(JSONB, default=dict)

    primary_role = Column(String)
    supporting_roles = Column(JSONB, default=list)

    package_ecosystem = Column(String)
    package_name = Column(String)
    current_version = Column(String)
    fixed_version = Column(String)

    status = Column(String, default='open')
    owner_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # NULL means never pushed. This schema cannot detect an issue deleted at the
    # far end, so a non-NULL value proves we created one, not that it still exists.
    auditboard_issue_id = Column(String, nullable=True)
    auditboard_instance = Column(String, nullable=True)
    auditboard_pushed_at = Column(DateTime, nullable=True)
    auditboard_push_status = Column(String, default='not_pushed')
    auditboard_push_detail = Column(Text)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint('organization_id', 'action_key', name='uq_remediation_action_key'),
    )

    findings = relationship("RemediationActionFinding", back_populates="action", cascade="all, delete-orphan")


class RemediationActionFinding(Base):
    """Which findings one action covers.

    The many-to-many that makes "this single upgrade closes these forty
    findings" a queryable fact rather than an assertion in report prose.
    """

    __tablename__ = "remediation_action_findings"

    action_id = Column(UUID(as_uuid=True), ForeignKey("remediation_actions.id", ondelete="CASCADE"), primary_key=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    # Denormalised so repos_count does not require a join back to findings.
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    action = relationship("RemediationAction", back_populates="findings")
    finding = relationship("Finding")


class FindingKnowledgeBase(Base):
    """One entry per unique finding signature, reusable across organizations.

    Not per occurrence: the 222,844 actionable findings in this estate resolve
    to 2,639 distinct signatures, and the ten largest cover half of them. The
    key is derived at read time by src/services/kb_key.py rather than stored on
    findings, so a change to key precedence does not require a backfill.
    """

    __tablename__ = "finding_knowledge_base"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('finding_kb_api_id_seq'), unique=True)

    # ghsa:… | cve:… | rule:{scanner}/{rule_id} | cwe:…
    kb_key = Column(String(512), nullable=False, unique=True)
    key_type = Column(String(16), nullable=False)

    cve_id = Column(String(32))
    cwe_id = Column(String(32))
    ghsa_id = Column(String(32))
    rule_id = Column(String(512))
    scanner_name = Column(String(64))
    # False when the key rests on prose upstream may reword (trivy-fs, nuclei).
    key_is_stable = Column(Boolean, nullable=False, default=True)

    title = Column(Text, nullable=False)
    summary = Column(Text)
    reference_ids = Column(JSONB, default=list)

    target_asset_type = Column(String(32))
    target_asset_detail = Column(Text)

    # What an attacker gains — exploitation, not regulatory. Regulatory blast
    # radius is sec-diligence's blast_radius.py and is a different thing.
    blast_radius = Column(JSONB)
    # CWE -> CAPEC -> ATT&CK, derived from committed MITRE data. mapping_source
    # is 'none' whenever no published mapping exists, which is the common case
    # here: findings.cwe_id carries no usable CWE anywhere in this estate.
    ttp = Column(JSONB)
    exploitability = Column(JSONB)
    mitigation_options = Column(JSONB, default=list)

    upstream_severity = Column(String(16))
    # Advisories get retracted. Remediating a withdrawn one is wasted work.
    is_withdrawn = Column(Boolean, nullable=False, default=False)
    affected_packages = Column(JSONB, default=list)

    status = Column(String(16), nullable=False, default='draft')
    version = Column(Integer, nullable=False, default=1)
    # import = fetched and citable, ai = generated, human = authored. Same
    # discipline as Finding.category_source: never count the three as one.
    source = Column(String(16), nullable=False, default='ai')
    ai_confidence = Column(Numeric(3, 2))
    source_url = Column(Text)
    source_fetched_at = Column(DateTime)

    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    approved_at = Column(DateTime)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    versions = relationship("FindingKBVersion", back_populates="kb_entry",
                            cascade="all, delete-orphan")
    overlays = relationship("FindingKBOrgOverlay", back_populates="kb_entry",
                            cascade="all, delete-orphan")

    @property
    def is_renderable(self) -> bool:
        """Only approved entries reach a report. A draft renders as
        'knowledge base entry pending review', never as its own text."""
        return self.status == 'approved'


class FindingKBVersion(Base):
    """Full snapshot per approved edit, mirroring PromptVersion.

    A snapshot rather than a diff: a diff chain only replays while every link
    survives, and the point of this table is re-rendering a months-old report
    against the knowledge base as it stood when the report was issued.
    """

    __tablename__ = "finding_kb_versions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    kb_id = Column(UUID(as_uuid=True), ForeignKey("finding_knowledge_base.id", ondelete="CASCADE"),
                   nullable=False)
    version = Column(Integer, nullable=False)
    snapshot = Column(JSONB, nullable=False)
    change_note = Column(Text)
    changed_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, server_default=func.now())

    kb_entry = relationship("FindingKnowledgeBase", back_populates="versions")

    __table_args__ = (UniqueConstraint('kb_id', 'version', name='uq_kb_version'),)


class FindingKBOrgOverlay(Base):
    """An organization's local standards for a global knowledge base entry.

    Kept separate so the global entry stays generic and reusable. The report
    merges the overlay over the global entry and labels any overlaid row as
    organization-specific, so a reader can tell house policy from published
    guidance.
    """

    __tablename__ = "finding_kb_org_overlays"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    kb_id = Column(UUID(as_uuid=True), ForeignKey("finding_knowledge_base.id", ondelete="CASCADE"),
                   nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
                             nullable=False)
    # 'append' adds to the global options; 'replace' overrides them. Explicit,
    # because "we have one too" and "the generic advice is wrong here" differ.
    mitigation_mode = Column(String(16), nullable=False, default='append')
    mitigation_options = Column(JSONB, default=list)
    notes = Column(Text)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    kb_entry = relationship("FindingKnowledgeBase", back_populates="overlays")

    __table_args__ = (UniqueConstraint('kb_id', 'organization_id', name='uq_kb_org_overlay'),)


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('users_api_id_seq'), unique=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    full_name = Column(String)

    # RBAC fields
    role = Column(String, nullable=False, default='user')  # super_admin, admin, manager, analyst, developer, user
    access_type = Column(String, nullable=False, default='both')  # ui_only, api_only, both

    # Break glass authentication (only for BREAK_GLASS_EMAIL)
    local_password_hash = Column(String, nullable=True)  # bcrypt hash

    # OIDC fields (provider-agnostic — stable identifier across any OIDC provider)
    oidc_subject = Column(String, unique=True, nullable=True, index=True)  # OIDC 'sub' claim
    oidc_issuer = Column(String, nullable=True)  # OIDC issuer URL (identifies which provider)

    # Entra ID fields (backward compatible, populated only for Entra logins)
    entra_id_object_id = Column(String, unique=True, nullable=True)  # Azure AD Object ID
    entra_id_upn = Column(String, nullable=True)  # User Principal Name
    auth_provider = Column(String, default='entra')  # entra, okta, mock-oidc, local

    # Status
    is_invited = Column(Boolean, default=False)
    first_login_at = Column(DateTime, nullable=True)

    # Legacy fields
    github_username = Column(String)
    jira_username = Column(String)
    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    is_service_account = Column(Boolean, default=False)

    assigned_findings = relationship("Finding", back_populates="assignee")
    api_keys = relationship("ApiKey", back_populates="user")


# =============================================================================
# USER INVITATIONS - Email-based user invitation system
# =============================================================================

class UserInvitation(Base):
    """Email invitation system for onboarding new users."""
    __tablename__ = "user_invitations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    api_id = Column(Integer, Sequence('user_invitations_api_id_seq'), unique=True)
    email = Column(String, nullable=False, index=True)
    invite_token = Column(String(64), unique=True, nullable=False, index=True)  # cryptographic token

    # Invitation metadata
    invited_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)  # Null for system/bootstrap invitations
    invited_role = Column(String, nullable=False, default='user')  # Initial role
    invited_access_type = Column(String, nullable=False, default='ui_only')

    # Status
    status = Column(String, default='pending')  # pending, accepted, expired, revoked

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)  # 7 days from creation
    accepted_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    inviter = relationship("User", foreign_keys=[invited_by])


# =============================================================================
# USER REPOSITORY ACCESS - Repository-level permissions
# =============================================================================

class UserRepositoryAccess(Base):
    """Maps users to repositories they can access."""
    __tablename__ = "user_repository_access"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    api_id = Column(Integer, Sequence('user_repository_access_api_id_seq'), unique=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('repositories.id', ondelete='CASCADE'), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False)

    # Assigned by
    assigned_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    assigned_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    repository = relationship("Repository")
    assigner = relationship("User", foreign_keys=[assigned_by])

    __table_args__ = (
        UniqueConstraint('user_id', 'repository_id', name='uq_user_repo_access'),
    )


# =============================================================================
# USER ORGANIZATION ACCESS - Organization-level permissions
# =============================================================================

class UserOrganizationAccess(Base):
    """Maps users to organizations they can access.

    Super admins and admins implicitly have access to ALL organizations.
    Manager, analyst, and user roles must be explicitly assigned.
    """
    __tablename__ = "user_organization_access"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)

    assigned_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    assigned_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", foreign_keys=[user_id])
    organization = relationship("Organization")
    assigner = relationship("User", foreign_keys=[assigned_by])

    __table_args__ = (
        UniqueConstraint('user_id', 'organization_id', name='uq_user_org_access'),
    )


# =============================================================================
# AUTH AUDIT LOG - Authentication event logging
# =============================================================================

class AuthAuditLog(Base):
    """Audit log for authentication events."""
    __tablename__ = "auth_audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    api_id = Column(Integer, Sequence('auth_audit_log_api_id_seq'), unique=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)  # Null for failed logins
    email = Column(String, nullable=False, index=True)

    # Event details
    event_type = Column(String, nullable=False)  # login, logout, invite_sent, invite_accepted, role_changed, etc.
    auth_method = Column(String)  # entra, local, device_flow
    success = Column(Boolean, default=True)
    failure_reason = Column(String, nullable=True)

    # Context
    ip_address = Column(String(45))
    user_agent = Column(String(500))

    # Break glass indicator
    is_break_glass = Column(Boolean, default=False)

    # Extra data (JSON for flexibility)
    extra_data = Column(JSONB, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", foreign_keys=[user_id])


# =============================================================================
# API KEYS - Programmatic API key authentication
# =============================================================================

class ApiKey(Base):
    """API key for programmatic access with tool/repo scoping and rate limiting."""
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('api_keys_api_id_seq'), unique=True)

    # Ownership
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False)

    # Key identity
    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    key_prefix = Column(String(12), nullable=False)

    # Tool scoping (hierarchical) — NULL = all tools allowed
    allowed_tool_categories = Column(JSONB, nullable=True)
    allowed_tools = Column(JSONB, nullable=True)

    # Repository scoping — NULL = all repos the owner has access to
    allowed_repository_ids = Column(JSONB, nullable=True)

    # RBAC override — NULL = inherit all owner permissions
    permission_overrides = Column(JSONB, nullable=True)

    # Rate limiting
    rate_limit_per_hour = Column(Integer, nullable=False, default=1000)

    # Lifecycle
    is_active = Column(Boolean, nullable=False, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    last_used_ip = Column(String(45), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="api_keys")
    organization = relationship("Organization")

    __table_args__ = (
        UniqueConstraint('user_id', 'organization_id', 'name', name='uq_api_keys_user_name'),
    )


class ApiKeyAuditLog(Base):
    """Audit log for API key lifecycle events."""
    __tablename__ = "api_key_audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('api_key_audit_log_api_id_seq'), unique=True)

    api_key_id = Column(UUID(as_uuid=True), ForeignKey('api_keys.id', ondelete='SET NULL'), nullable=True)
    actor_user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    event_type = Column(String(50), nullable=False)  # created, revoked, rotated, used, expired, permission_denied
    event_detail = Column(JSONB, default={})

    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    api_key = relationship("ApiKey")
    actor = relationship("User", foreign_keys=[actor_user_id])


# =============================================================================
# SANDBOX API KEY — Only used when SANDBOX_MODE=true
# =============================================================================

class SandboxApiKey(Base):
    """
    Pre-generated API keys for the sandbox environment.

    Unlike production ApiKey, these store the plaintext key_value so it can
    be displayed publicly on the sandbox landing page.  This table only
    exists in the auditgh_sandbox database.
    """
    __tablename__ = "sandbox_api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    name = Column(String(100), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    key_value = Column(String(64), nullable=False)  # plaintext — safe for sandbox display
    role = Column(String(50), nullable=False, default="viewer")
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


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


class AuditBoardIssue(Base):
    """A finding that was filed into AuditBoard, and the issue it became.

    Written only after AuditBoard confirms the create, and from AuditBoard's
    own response — never from what we asked for. A row here means the record
    exists over there; no row means it does not, or nobody filed it yet.

    Rows are kept when a finding is deleted rather than cascaded away: the
    GRC issue outlives the scan result, and a filing history that disappears
    with its source is not an audit trail. Hence the plain finding_id column
    with no foreign key.

    ``scope`` is the same vocabulary as everywhere else in this app. A global
    filing speaks for every finding sharing scanner_name and file_path, so
    those two are stored alongside the reference finding — they are how the
    UI knows a sibling finding has already been reported.
    """
    __tablename__ = "auditboard_issues"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))

    # Reference finding — the one the filer had open. Deliberately not a
    # ForeignKey: see the class docstring.
    finding_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), nullable=True, index=True)

    # Group key, for matching a filing to the findings it speaks for.
    #
    # ``scope`` is the tier: 'specific', 'project', 'org', or 'global' for
    # rows filed before 2026-09-16. 'global' keyed on (scanner_name,
    # file_path), which is why those two columns exist and still matter —
    # four issues were filed at that tier and must keep matching their
    # findings, or the UI shows them as unfiled and invites duplicates.
    #
    # Current tiers key on (scanner_name, rule_id) plus repository_id for
    # 'project'. See services/finding_groups.py for why.
    scope = Column(String, nullable=False, default='specific')
    scanner_name = Column(String, index=True)
    file_path = Column(Text, index=True)
    rule_id = Column(String(255), index=True)
    # The project a 'project'-tier filing belongs to. Null for 'org' and for
    # legacy rows. Not a ForeignKey, for the same reason finding_id is not:
    # the GRC issue outlives whatever this app later deletes.
    repository_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    # Locations named in the issue body at filing time, and how many were
    # omitted by the cap. Stored because the body cannot be edited afterwards,
    # so this is the only record of what the issue actually claimed.
    location_count = Column(Integer)
    locations_omitted = Column(Integer, default=0)
    # Projects the defect spanned when filed, which is what decided the tier.
    project_count = Column(Integer)

    # What AuditBoard created. issue_id is its numeric ID as a string: it is
    # an identifier we echo and link to, never something we do arithmetic on.
    issue_id = Column(String, nullable=False)
    issue_uid = Column(String)          # e.g. "I#1714", the label people quote
    issue_url = Column(Text)
    issue_status = Column(String)       # status at creation, not kept in sync
    issue_category_id = Column(Integer)
    deficiency_level_id = Column(Integer)
    deficiency_level_name = Column(String)

    # Count measured server-side at filing time. Stored because the live
    # count drifts as scans run, and the issue speaks for the population as
    # it stood when it was filed.
    occurrence_count = Column(Integer, default=1)

    filed_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    filed_by = Column(String)           # email or username, denormalized
    created_at = Column(DateTime, server_default=func.now())


class AuditBoardIssueFinding(Base):
    """One finding covered by a ``selection``-scope issue.

    Every other scope is a *rule*: 'project' and 'org' are answered by asking
    whether a finding shares a defect identity with the issue, so no membership
    list is needed and a finding scanned tomorrow is covered automatically.

    A selection has no rule. Someone ticked rows, and only those rows are
    covered — which means the membership has to be written down, or nothing can
    ever answer "is this finding already filed?" for them. Hence this table.

    ``finding_id`` carries no ForeignKey, for the same reason
    :class:`AuditBoardIssue.finding_id` does not: the GRC issue outlives
    whatever this application later deletes, and a filing history that vanishes
    with its evidence is not an audit trail. Rows are deleted only with the
    issue row they belong to.
    """

    __tablename__ = "auditboard_issue_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    auditboard_issue_id = Column(
        UUID(as_uuid=True),
        ForeignKey("auditboard_issues.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        # A finding appears at most once per issue. Without this a double
        # submit inflates the coverage count of a record that cannot be
        # edited afterwards.
        UniqueConstraint(
            "auditboard_issue_id", "finding_id", name="uq_auditboard_issue_finding"
        ),
    )


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
# DEVICE FLOW AUTHENTICATION - OAuth 2.0 Device Authorization Grant (RFC 8628)
# =============================================================================

class DeviceFlowRequest(Base):
    """
    Temporary device flow requests for CLI/device authentication.
    Stores device codes and user codes with 10-minute expiration.
    Status lifecycle: pending -> approved/denied/expired -> consumed
    """
    __tablename__ = "device_flow_requests"

    # Primary Key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    api_id = Column(Integer, Sequence('device_flow_requests_api_id_seq'), unique=True)

    # Device Flow Codes
    device_code = Column(String(128), unique=True, nullable=False, index=True)  # 128-char cryptographic code
    user_code = Column(String(9), unique=True, nullable=False, index=True)  # 8-char code (ABCD-1234 format with dash)

    # Client Information
    client_id = Column(String(255), nullable=False)
    client_name = Column(String(255), nullable=False)
    scopes = Column(JSONB, default=list)

    # Status Tracking
    status = Column(String(20), default='pending', index=True)  # pending, approved, denied, expired, consumed

    # Multi-tenant Scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False)

    # User Info (populated after approval)
    user_sub = Column(String(255), nullable=True)
    user_email = Column(String(255), nullable=True)
    user_name = Column(String(255), nullable=True)
    provider = Column(String(50), nullable=True)  # entra, okta

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)  # 10 minutes from creation
    approved_at = Column(DateTime(timezone=True), nullable=True)

    # Polling Tracking (rate limiting)
    last_poll_at = Column(DateTime(timezone=True), nullable=True)
    poll_count = Column(Integer, default=0)

    # Relationships
    organization = relationship("Organization", backref="device_flow_requests")

    def __repr__(self):
        return f"<DeviceFlowRequest(user_code='{self.user_code}', status='{self.status}')>"


class DeviceAuthorization(Base):
    """
    Persistent device authorization records.
    Tracks approved devices and their tokens for revocation management.
    Users can view/rename/revoke these in the "My Devices" UI.
    """
    __tablename__ = "device_authorizations"

    # Primary Key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    api_id = Column(Integer, Sequence('device_authorizations_api_id_seq'), unique=True)

    # Multi-tenant Scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)

    # User Identity
    user_sub = Column(String(255), nullable=False, index=True)  # Subject claim from ID token
    user_email = Column(String(255), nullable=False)
    user_name = Column(String(255), nullable=False)
    provider = Column(String(50), nullable=False)  # entra, okta

    # Device Information
    device_name = Column(String(255), nullable=False)  # User-friendly name (editable)
    client_id = Column(String(255), nullable=False)
    client_name = Column(String(255), nullable=False)

    # Token Tracking (for revocation)
    current_refresh_token_jti = Column(String(255), nullable=True)  # Latest refresh token JTI

    # Metadata
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6

    # Status
    is_active = Column(Boolean, default=True, index=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), server_default=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(String(255), nullable=True)  # User email/sub who revoked
    revoked_reason = Column(Text, nullable=True)

    # Usage Statistics
    token_refresh_count = Column(Integer, default=0)

    # Relationships
    organization = relationship("Organization", backref="device_authorizations")

    def __repr__(self):
        return f"<DeviceAuthorization(device_name='{self.device_name}', user_email='{self.user_email}', active={self.is_active})>"


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
    api_id = Column(Integer, Sequence('cribl_config_api_id_seq'), unique=True)
    
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



# =============================================================================
# CI/CD TRACKING - Deployment and Pipeline History
# =============================================================================

class DeploymentTarget(Base):
    """
    Deployment environments and targets (production, staging, etc.).
    Multi-tenant: Scoped to organization.
    """
    __tablename__ = "deployment_targets"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Multi-tenant: Organization scope
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    
    name = Column(String(255), nullable=False)  # prod, staging, dev, qa
    type = Column(String(50), nullable=False)  # production, staging, development, test
    url = Column(String(512))  # deployment URL
    cloud_provider = Column(String(50))  # aws, gcp, azure, on-premise
    region = Column(String(100))  # cloud region
    extra_data = Column(JSONB)  # additional environment metadata
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", backref="deployment_targets")

    __table_args__ = (
        UniqueConstraint('organization_id', 'name', name='uq_deployment_target_org_name'),
    )

    def __repr__(self):
        return f"<DeploymentTarget(name='{self.name}', type='{self.type}')>"


class CICDPipeline(Base):
    """
    CI/CD pipeline configurations from various platforms (GitHub Actions, GitLab CI, etc.).
    """
    __tablename__ = "cicd_pipelines"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Foreign keys
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"))
    
    platform = Column(String(50), nullable=False)  # github_actions, gitlab_ci, jenkins, circleci
    name = Column(String(255), nullable=False)  # workflow name
    file_path = Column(String(512))  # path to workflow file
    branch = Column(String(255))  # primary branch
    is_active = Column(Boolean, default=True)
    config = Column(JSONB)  # pipeline configuration details
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    last_run_at = Column(DateTime)

    # Relationships
    repository = relationship("Repository", backref="cicd_pipelines")

    __table_args__ = (
        UniqueConstraint('repository_id', 'platform', 'name', name='uq_cicd_pipeline_repo_platform_name'),
    )

    def __repr__(self):
        return f"<CICDPipeline(name='{self.name}', platform='{self.platform}')>"


class WorkflowRun(Base):
    """
    Individual workflow/pipeline execution runs (GitHub Actions specific, but adaptable).
    """
    __tablename__ = "workflow_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Foreign keys
    pipeline_id = Column(UUID(as_uuid=True), ForeignKey("cicd_pipelines.id", ondelete="CASCADE"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"))
    
    run_id = Column(BigInteger)  # External platform run ID
    run_number = Column(Integer)
    workflow_name = Column(String(255))
    event = Column(String(50))  # push, pull_request, workflow_dispatch
    status = Column(String(50))  # queued, in_progress, completed, cancelled, failed
    conclusion = Column(String(50))  # success, failure, cancelled, skipped, timed_out
    branch = Column(String(255))
    commit_sha = Column(String(40))
    commit_message = Column(Text)
    actor = Column(String(255))  # user who triggered the run
    html_url = Column(String(512))  # link to workflow run
    
    # Timing
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Integer)

    extra_data = Column(JSONB)  # additional workflow run data

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    pipeline = relationship("CICDPipeline", backref="workflow_runs")
    repository = relationship("Repository", backref="workflow_runs")

    def __repr__(self):
        return f"<WorkflowRun(workflow_name='{self.workflow_name}', status='{self.status}')>"


class Deployment(Base):
    """
    Deployment events to specific environments.
    Tracks when and where code is deployed.
    """
    __tablename__ = "deployments"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Foreign keys
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"))
    target_id = Column(UUID(as_uuid=True), ForeignKey("deployment_targets.id", ondelete="SET NULL"))
    workflow_run_id = Column(UUID(as_uuid=True), ForeignKey("workflow_runs.id", ondelete="SET NULL"))
    
    deployment_id = Column(BigInteger)  # External platform deployment ID
    environment = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False)  # queued, in_progress, success, failure, error, cancelled
    commit_sha = Column(String(40), nullable=False)
    commit_message = Column(Text)
    ref = Column(String(255))  # branch or tag
    deployer = Column(String(255))  # user or service that triggered deployment
    deployment_url = Column(String(512))  # URL where deployment is accessible
    log_url = Column(String(512))  # URL to deployment logs
    
    # Timing
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Integer)

    error_message = Column(Text)
    extra_data = Column(JSONB)  # additional deployment metadata

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    repository = relationship("Repository", backref="deployments")
    target = relationship("DeploymentTarget", backref="deployments")
    workflow_run = relationship("WorkflowRun", backref="deployments")

    def __repr__(self):
        return f"<Deployment(environment='{self.environment}', status='{self.status}', commit='{self.commit_sha[:8]}')>"


class DeploymentArtifact(Base):
    """
    Artifacts produced by deployments (Docker images, zip files, etc.).
    """
    __tablename__ = "deployment_artifacts"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Foreign keys
    deployment_id = Column(UUID(as_uuid=True), ForeignKey("deployments.id", ondelete="CASCADE"))
    
    artifact_type = Column(String(50))  # docker_image, zip, tar, binary
    artifact_name = Column(String(255))
    artifact_version = Column(String(100))
    artifact_url = Column(String(512))
    artifact_hash = Column(String(128))  # SHA256 or similar
    size_bytes = Column(BigInteger)
    extra_data = Column(JSONB)

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    deployment = relationship("Deployment", backref="artifacts")

    def __repr__(self):
        return f"<DeploymentArtifact(name='{self.artifact_name}', type='{self.artifact_type}')>"


# =============================================================================
# REPOSITORY OPERATIONS - Deployment, hosting, compliance & infrastructure context
# =============================================================================

class RepositoryOperations(Base):
    """
    1:1 operations context for a repository.
    Tracks deployment status, hosting platform, compliance frameworks,
    infrastructure details, and AI discovery metadata.
    """
    __tablename__ = "repository_operations"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('repository_operations_api_id_seq'), unique=True)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, unique=True)

    # Deployment Status
    deployment_status = Column(String(32), server_default="unknown")
    deployment_status_notes = Column(Text)

    # Environment URLs (JSONB array of {name, url, is_primary})
    environment_urls = Column(JSONB, server_default="[]")

    # Hosting & Platform
    hosting_platform = Column(String(64))
    hosting_detail = Column(Text)
    deployment_method = Column(String(64))
    deployment_method_detail = Column(Text)

    # Team & Ownership
    team_owner = Column(String(256))
    team_contact_email = Column(String(256))
    team_slack_channel = Column(String(256))

    # Business Criticality
    business_criticality = Column(String(32), server_default="medium")
    business_criticality_notes = Column(Text)

    # Compliance & Governance
    compliance_frameworks = Column(JSONB, server_default="[]")
    data_classification = Column(String(32))
    regulatory_notes = Column(Text)
    last_compliance_audit_at = Column(DateTime)

    # Infrastructure
    cicd_platform = Column(String(64))
    cicd_pipeline_url = Column(Text)
    container_registry = Column(String(128))
    iac_type = Column(String(64))
    iac_path = Column(Text)
    monitoring_url = Column(Text)
    alerting_url = Column(Text)
    logging_url = Column(Text)

    # AI Discovery
    last_discovery_at = Column(DateTime)
    last_discovery_status = Column(String(32))
    discovery_confidence = Column(Numeric(3, 2))

    # Metadata
    custom_metadata = Column(JSONB, server_default="{}")
    notes = Column(Text)

    created_by = Column(String(256))
    updated_by = Column(String(256))
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    repository = relationship("Repository", back_populates="operations")

    def __repr__(self):
        return f"<RepositoryOperations(repository_id='{self.repository_id}', status='{self.deployment_status}')>"


class RepositoryOpsDiscovery(Base):
    """
    AI discovery run history for repository operations context.
    Each row represents one AI discovery run with its suggestions and evidence.
    """
    __tablename__ = "repository_ops_discoveries"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('repository_ops_discoveries_api_id_seq'), unique=True)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False)

    status = Column(String(32), nullable=False, server_default="pending")
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    # AI results
    suggestions = Column(JSONB, server_default="[]")
    evidence_files = Column(JSONB, server_default="[]")
    raw_ai_response = Column(Text)

    # Metadata
    triggered_by = Column(String(256))
    error_message = Column(Text)
    tokens_used = Column(Integer)

    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    repository = relationship("Repository", backref="ops_discoveries")

    def __repr__(self):
        return f"<RepositoryOpsDiscovery(repository_id='{self.repository_id}', status='{self.status}')>"


# =============================================================================
# DEPLOYMENT TOPOLOGY - repo -> environment -> cloud resource map
# See migrations/020_deployment_topology.sql
# =============================================================================

class ReusableWorkflowTarget(Base):
    """
    Parsed deployment contract of a centrally-shared reusable workflow.

    Parsing the handful of central workflows once yields deployment topology for
    the hundreds of repositories that call them. One row per
    (source_repo, workflow_path, ref).
    """
    __tablename__ = "reusable_workflow_targets"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))

    # Identity of the shared workflow
    source_repo = Column(String(512), nullable=False)      # owner/repo hosting it
    workflow_path = Column(String(512), nullable=False)    # .github/workflows/x.yaml
    ref = Column(String(255), nullable=False)              # tag/branch consumers pin
    resolved_sha = Column(String(40))
    workflow_name = Column(String(512))
    kind = Column(String(50))                              # cd | ci | infra | release | utility

    # Reach (derived from the dependencies table)
    consumer_count = Column(Integer, default=0)

    # What it deploys
    cloud_providers = Column(JSONB)
    resource_types = Column(JSONB)
    is_deploying = Column(Boolean, default=False)

    # How the environment is chosen
    environment_source = Column(String(50))                # deployment_event|input|literal|matrix
    environment_gate_vars = Column(JSONB)
    literal_environments = Column(JSONB)

    # Credential + execution surface
    runner_labels = Column(JSONB)
    inputs = Column(JSONB)
    declared_secrets = Column(JSONB)
    referenced_vars = Column(JSONB)
    referenced_secrets = Column(JSONB)                     # NAMES only, never values
    nested_workflows = Column(JSONB)
    actions_used = Column(JSONB)
    permissions = Column(JSONB)
    oidc_used = Column(Boolean, default=False)
    secrets_bulk_exposure = Column(JSONB)                  # toJSON(secrets) / secrets: inherit sinks

    # Provenance
    parse_confidence = Column(Numeric(3, 2))
    parser_version = Column(String(20))
    evidence = Column(JSONB)
    fetch_status = Column(String(50))
    fetch_error = Column(Text)
    fetched_at = Column(DateTime)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    organization = relationship("Organization", backref="reusable_workflow_targets")

    __table_args__ = (
        UniqueConstraint('organization_id', 'source_repo', 'workflow_path', 'ref',
                         name='reusable_workflow_targets_organization_id_source_repo_worp_key'),
    )

    def __repr__(self):
        return (f"<ReusableWorkflowTarget('{self.source_repo}/{self.workflow_path}@{self.ref}', "
                f"consumers={self.consumer_count})>")


class RepoDeploymentMap(Base):
    """
    Where a repository's code runs, with provenance and confidence.

    One row per (repository, environment, method, resource). Each collection
    method writes its own rows rather than overwriting another's, so a
    low-confidence static inference never masks a high-confidence observation.

    A row with is_resolved = False is an explicit "we looked and could not
    determine" marker - an unbounded unknown, NOT an assertion that the
    repository deploys nowhere.
    """
    __tablename__ = "repo_deployment_map"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"),
                           nullable=False)

    environment = Column(String(255), nullable=False)      # dev, prd, prd-ncus, __unresolved__
    environment_kind = Column(String(50))                  # production|staging|test|development|ephemeral

    cloud_provider = Column(String(50))
    resource_type = Column(String(100))
    resource_identifier = Column(String(512))
    subscription_or_account = Column(String(255))
    region = Column(String(100))

    # Who/what executes the deploy, and with which identity
    runner_labels = Column(JSONB)
    deploy_identity = Column(String(255))                  # e.g. Azure SP client id for this env
    tf_backend = Column(JSONB)

    # Provenance
    method = Column(String(50), nullable=False)
    confidence = Column(Numeric(3, 2), nullable=False)
    source_workflow_id = Column(UUID(as_uuid=True),
                                ForeignKey("reusable_workflow_targets.id", ondelete="SET NULL"))
    is_resolved = Column(Boolean, default=False)
    unresolved_reason = Column(String(255))
    evidence = Column(JSONB, nullable=False)

    first_observed_at = Column(DateTime, server_default=func.now())
    last_observed_at = Column(DateTime, server_default=func.now())
    is_current = Column(Boolean, default=True)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", backref="deployment_map")
    source_workflow = relationship("ReusableWorkflowTarget", backref="deployment_map_rows")

    def __repr__(self):
        return (f"<RepoDeploymentMap(env='{self.environment}', method='{self.method}', "
                f"confidence={self.confidence})>")


# =============================================================================
# RULE EQUIVALENCE - cross-scanner "this is the same defect" decisions
# =============================================================================

class RuleEquivalence(Base):
    """One claim that two scanners' rules describe the same defect.

    Exists because grouping findings by ``(scanner_name, rule_id)`` files two
    issues when grype and trivy-fs both report the same CVE. An AI pass
    proposes which pairs are really one defect; a person approves or rejects;
    only approved rows change how anything is filed.

    That order is deliberate. AuditBoard issues cannot be deleted and their
    descriptions cannot be edited after create, so a wrong merge permanently
    claims an issue covers a finding it does not describe, and no later pass
    can fix it. An unreviewed proposal therefore has no effect at all: the
    scanners stay separate, which files a visible duplicate instead of hiding
    a real defect.

    The pair is stored in a canonical order (``scanner_a <= scanner_b``, then
    rule) so the same two rules cannot be recorded twice in opposite order and
    end up with contradictory verdicts.

    Blocking keeps this table small: only rule pairs that actually co-occur on
    the same normalized path in the same repository are worth asking about,
    which was 478 pairs across the whole instance on 2026-09-16.
    """
    __tablename__ = "rule_equivalences"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    organization_id = Column(UUID(as_uuid=True), nullable=True, index=True)

    # The pair, in canonical order. Not foreign keys: a rule is not a row
    # anywhere, it is a value scanners emit.
    scanner_a = Column(String(100), nullable=False)
    rule_a = Column(String(255), nullable=False)
    scanner_b = Column(String(100), nullable=False)
    rule_b = Column(String(255), nullable=False)

    # What the AI proposed. 'equivalent' or 'distinct'.
    verdict = Column(String(20), nullable=False)
    confidence = Column(Numeric(3, 2))
    # Which model said so, and what it was shown. Without these a verdict is
    # an assertion nobody can re-examine when a model is replaced.
    model = Column(String(255))
    rationale = Column(Text)
    evidence = Column(JSONB)
    proposed_at = Column(DateTime, server_default=func.now())

    # Human review. Null review_decision means unreviewed, which means the
    # row does not affect grouping.
    review_decision = Column(String(20), index=True)  # approved|rejected
    reviewed_by = Column(String(255))
    reviewed_at = Column(DateTime)
    review_note = Column(Text)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "scanner_a", "rule_a", "scanner_b", "rule_b",
            name="uq_rule_equivalence_pair",
        ),
        Index("ix_rule_equivalence_approved", "review_decision", "verdict"),
    )

    @property
    def is_active_merge(self) -> bool:
        """True when this row actually merges two identities."""
        return self.review_decision == "approved" and self.verdict == "equivalent"

    def __repr__(self):
        return (f"<RuleEquivalence({self.scanner_a}:{self.rule_a} ~ "
                f"{self.scanner_b}:{self.rule_b}, {self.verdict}, "
                f"review={self.review_decision or 'pending'})>")
