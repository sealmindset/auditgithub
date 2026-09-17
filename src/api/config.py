import os
from pydantic import field_validator
from pydantic_settings import BaseSettings

#: Defaults for the filing knobs, named here so the "blank means default"
#: validator can apply the right one per field. Kept in step with the field
#: declarations below by the test that asserts they match.
_FILING_INT_DEFAULTS = {
    "FILING_PROJECT_ESCALATION_THRESHOLD": 10,
    "FILING_MAX_LOCATIONS": 100,
}


class Settings(BaseSettings):
    # Database
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: str = "5432"
    POSTGRES_USER: str = "auditgh"
    POSTGRES_PASSWORD: str = "auditgh_secret"
    POSTGRES_DB: str = "auditgh_kb"

    # Jira
    JIRA_URL: str = ""
    JIRA_USERNAME: str = ""
    JIRA_API_TOKEN: str = ""
    JIRA_PROJECT_KEY: str = "SEC"

    # AuditBoard GRC
    # Unlike Jira, issue creation here is an authenticated API write, so the
    # token is server-side only and must never be exposed to the browser.
    AUDITBOARD_URL: str = ""
    AUDITBOARD_TOKEN: str = ""
    # Issue category the created issue is filed under. The instance keeps its
    # registers in one collection and separates them by this ID: 10 IT Risk
    # Issue, 11 IT Risk Exception, 12 IT Infrastructure Exception. There is no
    # per-register endpoint. 10 is source-backed, so it also needs
    # AUDITBOARD_ISSUE_SOURCE_ID below; 11 and 12 stand alone.
    AUDITBOARD_ISSUE_CATEGORY_ID: int = 0
    # Status new issues are created in. Must be a status this instance really
    # has: Open, Closed, Remediated, Pending Remediation, Inactive or Canceled.
    # "Draft" is not one, and sending a status that does not exist is answered
    # with a bare HTTP 500.
    AUDITBOARD_CREATE_STATUS: str = "Open"
    # How the issue was identified. 7 = "Other", the honest answer for a
    # scanner: not Internal Audit, not External Audit, not Management.
    AUDITBOARD_ISSUE_IDENT_ID: int = 7
    # Required only for a source-backed issue category (10 IT Risk Issue
    # attaches each issue to a Risk record). 0 means unset.
    AUDITBOARD_ISSUE_SOURCE_ID: int = 0
    # Workspace number in the issue URL. Display only — filing works without
    # it, but no link is emitted. Not derivable from the API.
    AUDITBOARD_WORKSPACE_ID: int = 0
    # Path to a CA bundle for the AuditBoard host. Egress reaches this host by
    # two different paths — sometimes intercepted by Zscaler, sometimes direct
    # to AWS — so the bundle needs both trust anchors. Sending a bearer token
    # over an unverified connection is not an acceptable workaround.
    AUDITBOARD_CA_BUNDLE: str = ""
    # AuditBoard user IDs stamped on each filed issue. Category 10 requires a
    # senior owner and a vice president to sit at status Open, and the API
    # enforces neither — an issue missing them is accepted and then reads as an
    # incomplete register entry. AuditGitHub logins and AuditBoard users are
    # separate identities with no mapping between them, so these are
    # configuration rather than something derived from the filer. 0 means the
    # field is left off.
    AUDITBOARD_SENIOR_OWNER_USER_ID: int = 0
    AUDITBOARD_VICE_PRESIDENT_USER_ID: int = 0
    AUDITBOARD_TESTER_USER_ID: int = 0
    AUDITBOARD_REVIEWER_USER_ID: int = 0

    # -- Filing principle (see services/finding_groups.py) -----------------
    # Projects a single defect may touch before it stops being filed per
    # project and becomes one org-wide issue. Above this, no single team can
    # reasonably own it and per-project filing would flood the register: the
    # 15 most widespread critical defects here span more than ten projects
    # each and account for 25,274 findings between them.
    FILING_PROJECT_ESCALATION_THRESHOLD: int = 10
    # Severities eligible to be filed, comma-separated. Configuration rather
    # than a constant because the volume differs by two orders of magnitude:
    # at project tier this instance yields 1,109 critical groups, 5,893 with
    # high, and 10,367 with medium.
    FILING_SEVERITIES: str = "critical,high,medium"
    # Locations printed in one issue body before the list is truncated with a
    # count of what was left out. The largest group here resolves to 1,005
    # distinct paths; only 8 of 10,367 groups exceed 100.
    FILING_MAX_LOCATIONS: int = 100
    # Skip findings already ruled out of the work list. 546,977 findings carry
    # an exclusion reason — comment-matching noise and filename-only matches —
    # and filing those would put work into a GRC register that this app has
    # already decided is not work.
    FILING_EXCLUDE_NON_ACTIONABLE: bool = True

    @property
    def filing_severities_list(self) -> list[str]:
        """FILING_SEVERITIES as lowercase names, empty meaning no filter."""
        return [s.strip().lower() for s in (self.FILING_SEVERITIES or "").split(",") if s.strip()]

    @field_validator(
        "FILING_PROJECT_ESCALATION_THRESHOLD",
        "FILING_MAX_LOCATIONS",
        mode="before",
    )
    @classmethod
    def _blank_filing_int_is_default(cls, v, info):
        """An unset filing knob means its default, not a parse failure.

        Same reasoning as the AuditBoard IDs below: these arrive as "" from
        `${VAR:-}` in compose, and settings are built at import time, so a
        blank line in .env would otherwise stop the API from starting. The
        default is named here rather than returned as None, because None is
        not a valid int and pydantic would reject it just as loudly.
        """
        if v is None or (isinstance(v, str) and not v.strip()):
            return _FILING_INT_DEFAULTS.get(info.field_name, 0)
        return v

    @field_validator(
        "AUDITBOARD_ISSUE_CATEGORY_ID",
        "AUDITBOARD_ISSUE_IDENT_ID",
        "AUDITBOARD_ISSUE_SOURCE_ID",
        "AUDITBOARD_WORKSPACE_ID",
        "AUDITBOARD_SENIOR_OWNER_USER_ID",
        "AUDITBOARD_VICE_PRESIDENT_USER_ID",
        "AUDITBOARD_TESTER_USER_ID",
        "AUDITBOARD_REVIEWER_USER_ID",
        mode="before",
    )
    @classmethod
    def _empty_category_is_unset(cls, v):
        """Treat an empty value as unset rather than as a parse failure.

        An unconfigured integer arrives as "" — from `${VAR:-}` in compose, or
        from a blank line in .env. Pydantic rejects that, and because settings
        are built at import time the whole API refuses to start over an
        optional integration. Unset means the feature reports itself
        unavailable; it does not mean the service is down.
        """
        if v is None or (isinstance(v, str) and not v.strip()):
            return 0
        return v

    @field_validator("AUDITBOARD_CREATE_STATUS", mode="before")
    @classmethod
    def _blank_status_is_default(cls, v):
        """An empty status means the default, not an empty string."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return "Open"
        return v

    # GitHub
    GITHUB_TOKEN: str = ""
    
    # Security
    SECRET_KEY: str = "your-secret-key-here"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Corporate identity matching configuration
    # Comma-separated list of corporate email domains (e.g., "company.com,corp.example.com")
    CORPORATE_EMAIL_DOMAINS: str = ""
    # Comma-separated list of GitHub username suffixes to strip (e.g., "-corp,-dev,-company,_corp,_dev")
    CORPORATE_USERNAME_SUFFIXES: str = ""

    @property
    def corporate_email_domains_list(self) -> list[str]:
        """Parse CORPORATE_EMAIL_DOMAINS into a list."""
        if not self.CORPORATE_EMAIL_DOMAINS:
            return []
        return [d.strip().lower() for d in self.CORPORATE_EMAIL_DOMAINS.split(',') if d.strip()]

    @property
    def corporate_username_suffixes_list(self) -> list[str]:
        """Parse CORPORATE_USERNAME_SUFFIXES into a list."""
        if not self.CORPORATE_USERNAME_SUFFIXES:
            return []
        return [s.strip().lower() for s in self.CORPORATE_USERNAME_SUFFIXES.split(',') if s.strip()]

    # AI Configuration - Values come from .env file
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = ""  # Set in .env (e.g., gpt-5.1, gpt-4.1, gpt-3.5-turbo)
    
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = ""  # Set in .env (e.g., claude-sonnet-4-20250514)
    
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-1.5-pro-latest" # Default to 1.5 Pro
    
    AI_PROVIDER: str = "openai"  # openai, claude, anthropic_foundry, ollama, docker
    AI_MODEL: str = ""  # Fallback - typically use provider-specific model
    
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    DOCKER_BASE_URL: str = "http://localhost:12434"  # Docker Model Runner
    DOCKER_MODEL: str = "ai/llama3.2:latest"  # Default model for Docker Model Runner
    
    AZURE_AI_FOUNDRY_ENDPOINT: str = ""
    AZURE_AI_FOUNDRY_API_KEY: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
