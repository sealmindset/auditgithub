"""
Sandbox dummy-data seed engine.

Populates the sandbox database with realistic but synthetic data so that
every API endpoint returns meaningful results.  All data is deterministic
(no randomness) so that resets are reproducible.

Entry points
------------
- ``initialize_sandbox()``  — seed only if the database is empty
- ``reset_and_seed(db)``    — drop everything, re-create, and re-seed
"""

import hashlib
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from src.api.database import engine, SessionLocal
from src.api import models

logger = logging.getLogger(__name__)

# ============================================================================
# Deterministic UUID helper
# ============================================================================

def _duuid(namespace: str, index: int) -> uuid.UUID:
    """Generate a deterministic UUID from a namespace string + index."""
    return uuid.uuid5(uuid.NAMESPACE_DNS, f"sandbox.{namespace}.{index}")


# ============================================================================
# Template constants
# ============================================================================

ORG_TEMPLATES = [
    {"name": "acme-corp", "github_org": "acme-corp", "display_name": "Acme Corporation"},
    {"name": "globex-labs", "github_org": "globex-labs", "display_name": "Globex Laboratories"},
    {"name": "initech-systems", "github_org": "initech-systems", "display_name": "Initech Systems"},
]

REPO_TEMPLATES = [
    # name, language, description, stars
    ("frontend-app", "TypeScript", "Next.js customer portal", 142),
    ("backend-api", "Python", "FastAPI microservice layer", 89),
    ("infra-terraform", "HCL", "AWS infrastructure as code", 34),
    ("mobile-ios", "Swift", "iOS mobile application", 67),
    ("mobile-android", "Kotlin", "Android mobile application", 55),
    ("data-pipeline", "Python", "Airflow ETL pipeline", 23),
    ("ml-models", "Python", "Machine learning model training", 112),
    ("auth-service", "Go", "OAuth2 / OIDC authentication service", 78),
    ("payment-gateway", "Java", "Payment processing microservice", 45),
    ("notification-svc", "TypeScript", "Email and push notification service", 31),
    ("search-engine", "Rust", "Full-text search microservice", 200),
    ("config-server", "Go", "Centralized configuration management", 18),
    ("ci-cd-pipelines", "YAML", "GitHub Actions workflow definitions", 12),
    ("docs-site", "MDX", "Developer documentation portal", 56),
    ("monitoring-stack", "Python", "Prometheus + Grafana dashboards", 29),
    ("sdk-python", "Python", "Python SDK for the platform API", 95),
    ("sdk-typescript", "TypeScript", "TypeScript SDK for the platform API", 88),
    ("load-tester", "Go", "k6-based performance test suite", 41),
]

FINDING_TEMPLATES = [
    # title, severity, tool, finding_type, category
    ("Hardcoded AWS access key in config.py", "critical", "gitleaks", "secret", "credentials"),
    ("SQL injection in user search endpoint", "critical", "semgrep", "vulnerability", "injection"),
    ("Vulnerable dependency: lodash < 4.17.21", "high", "grype", "dependency", "outdated-library"),
    ("Container image runs as root", "high", "trivy", "misconfiguration", "container"),
    ("Insecure deserialization in API handler", "high", "bandit", "vulnerability", "deserialization"),
    ("Missing HTTPS redirect in Terraform ALB", "medium", "checkov", "misconfiguration", "infrastructure"),
    ("Weak cryptographic algorithm (MD5)", "medium", "semgrep", "vulnerability", "cryptography"),
    ("Exposed .env file in repository root", "medium", "gitleaks", "secret", "configuration"),
    ("Unused IAM policy with admin access", "low", "checkov", "misconfiguration", "iam"),
    ("Informational: dependency is 2 major versions behind", "info", "osv", "dependency", "outdated-library"),
]

CONTRIBUTOR_NAMES = [
    ("alice-dev", "alice@acme-corp.dev"),
    ("bob-security", "bob@acme-corp.dev"),
    ("carol-infra", "carol@globex-labs.io"),
    ("dave-ml", "dave@globex-labs.io"),
    ("eve-mobile", "eve@initech-systems.com"),
    ("frank-backend", "frank@initech-systems.com"),
    ("grace-frontend", "grace@acme-corp.dev"),
    ("heidi-devops", "heidi@globex-labs.io"),
    ("ivan-qa", "ivan@initech-systems.com"),
    ("judy-data", "judy@acme-corp.dev"),
    ("karl-sre", "karl@globex-labs.io"),
    ("lisa-pm", "lisa@initech-systems.com"),
]

USER_TEMPLATES = [
    ("sandbox-admin", "admin@sandbox.local", "super_admin"),
    ("sandbox-analyst", "analyst@sandbox.local", "analyst"),
    ("sandbox-viewer", "viewer@sandbox.local", "viewer"),
    ("sandbox-auditor", "auditor@sandbox.local", "auditor"),
    ("sandbox-developer", "developer@sandbox.local", "developer"),
    ("sandbox-manager", "manager@sandbox.local", "manager"),
]

SANDBOX_KEY_TEMPLATES = [
    ("sandbox-admin-key", "sbx_admin_4a8b2c1d3e5f6789", "super_admin", "Full admin access — can reset sandbox and manage all resources"),
    ("sandbox-analyst-key", "sbx_analyst_9f8e7d6c5b4a3210", "analyst", "Analyst access — read/write findings, scans, and analytics"),
    ("sandbox-readonly-key", "sbx_readonly_1a2b3c4d5e6f7890", "viewer", "Read-only access — view all resources, no mutations"),
]

SCHEDULE_TEMPLATES = [
    # schedule_type, frequency, time_window
    ("ai", "weekly", "02:00-04:00"),
    ("manual", "daily", "00:00-06:00"),
    ("ai", "monthly", "03:00-05:00"),
]


# ============================================================================
# Seed functions
# ============================================================================

def _seed_sandbox_api_keys(db: Session) -> list:
    """Create the three pre-generated sandbox API keys."""
    keys = []
    for name, raw_key, role, desc in SANDBOX_KEY_TEMPLATES:
        key = models.SandboxApiKey(
            id=_duuid("sbxkey", SANDBOX_KEY_TEMPLATES.index((name, raw_key, role, desc))),
            name=name,
            key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
            key_value=raw_key,
            role=role,
            description=desc,
            is_active=True,
        )
        db.add(key)
        keys.append(key)
    db.flush()
    logger.info(f"Seeded {len(keys)} sandbox API keys")
    return keys


def _seed_organizations(db: Session) -> list:
    """Create 3 sandbox organizations."""
    orgs = []
    for idx, tpl in enumerate(ORG_TEMPLATES):
        org = models.Organization(
            id=_duuid("org", idx),
            name=tpl["name"],
            github_org=tpl["github_org"],
            display_name=tpl["display_name"],
            is_default=(idx == 0),
            is_active=True,
        )
        db.add(org)
        orgs.append(org)
    db.flush()
    logger.info(f"Seeded {len(orgs)} organizations")
    return orgs


def _seed_users(db: Session) -> list:
    """Create 6 sandbox users."""
    users = []
    for idx, (username, email, role) in enumerate(USER_TEMPLATES):
        user = models.User(
            id=_duuid("user", idx),
            username=username,
            email=email,
            role=role,
            is_active=True,
        )
        db.add(user)
        users.append(user)
    db.flush()
    logger.info(f"Seeded {len(users)} users")
    return users


def _seed_repositories(db: Session, orgs: list) -> list:
    """Create 18 repos per org (54 total)."""
    repos = []
    counter = 0
    now = datetime.now(timezone.utc)
    for org in orgs:
        for idx, (name, lang, desc, stars) in enumerate(REPO_TEMPLATES):
            repo = models.Repository(
                id=_duuid("repo", counter),
                name=f"{org.github_org}/{name}",
                organization_id=org.id,
                language=lang,
                description=desc,
                stars=stars,
                default_branch="main",
                is_archived=False,
                last_scan_at=now - timedelta(hours=counter % 48),
            )
            db.add(repo)
            repos.append(repo)
            counter += 1
    db.flush()
    logger.info(f"Seeded {len(repos)} repositories")
    return repos


def _seed_findings(db: Session, repos: list) -> list:
    """Create 10 findings per repo (540 total)."""
    findings = []
    counter = 0
    now = datetime.now(timezone.utc)
    statuses = ["open", "open", "open", "in_progress", "in_progress",
                "resolved", "resolved", "false_positive", "accepted", "open"]
    for repo in repos:
        for idx, (title, severity, tool, ftype, category) in enumerate(FINDING_TEMPLATES):
            finding = models.Finding(
                id=_duuid("finding", counter),
                title=f"{title} — {repo.name.split('/')[-1]}",
                organization_id=repo.organization_id,
                repository_id=repo.id,
                severity=severity,
                tool=tool,
                finding_type=ftype,
                category=category,
                status=statuses[idx],
                file_path=f"src/{category}/{repo.name.split('/')[-1]}.py",
                line_number=(idx + 1) * 10,
                description=f"[Sandbox] {title}. Detected by {tool} in {repo.name}.",
                first_seen=now - timedelta(days=30 - idx),
                last_seen=now - timedelta(hours=idx * 6),
            )
            db.add(finding)
            findings.append(finding)
            counter += 1
    db.flush()
    logger.info(f"Seeded {len(findings)} findings")
    return findings


def _seed_scan_runs(db: Session, repos: list) -> list:
    """Create 2 scan runs per repo (108 total)."""
    runs = []
    counter = 0
    now = datetime.now(timezone.utc)
    for repo in repos:
        for scan_idx in range(2):
            started = now - timedelta(days=scan_idx * 7, hours=2)
            finished = started + timedelta(minutes=15 + counter % 30)
            run = models.ScanRun(
                id=_duuid("scanrun", counter),
                organization_id=repo.organization_id,
                repository_id=repo.id,
                status="completed",
                tools_run=["gitleaks", "semgrep", "grype"],
                started_at=started,
                completed_at=finished,
                findings_count=10,
                critical_count=1,
                high_count=2,
                medium_count=3,
                low_count=3,
                info_count=1,
            )
            db.add(run)
            runs.append(run)
            counter += 1
    db.flush()
    logger.info(f"Seeded {len(runs)} scan runs")
    return runs


def _seed_schedules(db: Session, orgs: list, repos: list) -> list:
    """Create 3 schedules per org (9 total)."""
    schedules = []
    counter = 0
    for org in orgs:
        org_repos = [r for r in repos if r.organization_id == org.id]
        for idx, (stype, freq, window) in enumerate(SCHEDULE_TEMPLATES):
            repo = org_repos[idx % len(org_repos)]
            sched = models.ScanSchedule(
                id=_duuid("schedule", counter),
                organization_id=org.id,
                repository_id=repo.id,
                schedule_type=stype,
                frequency=freq,
                time_window=window,
                is_active=True,
            )
            db.add(sched)
            schedules.append(sched)
            counter += 1
    db.flush()
    logger.info(f"Seeded {len(schedules)} schedules")
    return schedules


def _seed_contributors(db: Session, repos: list) -> list:
    """Create 3 contributors per repo (162 total)."""
    contributors = []
    counter = 0
    now = datetime.now(timezone.utc)
    for repo in repos:
        for c_idx in range(3):
            name_tpl = CONTRIBUTOR_NAMES[(counter) % len(CONTRIBUTOR_NAMES)]
            contributor = models.Contributor(
                id=_duuid("contributor", counter),
                name=name_tpl[0],
                email=name_tpl[1],
                organization_id=repo.organization_id,
                repository_id=repo.id,
                commit_count=50 + counter % 200,
                first_commit=now - timedelta(days=365),
                last_commit=now - timedelta(days=counter % 30),
            )
            db.add(contributor)
            contributors.append(contributor)
            counter += 1
    db.flush()
    logger.info(f"Seeded {len(contributors)} contributors")
    return contributors


def _seed_api_endpoints(db: Session, repos: list) -> list:
    """Create 5 API endpoints per repo (270 total)."""
    endpoints = []
    counter = 0
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    paths = ["/api/v1/users", "/api/v1/orders", "/api/v1/products", "/api/v1/auth/login", "/api/v1/health"]
    for repo in repos:
        for e_idx in range(5):
            ep = models.APIEndpoint(
                id=_duuid("apiep", counter),
                organization_id=repo.organization_id,
                repository_id=repo.id,
                endpoint_url=paths[e_idx],
                http_method=methods[e_idx],
                direction="inbound",
                source_file=f"src/routes/{paths[e_idx].split('/')[-1]}.py",
                is_authenticated=(e_idx != 4),  # /health is unauthenticated
            )
            db.add(ep)
            endpoints.append(ep)
            counter += 1
    db.flush()
    logger.info(f"Seeded {len(endpoints)} API endpoints")
    return endpoints


def _seed_contributor_profiles(db: Session) -> list:
    """Create contributor profiles for the 12 template contributors."""
    profiles = []
    now = datetime.now(timezone.utc)
    for idx, (name, email) in enumerate(CONTRIBUTOR_NAMES):
        profile = models.ContributorProfile(
            id=_duuid("profile", idx),
            display_name=name,
            email=email,
            total_commits=100 + idx * 50,
            total_repos=3 + idx % 5,
            risk_score=round(0.1 + (idx % 10) * 0.09, 2),
            first_seen=now - timedelta(days=365),
            last_seen=now - timedelta(days=idx),
        )
        db.add(profile)
        profiles.append(profile)
    db.flush()
    logger.info(f"Seeded {len(profiles)} contributor profiles")
    return profiles


def _seed_system_config(db: Session) -> None:
    """Seed a few system config entries."""
    configs = [
        ("sandbox.version", "1.0.0"),
        ("sandbox.seeded_at", datetime.now(timezone.utc).isoformat()),
        ("ai.provider", "mock"),
    ]
    for key, val in configs:
        db.add(models.SystemConfig(key=key, value=val))
    db.flush()
    logger.info("Seeded system config")


# ============================================================================
# Entry points
# ============================================================================

async def initialize_sandbox() -> None:
    """Seed the sandbox database if it is empty (first boot)."""
    from src.api.sandbox import is_sandbox
    if not is_sandbox():
        return

    db = SessionLocal()
    try:
        org_count = db.query(models.Organization).count()
        if org_count > 0:
            logger.info("Sandbox database already seeded — skipping initialization")
            return

        logger.info("Sandbox database is empty — seeding dummy data...")
        _run_full_seed(db)
        db.commit()
        logger.info("Sandbox initialization complete")
    except Exception as e:
        db.rollback()
        logger.error(f"Sandbox initialization failed: {e}")
        raise
    finally:
        db.close()


async def reset_and_seed(db: Session) -> None:
    """Drop all tables, recreate, and seed from scratch."""
    logger.warning("Resetting sandbox database...")

    # Flush Redis sandbox DB
    await _flush_sandbox_redis()

    # Drop and recreate all tables
    models.Base.metadata.drop_all(bind=engine)
    models.Base.metadata.create_all(bind=engine)

    # Use a fresh session (the old one's connection may be stale after DDL)
    fresh_db = SessionLocal()
    try:
        _run_full_seed(fresh_db)
        fresh_db.commit()

        # Re-initialize RBAC roles
        try:
            from src.rbac.seeds import init_rbac_if_needed
            init_rbac_if_needed(fresh_db)
        except Exception as e:
            logger.warning(f"RBAC re-init after sandbox reset: {e}")

        logger.info("Sandbox reset and re-seed complete")
    except Exception as e:
        fresh_db.rollback()
        logger.error(f"Sandbox re-seed failed: {e}")
        raise
    finally:
        fresh_db.close()


def _run_full_seed(db: Session) -> None:
    """Run all seed functions in dependency order."""
    _seed_sandbox_api_keys(db)
    orgs = _seed_organizations(db)
    _seed_users(db)
    repos = _seed_repositories(db, orgs)
    _seed_findings(db, repos)
    _seed_scan_runs(db, repos)
    _seed_schedules(db, orgs, repos)
    _seed_contributors(db, repos)
    _seed_api_endpoints(db, repos)
    _seed_contributor_profiles(db)
    _seed_system_config(db)


async def _flush_sandbox_redis() -> None:
    """Flush Redis DB 1 (sandbox cache)."""
    try:
        import redis
        redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/1")
        r = redis.from_url(redis_url)
        r.flushdb()
        logger.info("Flushed sandbox Redis DB")
    except Exception as e:
        logger.warning(f"Could not flush sandbox Redis: {e}")
