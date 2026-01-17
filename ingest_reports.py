"""
Ingest vulnerability reports from filesystem into database.

Reads JSON reports from vulnerability_reports/ and populates the database
with repositories and findings.
"""
import os
import json
import logging
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import uuid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/security_portal')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

REPORTS_DIR = Path(os.getenv('REPORTS_DIR', '/app/vulnerability_reports'))

def get_organization_id(session, org_name):
    """Get organization ID by name."""
    result = session.execute(
        text("SELECT id FROM organizations WHERE github_org = :org_name"),
        {"org_name": org_name}
    ).fetchone()
    return str(result[0]) if result else None

def ingest_repository(session, org_id, org_name, repo_name):
    """Create repository record if it doesn't exist."""
    try:
        # Check if repository exists
        result = session.execute(
            text("SELECT id FROM repositories WHERE organization_id = :org_id AND name = :repo_name"),
            {"org_id": org_id, "repo_name": repo_name}
        ).fetchone()

        if result:
            return str(result[0])

        # Create repository
        repo_id = str(uuid.uuid4())
        session.execute(
            text("""
                INSERT INTO repositories
                (id, organization_id, name, full_name, description, is_private,
                 url, default_branch, created_at, updated_at, last_scanned_at)
                VALUES
                (:id, :org_id, :name, :full_name, :description, :is_private,
                 :url, :default_branch, :created_at, :updated_at, :last_scanned_at)
            """),
            {
                "id": repo_id,
                "org_id": org_id,
                "name": repo_name,
                "full_name": f"{org_name}/{repo_name}",
                "description": f"Repository {repo_name}",
                "is_private": True,
                "url": f"https://github.com/{org_name}/{repo_name}",
                "default_branch": "main",
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
                "last_scanned_at": datetime.now()
            }
        )
        session.commit()
        logger.info(f"Created repository: {org_name}/{repo_name}")
        return repo_id
    except Exception as e:
        session.rollback()
        logger.error(f"Error creating repository {org_name}/{repo_name}: {e}")
        raise

def ingest_gitleaks_findings(session, repo_id, report_path):
    """Ingest findings from gitleaks JSON report."""
    try:
        with open(report_path, 'r') as f:
            findings = json.load(f)

        if not findings:
            return 0

        # Get organization_id from repository
        repo_result = session.execute(
            text("SELECT organization_id FROM repositories WHERE id = :repo_id"),
            {"repo_id": repo_id}
        ).fetchone()
        org_id = repo_result[0] if repo_result else None

        count = 0
        for finding in findings:
            # Use Fingerprint as finding_uuid for deduplication
            finding_uuid = finding.get('Fingerprint', str(uuid.uuid4()))

            # Check if finding already exists
            result = session.execute(
                text("SELECT id FROM findings WHERE repository_id = :repo_id AND file_path = :file_path AND line_start = :line_start AND scanner_name = 'gitleaks'"),
                {
                    "repo_id": repo_id,
                    "file_path": finding.get('File', ''),
                    "line_start": finding.get('StartLine')
                }
            ).fetchone()

            if result:
                continue

            # Create finding
            finding_id = str(uuid.uuid4())
            session.execute(
                text("""
                    INSERT INTO findings
                    (id, organization_id, repository_id, scanner_name, finding_type, severity, title,
                     description, file_path, line_start, line_end, finding_uuid,
                     status, created_at, updated_at)
                    VALUES
                    (:id, :org_id, :repo_id, :scanner, :finding_type, :severity, :title,
                     :description, :file_path, :line_start, :line_end, :finding_uuid,
                     :status, :created_at, :updated_at)
                """),
                {
                    "id": finding_id,
                    "org_id": org_id,
                    "repo_id": repo_id,
                    "scanner": "gitleaks",
                    "finding_type": "secret",  # Fixed: Use 'secret' for gitleaks findings
                    "severity": "high",  # Gitleaks secrets are high severity
                    "title": finding.get('Description', 'Secret detected'),
                    "description": finding.get('Match', ''),
                    "file_path": finding.get('File', ''),
                    "line_start": finding.get('StartLine'),
                    "line_end": finding.get('EndLine'),
                    "finding_uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, finding_uuid)),
                    "status": "open",
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                }
            )
            count += 1

        session.commit()
        return count
    except Exception as e:
        session.rollback()
        logger.error(f"Error ingesting gitleaks findings from {report_path}: {e}")
        return 0

def ingest_semgrep_findings(session, repo_id, report_path):
    """Ingest findings from semgrep JSON report."""
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)

        findings = data.get('results', [])
        if not findings:
            return 0

        # Get organization_id from repository
        repo_result = session.execute(
            text("SELECT organization_id FROM repositories WHERE id = :repo_id"),
            {"repo_id": repo_id}
        ).fetchone()
        org_id = repo_result[0] if repo_result else None

        count = 0
        for finding in findings:
            # Generate fingerprint and UUID
            check_id = finding.get('check_id', 'unknown')
            path = finding.get('path', '')
            line = finding.get('start', {}).get('line', 0)
            fingerprint = f"semgrep:{check_id}:{path}:{line}"
            finding_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, fingerprint))

            # Check if finding exists
            result = session.execute(
                text("SELECT id FROM findings WHERE repository_id = :repo_id AND file_path = :file_path AND line_start = :line_start AND scanner_name = 'semgrep'"),
                {
                    "repo_id": repo_id,
                    "file_path": path,
                    "line_start": line
                }
            ).fetchone()

            if result:
                continue

            # Map semgrep severity to our severity levels
            semgrep_severity = finding.get('extra', {}).get('severity', 'WARNING')
            severity_map = {'ERROR': 'high', 'WARNING': 'medium', 'INFO': 'low'}
            severity = severity_map.get(semgrep_severity, 'medium')

            # Create finding
            finding_id = str(uuid.uuid4())
            session.execute(
                text("""
                    INSERT INTO findings
                    (id, organization_id, repository_id, scanner_name, finding_type, severity, title,
                     description, file_path, line_start, line_end, finding_uuid,
                     status, created_at, updated_at)
                    VALUES
                    (:id, :org_id, :repo_id, :scanner, :finding_type, :severity, :title,
                     :description, :file_path, :line_start, :line_end, :finding_uuid,
                     :status, :created_at, :updated_at)
                """),
                {
                    "id": finding_id,
                    "org_id": org_id,
                    "repo_id": repo_id,
                    "scanner": "semgrep",
                    "finding_type": "sast",  # Fixed: Use 'sast' for semgrep findings
                    "severity": severity,
                    "title": finding.get('extra', {}).get('message', 'Security issue detected'),
                    "description": finding.get('extra', {}).get('message', ''),
                    "file_path": path,
                    "line_start": finding.get('start', {}).get('line'),
                    "line_end": finding.get('end', {}).get('line'),
                    "finding_uuid": finding_uuid,
                    "status": "open",
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                }
            )
            count += 1

        session.commit()
        return count
    except Exception as e:
        session.rollback()
        logger.error(f"Error ingesting semgrep findings from {report_path}: {e}")
        return 0

def ingest_grype_findings(session, repo_id, report_path):
    """Ingest findings from grype JSON report."""
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)

        findings = data.get('matches', [])
        if not findings:
            return 0

        # Get organization_id from repository
        repo_result = session.execute(
            text("SELECT organization_id FROM repositories WHERE id = :repo_id"),
            {"repo_id": repo_id}
        ).fetchone()
        org_id = repo_result[0] if repo_result else None

        count = 0
        for finding in findings:
            # Generate fingerprint
            vuln_id = finding.get('vulnerability', {}).get('id', 'unknown')
            artifact = finding.get('artifact', {}).get('name', '')
            version = finding.get('artifact', {}).get('version', '')
            fingerprint = f"grype:{vuln_id}:{artifact}:{version}"
            finding_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, fingerprint))

            # Check if finding exists
            result = session.execute(
                text("SELECT id FROM findings WHERE repository_id = :repo_id AND package_name = :package_name AND cve_id = :cve_id AND scanner_name = 'grype'"),
                {
                    "repo_id": repo_id,
                    "package_name": artifact,
                    "cve_id": vuln_id
                }
            ).fetchone()

            if result:
                continue

            # Map grype severity
            grype_severity = finding.get('vulnerability', {}).get('severity', 'Medium')
            severity = grype_severity.lower() if grype_severity.lower() in ['critical', 'high', 'medium', 'low'] else 'medium'

            # Create finding
            finding_id = str(uuid.uuid4())
            vuln = finding.get('vulnerability', {})
            session.execute(
                text("""
                    INSERT INTO findings
                    (id, organization_id, repository_id, scanner_name, finding_type, severity, title,
                     description, package_name, package_version, cve_id, finding_uuid,
                     status, created_at, updated_at)
                    VALUES
                    (:id, :org_id, :repo_id, :scanner, :finding_type, :severity, :title,
                     :description, :package_name, :package_version, :cve_id, :finding_uuid,
                     :status, :created_at, :updated_at)
                """),
                {
                    "id": finding_id,
                    "org_id": org_id,
                    "repo_id": repo_id,
                    "scanner": "grype",
                    "finding_type": "oss",  # Fixed: Use 'oss' for grype findings
                    "severity": severity,
                    "title": f"{vuln_id} in {artifact}",
                    "description": vuln.get('description', ''),
                    "package_name": artifact,
                    "package_version": version,
                    "cve_id": vuln_id,
                    "finding_uuid": finding_uuid,
                    "status": "open",
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                }
            )
            count += 1

        session.commit()
        return count
    except Exception as e:
        session.rollback()
        logger.error(f"Error ingesting grype findings from {report_path}: {e}")
        return 0

def ingest_contributors(session, repo_id, report_path):
    """Ingest contributors from intel.json report."""
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)

        contributors_data = data.get('contributors', {})
        top_contributors = contributors_data.get('top_contributors', [])

        if not top_contributors:
            return 0

        count = 0
        for contrib in top_contributors:
            # Generate contributor ID
            contrib_id = str(uuid.uuid4())

            # Check if contributor exists
            result = session.execute(
                text("SELECT id FROM contributors WHERE repository_id = :repo_id AND email = :email"),
                {
                    "repo_id": repo_id,
                    "email": contrib.get('email', '')
                }
            ).fetchone()

            if result:
                continue

            # Extract files contributed
            files_contributed = contrib.get('files_contributed', [])
            folders_contributed = list(set([
                os.path.dirname(f['path']) for f in files_contributed if f.get('path')
            ]))

            # Insert contributor
            session.execute(
                text("""
                    INSERT INTO contributors
                    (id, repository_id, name, email, github_username, commits, commit_percentage,
                     last_commit_at, languages, files_contributed, folders_contributed, risk_score,
                     created_at, updated_at)
                    VALUES
                    (:id, :repo_id, :name, :email, :github_username, :commits, :commit_percentage,
                     :last_commit_at, :languages, :files_contributed, :folders_contributed, :risk_score,
                     :created_at, :updated_at)
                """),
                {
                    "id": contrib_id,
                    "repo_id": repo_id,
                    "name": contrib.get('name', 'Unknown'),
                    "email": contrib.get('email', ''),
                    "github_username": contrib.get('github_username'),
                    "commits": contrib.get('commits', 0),
                    "commit_percentage": contrib.get('commit_percentage'),
                    "last_commit_at": contrib.get('last_commit_at'),
                    "languages": json.dumps(contrib.get('languages', [])),
                    "files_contributed": json.dumps(files_contributed),
                    "folders_contributed": json.dumps(folders_contributed),
                    "risk_score": 0,  # Calculate based on files with findings
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                }
            )
            count += 1

        session.commit()
        return count
    except Exception as e:
        session.rollback()
        logger.error(f"Error ingesting contributors from {report_path}: {e}")
        return 0

def ingest_languages(session, repo_id, report_path):
    """Ingest language statistics from cloc.json report."""
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)

        count = 0
        for lang_name, lang_data in data.items():
            # Skip header and SUM entries
            if lang_name in ['header', 'SUM'] or not isinstance(lang_data, dict):
                continue

            # Check if language stat exists
            result = session.execute(
                text("SELECT id FROM language_stats WHERE repository_id = :repo_id AND name = :name"),
                {
                    "repo_id": repo_id,
                    "name": lang_name
                }
            ).fetchone()

            if result:
                continue

            # Insert language stat
            lang_id = str(uuid.uuid4())
            session.execute(
                text("""
                    INSERT INTO language_stats
                    (id, repository_id, name, files, lines, blanks, comments, created_at, updated_at)
                    VALUES
                    (:id, :repo_id, :name, :files, :lines, :blanks, :comments, :created_at, :updated_at)
                """),
                {
                    "id": lang_id,
                    "repo_id": repo_id,
                    "name": lang_name,
                    "files": lang_data.get('nFiles', 0),
                    "lines": lang_data.get('code', 0),
                    "blanks": lang_data.get('blank', 0),
                    "comments": lang_data.get('comment', 0),
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                }
            )
            count += 1

        session.commit()
        return count
    except Exception as e:
        session.rollback()
        logger.error(f"Error ingesting languages from {report_path}: {e}")
        return 0

def ingest_dependencies(session, repo_id, report_path):
    """Ingest dependencies from syft SBOM report."""
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)

        components = data.get('components', [])
        if not components:
            return 0

        count = 0
        for component in components:
            name = component.get('name', 'unknown')
            version = component.get('version', 'unknown')
            purl = component.get('purl', '')

            # Check if dependency exists
            result = session.execute(
                text("SELECT id FROM dependencies WHERE repository_id = :repo_id AND name = :name AND version = :version"),
                {
                    "repo_id": repo_id,
                    "name": name,
                    "version": version
                }
            ).fetchone()

            if result:
                continue

            # Extract package manager from purl or properties
            package_manager = 'unknown'
            if purl.startswith('pkg:'):
                package_manager = purl.split(':')[1].split('/')[0]

            # Extract locations
            locations = []
            properties = component.get('properties', [])
            for prop in properties:
                if prop.get('name', '').startswith('syft:location:'):
                    locations.append(prop.get('value', ''))

            # Insert dependency
            dep_id = str(uuid.uuid4())
            session.execute(
                text("""
                    INSERT INTO dependencies
                    (id, repository_id, name, version, type, package_manager, license,
                     locations, source, created_at, updated_at)
                    VALUES
                    (:id, :repo_id, :name, :version, :type, :package_manager, :license,
                     :locations, :source, :created_at, :updated_at)
                """),
                {
                    "id": dep_id,
                    "repo_id": repo_id,
                    "name": name,
                    "version": version,
                    "type": component.get('type', 'library'),
                    "package_manager": package_manager,
                    "license": component.get('licenses', [{}])[0].get('license', {}).get('id', 'Unknown') if component.get('licenses') else 'Unknown',
                    "locations": json.dumps(locations),
                    "source": purl,
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                }
            )
            count += 1

        session.commit()
        return count
    except Exception as e:
        session.rollback()
        logger.error(f"Error ingesting dependencies from {report_path}: {e}")
        return 0

def ingest_organization_reports(org_name):
    """Ingest all reports for an organization.

    Returns:
        dict: Statistics with 'repos' and 'findings' counts, or None if failed
    """
    org_dir = REPORTS_DIR / org_name
    if not org_dir.exists():
        logger.warning(f"Organization directory not found: {org_dir}")
        return None

    session = Session()
    try:
        # Get organization ID
        org_id = get_organization_id(session, org_name)
        if not org_id:
            logger.error(f"Organization not found in database: {org_name}")
            return None

        logger.info(f"Processing organization: {org_name} (ID: {org_id})")

        total_repos = 0
        total_findings = 0

        # Iterate through repository directories
        for repo_dir in sorted(org_dir.iterdir()):
            if not repo_dir.is_dir():
                continue

            repo_name = repo_dir.name

            # Skip non-repo directories
            if repo_name.startswith('_') or repo_name.startswith('.'):
                continue

            logger.info(f"  Processing repository: {repo_name}")

            # Create repository
            repo_id = ingest_repository(session, org_id, org_name, repo_name)
            total_repos += 1

            # Ingest findings from different scanners
            gitleaks_file = repo_dir / f"{repo_name}_gitleaks.json"
            if gitleaks_file.exists():
                count = ingest_gitleaks_findings(session, repo_id, gitleaks_file)
                total_findings += count
                logger.info(f"    Ingested {count} gitleaks findings")

            semgrep_file = repo_dir / f"{repo_name}_semgrep.json"
            if semgrep_file.exists():
                count = ingest_semgrep_findings(session, repo_id, semgrep_file)
                total_findings += count
                logger.info(f"    Ingested {count} semgrep findings")

            grype_file = repo_dir / f"{repo_name}_grype_repo.json"
            if grype_file.exists():
                count = ingest_grype_findings(session, repo_id, grype_file)
                total_findings += count
                logger.info(f"    Ingested {count} grype findings")

            # Ingest contributors from intel.json
            intel_file = repo_dir / f"{repo_name}_intel.json"
            if intel_file.exists():
                count = ingest_contributors(session, repo_id, intel_file)
                if count > 0:
                    logger.info(f"    Ingested {count} contributors")

            # Ingest languages from cloc.json
            cloc_file = repo_dir / f"{repo_name}_cloc.json"
            if cloc_file.exists():
                count = ingest_languages(session, repo_id, cloc_file)
                if count > 0:
                    logger.info(f"    Ingested {count} languages")

            # Ingest dependencies from syft SBOM
            syft_file = repo_dir / f"{repo_name}_syft_repo.json"
            if syft_file.exists():
                count = ingest_dependencies(session, repo_id, syft_file)
                if count > 0:
                    logger.info(f"    Ingested {count} dependencies")

        logger.info(f"Completed {org_name}: {total_repos} repositories, {total_findings} findings")

        return {
            'repos': total_repos,
            'findings': total_findings
        }

    except Exception as e:
        logger.error(f"Error ingesting organization {org_name}: {e}")
        return None
    finally:
        session.close()

def ingest_all_organizations(org_names=None):
    """
    Ingest reports for all organizations.

    Args:
        org_names: List of organization names to ingest. If None, ingests all found.

    Returns:
        dict: Results by organization name
    """
    if org_names is None:
        # Auto-detect organizations from report directory
        org_names = []
        if REPORTS_DIR.exists():
            for item in REPORTS_DIR.iterdir():
                if item.is_dir() and not item.name.startswith(('_', '.')):
                    org_names.append(item.name)

    if not org_names:
        logger.warning("No organizations found to ingest")
        return {}

    results = {}
    for org_name in org_names:
        result = ingest_organization_reports(org_name)
        if result:
            results[org_name] = result

    return results

def main():
    """Main ingestion function."""
    logger.info("Starting report ingestion...")

    # Ingest for all organizations
    results = ingest_all_organizations(['sleepnumberlabs', 'SleepNumberInc'])

    # Print summary
    for org_name, stats in results.items():
        logger.info(f"{org_name}: {stats['repos']} repos, {stats['findings']} findings")

    logger.info("Report ingestion complete!")

if __name__ == "__main__":
    main()
