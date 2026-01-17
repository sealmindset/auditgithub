"""
Validate data ingestion completeness.

This script validates that scan data has been properly ingested into the database
by comparing filesystem reports with database records.
"""
import os
import json
import logging
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/security_portal')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

REPORTS_DIR = Path(os.getenv('REPORTS_DIR', '/app/vulnerability_reports'))


class IngestionValidator:
    """Validates data ingestion completeness."""

    def __init__(self, session):
        self.session = session
        self.issues = []
        self.stats = defaultdict(lambda: defaultdict(int))

    def validate_organization(self, org_name):
        """Validate ingestion for an organization."""
        logger.info(f"Validating organization: {org_name}")

        org_dir = REPORTS_DIR / org_name
        if not org_dir.exists():
            logger.warning(f"Organization directory not found: {org_dir}")
            return None

        # Get organization from database
        org_result = self.session.execute(
            text("SELECT id FROM organizations WHERE name = :name"),
            {"name": org_name}
        ).fetchone()

        if not org_result:
            self.issues.append({
                "type": "missing_organization",
                "org": org_name,
                "message": f"Organization {org_name} not found in database"
            })
            return None

        org_id = org_result[0]

        # Iterate through repository directories
        for repo_dir in sorted(org_dir.iterdir()):
            if not repo_dir.is_dir() or repo_dir.name.startswith(('_', '.')):
                continue

            repo_name = repo_dir.name
            self.validate_repository(org_id, org_name, repo_name, repo_dir)

        return self.get_summary(org_name)

    def validate_repository(self, org_id, org_name, repo_name, repo_dir):
        """Validate ingestion for a single repository."""

        # Get repository from database
        repo_result = self.session.execute(
            text("SELECT id FROM repositories WHERE organization_id = :org_id AND name = :name"),
            {"org_id": org_id, "name": repo_name}
        ).fetchone()

        if not repo_result:
            self.issues.append({
                "type": "missing_repository",
                "org": org_name,
                "repo": repo_name,
                "message": f"Repository {repo_name} not found in database"
            })
            return

        repo_id = repo_result[0]

        # Validate each data type
        self.validate_findings(org_name, repo_name, repo_id, repo_dir)
        self.validate_contributors(org_name, repo_name, repo_id, repo_dir)
        self.validate_languages(org_name, repo_name, repo_id, repo_dir)
        self.validate_dependencies(org_name, repo_name, repo_id, repo_dir)

    def validate_findings(self, org_name, repo_name, repo_id, repo_dir):
        """Validate findings ingestion."""
        # Check gitleaks
        gitleaks_file = repo_dir / f"{repo_name}_gitleaks.json"
        if gitleaks_file.exists():
            with open(gitleaks_file, 'r') as f:
                gitleaks_data = json.load(f)

            file_count = len(gitleaks_data) if isinstance(gitleaks_data, list) else 0

            db_count_result = self.session.execute(
                text("SELECT COUNT(*) FROM findings WHERE repository_id = :repo_id AND scanner_name = 'gitleaks'"),
                {"repo_id": repo_id}
            ).fetchone()
            db_count = db_count_result[0] if db_count_result else 0

            self.stats[org_name]["gitleaks_file"] += file_count
            self.stats[org_name]["gitleaks_db"] += db_count

            if file_count > 0 and db_count == 0:
                self.issues.append({
                    "type": "missing_gitleaks_findings",
                    "org": org_name,
                    "repo": repo_name,
                    "file_count": file_count,
                    "db_count": db_count,
                    "message": f"Gitleaks findings not ingested: {file_count} in file, 0 in database"
                })

        # Check semgrep
        semgrep_file = repo_dir / f"{repo_name}_semgrep.json"
        if semgrep_file.exists():
            with open(semgrep_file, 'r') as f:
                semgrep_data = json.load(f)

            file_count = len(semgrep_data.get('results', [])) if isinstance(semgrep_data, dict) else 0

            db_count_result = self.session.execute(
                text("SELECT COUNT(*) FROM findings WHERE repository_id = :repo_id AND scanner_name = 'semgrep'"),
                {"repo_id": repo_id}
            ).fetchone()
            db_count = db_count_result[0] if db_count_result else 0

            self.stats[org_name]["semgrep_file"] += file_count
            self.stats[org_name]["semgrep_db"] += db_count

            if file_count > 0 and db_count == 0:
                self.issues.append({
                    "type": "missing_semgrep_findings",
                    "org": org_name,
                    "repo": repo_name,
                    "file_count": file_count,
                    "db_count": db_count,
                    "message": f"Semgrep findings not ingested: {file_count} in file, 0 in database"
                })

        # Check grype
        grype_file = repo_dir / f"{repo_name}_grype_repo.json"
        if grype_file.exists():
            with open(grype_file, 'r') as f:
                grype_data = json.load(f)

            file_count = len(grype_data.get('matches', [])) if isinstance(grype_data, dict) else 0

            db_count_result = self.session.execute(
                text("SELECT COUNT(*) FROM findings WHERE repository_id = :repo_id AND scanner_name = 'grype'"),
                {"repo_id": repo_id}
            ).fetchone()
            db_count = db_count_result[0] if db_count_result else 0

            self.stats[org_name]["grype_file"] += file_count
            self.stats[org_name]["grype_db"] += db_count

            if file_count > 0 and db_count == 0:
                self.issues.append({
                    "type": "missing_grype_findings",
                    "org": org_name,
                    "repo": repo_name,
                    "file_count": file_count,
                    "db_count": db_count,
                    "message": f"Grype findings not ingested: {file_count} in file, 0 in database"
                })

    def validate_contributors(self, org_name, repo_name, repo_id, repo_dir):
        """Validate contributors ingestion."""
        intel_file = repo_dir / f"{repo_name}_intel.json"
        if intel_file.exists():
            with open(intel_file, 'r') as f:
                intel_data = json.load(f)

            contributors_data = intel_data.get('contributors', {})
            file_count = len(contributors_data.get('top_contributors', []))

            db_count_result = self.session.execute(
                text("SELECT COUNT(*) FROM contributors WHERE repository_id = :repo_id"),
                {"repo_id": repo_id}
            ).fetchone()
            db_count = db_count_result[0] if db_count_result else 0

            self.stats[org_name]["contributors_file"] += file_count
            self.stats[org_name]["contributors_db"] += db_count

            if file_count > 0 and db_count == 0:
                self.issues.append({
                    "type": "missing_contributors",
                    "org": org_name,
                    "repo": repo_name,
                    "file_count": file_count,
                    "db_count": db_count,
                    "severity": "high",
                    "message": f"Contributors not ingested: {file_count} in file, 0 in database"
                })
            elif file_count != db_count:
                self.issues.append({
                    "type": "partial_contributors",
                    "org": org_name,
                    "repo": repo_name,
                    "file_count": file_count,
                    "db_count": db_count,
                    "severity": "medium",
                    "message": f"Partial contributor ingestion: {db_count}/{file_count} ingested"
                })

    def validate_languages(self, org_name, repo_name, repo_id, repo_dir):
        """Validate languages ingestion."""
        cloc_file = repo_dir / f"{repo_name}_cloc.json"
        if cloc_file.exists():
            with open(cloc_file, 'r') as f:
                cloc_data = json.load(f)

            # Count languages (exclude 'header' and 'SUM')
            file_count = sum(1 for k in cloc_data.keys() if k not in ['header', 'SUM'])

            db_count_result = self.session.execute(
                text("SELECT COUNT(*) FROM language_stats WHERE repository_id = :repo_id"),
                {"repo_id": repo_id}
            ).fetchone()
            db_count = db_count_result[0] if db_count_result else 0

            self.stats[org_name]["languages_file"] += file_count
            self.stats[org_name]["languages_db"] += db_count

            if file_count > 0 and db_count == 0:
                self.issues.append({
                    "type": "missing_languages",
                    "org": org_name,
                    "repo": repo_name,
                    "file_count": file_count,
                    "db_count": db_count,
                    "severity": "high",
                    "message": f"Languages not ingested: {file_count} in file, 0 in database"
                })

    def validate_dependencies(self, org_name, repo_name, repo_id, repo_dir):
        """Validate dependencies ingestion."""
        syft_file = repo_dir / f"{repo_name}_syft_repo.json"
        if syft_file.exists():
            with open(syft_file, 'r') as f:
                syft_data = json.load(f)

            file_count = len(syft_data.get('components', []))

            db_count_result = self.session.execute(
                text("SELECT COUNT(*) FROM dependencies WHERE repository_id = :repo_id"),
                {"repo_id": repo_id}
            ).fetchone()
            db_count = db_count_result[0] if db_count_result else 0

            self.stats[org_name]["dependencies_file"] += file_count
            self.stats[org_name]["dependencies_db"] += db_count

            if file_count > 0 and db_count == 0:
                self.issues.append({
                    "type": "missing_dependencies",
                    "org": org_name,
                    "repo": repo_name,
                    "file_count": file_count,
                    "db_count": db_count,
                    "severity": "high",
                    "message": f"Dependencies not ingested: {file_count} in file, 0 in database"
                })

    def get_summary(self, org_name):
        """Get validation summary for an organization."""
        org_stats = self.stats[org_name]

        summary = {
            "organization": org_name,
            "validated_at": datetime.now().isoformat(),
            "findings": {
                "gitleaks": {
                    "file": org_stats["gitleaks_file"],
                    "database": org_stats["gitleaks_db"],
                    "match": org_stats["gitleaks_file"] == org_stats["gitleaks_db"]
                },
                "semgrep": {
                    "file": org_stats["semgrep_file"],
                    "database": org_stats["semgrep_db"],
                    "match": org_stats["semgrep_file"] == org_stats["semgrep_db"]
                },
                "grype": {
                    "file": org_stats["grype_file"],
                    "database": org_stats["grype_db"],
                    "match": org_stats["grype_file"] == org_stats["grype_db"]
                }
            },
            "contributors": {
                "file": org_stats["contributors_file"],
                "database": org_stats["contributors_db"],
                "match": org_stats["contributors_file"] == org_stats["contributors_db"]
            },
            "languages": {
                "file": org_stats["languages_file"],
                "database": org_stats["languages_db"],
                "match": org_stats["languages_file"] == org_stats["languages_db"]
            },
            "dependencies": {
                "file": org_stats["dependencies_file"],
                "database": org_stats["dependencies_db"],
                "match": org_stats["dependencies_file"] == org_stats["dependencies_db"]
            },
            "issues_count": len([i for i in self.issues if i.get("org") == org_name])
        }

        return summary

    def print_report(self, summaries):
        """Print validation report."""
        print("\n" + "=" * 80)
        print("INGESTION VALIDATION REPORT")
        print("=" * 80)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("")

        for summary in summaries:
            org = summary["organization"]
            print(f"\n{org}:")
            print("-" * 80)

            # Findings
            print("\nFindings:")
            for scanner in ["gitleaks", "semgrep", "grype"]:
                data = summary["findings"][scanner]
                match_icon = "✅" if data["match"] else "❌"
                print(f"  {match_icon} {scanner:12} File: {data['file']:6} | DB: {data['database']:6} | Match: {data['match']}")

            # Contributors
            data = summary["contributors"]
            match_icon = "✅" if data["match"] else "❌"
            print(f"\nContributors:")
            print(f"  {match_icon} {'contributors':12} File: {data['file']:6} | DB: {data['database']:6} | Match: {data['match']}")

            # Languages
            data = summary["languages"]
            match_icon = "✅" if data["match"] else "❌"
            print(f"\nLanguages:")
            print(f"  {match_icon} {'languages':12} File: {data['file']:6} | DB: {data['database']:6} | Match: {data['match']}")

            # Dependencies
            data = summary["dependencies"]
            match_icon = "✅" if data["match"] else "❌"
            print(f"\nDependencies:")
            print(f"  {match_icon} {'dependencies':12} File: {data['file']:6} | DB: {data['database']:6} | Match: {data['match']}")

            # Issues
            org_issues = [i for i in self.issues if i.get("org") == org]
            if org_issues:
                print(f"\n⚠️  Issues Found: {len(org_issues)}")
                for issue in org_issues[:10]:  # Show first 10
                    severity = issue.get("severity", "low")
                    severity_icon = "🔴" if severity == "high" else "🟡" if severity == "medium" else "🟢"
                    print(f"    {severity_icon} {issue['type']}: {issue['message']}")
                if len(org_issues) > 10:
                    print(f"    ... and {len(org_issues) - 10} more issues")

        print("\n" + "=" * 80)
        print(f"Total Issues: {len(self.issues)}")
        if self.issues:
            high_priority = len([i for i in self.issues if i.get("severity") == "high"])
            print(f"High Priority: {high_priority}")
        print("=" * 80 + "\n")


def validate_all_organizations(org_names=None):
    """Validate ingestion for all organizations."""
    if org_names is None:
        # Auto-detect organizations
        org_names = []
        if REPORTS_DIR.exists():
            for item in REPORTS_DIR.iterdir():
                if item.is_dir() and not item.name.startswith(('_', '.')):
                    org_names.append(item.name)

    if not org_names:
        logger.warning("No organizations found to validate")
        return

    session = Session()
    try:
        validator = IngestionValidator(session)
        summaries = []

        for org_name in org_names:
            summary = validator.validate_organization(org_name)
            if summary:
                summaries.append(summary)

        validator.print_report(summaries)

        # Return issues for programmatic access
        return {
            "summaries": summaries,
            "issues": validator.issues,
            "total_issues": len(validator.issues),
            "high_priority": len([i for i in validator.issues if i.get("severity") == "high"])
        }
    finally:
        session.close()


def main():
    """Main validation function."""
    logger.info("Starting ingestion validation...")

    results = validate_all_organizations()

    if results and results["total_issues"] > 0:
        logger.warning(f"Validation found {results['total_issues']} issues ({results['high_priority']} high priority)")
        exit(1)  # Exit with error code if issues found
    else:
        logger.info("✅ Validation passed - all data properly ingested")
        exit(0)


if __name__ == "__main__":
    main()
