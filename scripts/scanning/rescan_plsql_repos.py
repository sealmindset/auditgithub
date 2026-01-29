#!/usr/bin/env python3
"""
Re-scan existing repositories that contain PL/SQL code.

This script identifies repositories with .sql, .pls, .pkb files and re-runs
Semgrep with PL/SQL security rules to update their findings.

Usage:
    python rescan_plsql_repos.py [--org ORG_NAME] [--dry-run]

Examples:
    python rescan_plsql_repos.py --org SleepNumberInc --dry-run
    python rescan_plsql_repos.py --org SleepNumberInc
    python rescan_plsql_repos.py  # Scans all orgs
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database configuration
DB_HOST = os.getenv('POSTGRES_HOST', 'localhost')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')
DB_NAME = os.getenv('POSTGRES_DB', 'security_portal')
DB_USER = os.getenv('POSTGRES_USER', 'postgres')
DB_PASS = os.getenv('POSTGRES_PASSWORD', 'postgres')

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Reports directory
REPORTS_DIR = Path(os.getenv('REPORTS_DIR', '/app/vulnerability_reports'))
if not REPORTS_DIR.exists():
    REPORTS_DIR = Path('vulnerability_reports')

# PL/SQL file extensions
PLSQL_EXTENSIONS = ('.sql', '.pls', '.pkb', '.pks', '.plb', '.fnc', '.prc', '.trg', '.vw')


def find_plsql_repositories(org_name=None):
    """
    Find repositories that contain PL/SQL files.

    Args:
        org_name: Optional organization name to filter by

    Returns:
        List of tuples: (repo_id, repo_name, org_name, file_count)
    """
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # Get all repositories
        query = """
            SELECT r.id, r.name, o.github_org
            FROM repositories r
            JOIN organizations o ON r.organization_id = o.id
        """

        if org_name:
            query += " WHERE o.github_org = :org_name"
            result = db.execute(text(query), {"org_name": org_name})
        else:
            result = db.execute(text(query))

        repositories = result.fetchall()

        # Check which repos have PL/SQL files
        plsql_repos = []

        for repo_id, repo_name, github_org in repositories:
            # Check report directory for PL/SQL files
            repo_paths = [
                REPORTS_DIR / github_org / repo_name,
                REPORTS_DIR / repo_name,
            ]

            file_count = 0
            for repo_path in repo_paths:
                if repo_path.exists():
                    for root, _, files in os.walk(repo_path):
                        file_count += sum(1 for f in files if f.endswith(PLSQL_EXTENSIONS))

                    if file_count > 0:
                        plsql_repos.append((repo_id, repo_name, github_org, file_count))
                        break

        return plsql_repos

    finally:
        db.close()


def scan_repository_plsql(repo_id, repo_name, org_name, dry_run=False):
    """
    Run Semgrep with PL/SQL rules on a repository.

    Args:
        repo_id: Repository UUID
        repo_name: Repository name
        org_name: Organization name
        dry_run: If True, don't actually run the scan

    Returns:
        int: Number of findings (or -1 if scan failed)
    """
    # Find repository path
    repo_paths = [
        REPORTS_DIR / org_name / repo_name,
        REPORTS_DIR / repo_name,
    ]

    repo_path = None
    for path in repo_paths:
        if path.exists():
            repo_path = path
            break

    if not repo_path:
        logger.warning(f"Repository path not found for {org_name}/{repo_name}")
        return -1

    if dry_run:
        logger.info(f"[DRY RUN] Would scan: {org_name}/{repo_name}")
        return 0

    # Path to PL/SQL rules
    plsql_rules_path = Path(__file__).parent / "semgrep_plsql_rules.yml"
    if not plsql_rules_path.exists():
        logger.error(f"PL/SQL rules not found at {plsql_rules_path}")
        return -1

    # Output path for results
    output_json = repo_path / f"{repo_name}_semgrep_plsql.json"

    try:
        logger.info(f"Scanning {org_name}/{repo_name} with PL/SQL rules...")

        # Run Semgrep with PL/SQL rules only
        cmd = [
            "semgrep",
            "scan",
            "--config", str(plsql_rules_path),
            "--json",
            "--output", str(output_json),
            str(repo_path)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        # Count findings
        if output_json.exists():
            with open(output_json, 'r') as f:
                data = json.load(f)
                findings = data.get('results', [])
                logger.info(f"  Found {len(findings)} PL/SQL security issues")
                return len(findings)

        return 0

    except subprocess.TimeoutExpired:
        logger.error(f"Scan timeout for {org_name}/{repo_name}")
        return -1
    except Exception as e:
        logger.error(f"Error scanning {org_name}/{repo_name}: {e}")
        return -1


def main():
    parser = argparse.ArgumentParser(
        description='Re-scan repositories with PL/SQL code for security issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --org SleepNumberInc --dry-run   # Preview PL/SQL repos to scan
  %(prog)s --org SleepNumberInc             # Scan all PL/SQL repos in org
  %(prog)s                                  # Scan all PL/SQL repos in all orgs
        """
    )

    parser.add_argument(
        '--org',
        type=str,
        help='Organization name to scan (e.g., SleepNumberInc). If omitted, scans all orgs.'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview which repositories would be scanned without actually scanning'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose debug logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 80)
    logger.info("PL/SQL Repository Security Re-Scan")
    logger.info("=" * 80)
    logger.info(f"Target: {args.org or 'All organizations'}")
    logger.info(f"Mode: {'DRY RUN (preview only)' if args.dry_run else 'LIVE SCAN'}")
    logger.info("=" * 80)
    logger.info("")

    # Find repositories with PL/SQL code
    logger.info("Scanning repository directories for PL/SQL files...")
    plsql_repos = find_plsql_repositories(args.org)

    if not plsql_repos:
        logger.warning("No repositories with PL/SQL files found!")
        logger.info("")
        logger.info("Checked for files with extensions: " + ", ".join(PLSQL_EXTENSIONS))
        return

    logger.info(f"Found {len(plsql_repos)} repositories with PL/SQL code:")
    logger.info("")

    # Show repositories
    for idx, (repo_id, repo_name, org_name, file_count) in enumerate(plsql_repos, 1):
        logger.info(f"{idx:3}. {org_name}/{repo_name} ({file_count} PL/SQL files)")

    logger.info("")
    logger.info("=" * 80)

    if args.dry_run:
        logger.info("")
        logger.info("DRY RUN COMPLETE - No scans were performed")
        logger.info("Remove --dry-run flag to actually scan these repositories")
        logger.info("")
        logger.info("This will:")
        logger.info("  1. Run Semgrep with PL/SQL security rules on each repository")
        logger.info("  2. Create {repo_name}_semgrep_plsql.json files")
        logger.info("  3. Findings will be visible after running ingest_reports.py")
        return

    # Scan repositories
    logger.info("Starting PL/SQL security scans...")
    logger.info("")

    stats = {
        'total': len(plsql_repos),
        'scanned': 0,
        'failed': 0,
        'total_findings': 0
    }

    for idx, (repo_id, repo_name, org_name, file_count) in enumerate(plsql_repos, 1):
        logger.info(f"[{idx}/{stats['total']}] {org_name}/{repo_name}")

        findings_count = scan_repository_plsql(repo_id, repo_name, org_name, args.dry_run)

        if findings_count >= 0:
            stats['scanned'] += 1
            stats['total_findings'] += findings_count
        else:
            stats['failed'] += 1

    # Print summary
    logger.info("")
    logger.info("=" * 80)
    logger.info("Scan Complete!")
    logger.info("=" * 80)
    logger.info(f"Total Repositories: {stats['total']}")
    logger.info(f"Successfully Scanned: {stats['scanned']}")
    logger.info(f"Failed: {stats['failed']}")
    logger.info(f"Total PL/SQL Findings: {stats['total_findings']}")
    logger.info("=" * 80)
    logger.info("")
    logger.info("Next Steps:")
    logger.info("  1. Run: docker exec auditgh_api python ingest_reports.py")
    logger.info("  2. Or wait for next scheduled scan to auto-ingest")
    logger.info("  3. View findings in Web UI under SAST category")
    logger.info("")


if __name__ == "__main__":
    main()
