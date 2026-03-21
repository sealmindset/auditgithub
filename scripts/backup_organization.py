#!/usr/bin/env python3
"""
Organization Backup Script

Backs up all data for a specific organization to a JSON file.
Supports individual org backup or all orgs at once.

Usage:
    # Backup single org
    python scripts/backup_organization.py --org myorg --output backups/
    
    # Backup all orgs
    python scripts/backup_organization.py --all --output backups/
    
    # List available orgs
    python scripts/backup_organization.py --list
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import UUID, ARRAY


def get_db_url():
    """Get database URL from environment."""
    host = os.environ.get('POSTGRES_HOST', 'localhost')
    port = os.environ.get('POSTGRES_PORT', '5432')
    user = os.environ.get('POSTGRES_USER', 'postgres')
    password = os.environ.get('POSTGRES_PASSWORD', 'postgres')
    db = os.environ.get('POSTGRES_DB', 'auditgh_kb')
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def get_session():
    """Create database session."""
    engine = create_engine(get_db_url())
    Session = sessionmaker(bind=engine)
    return Session()


def list_organizations(session):
    """List all organizations."""
    result = session.execute(text("""
        SELECT o.id, o.name, o.github_org,
               COUNT(DISTINCT r.id) as repo_count,
               COUNT(DISTINCT f.id) as finding_count
        FROM organizations o
        LEFT JOIN repositories r ON r.organization_id = o.id
        LEFT JOIN findings f ON f.repository_id = r.id
        GROUP BY o.id, o.name, o.github_org
        ORDER BY o.name
    """))
    
    orgs = []
    for row in result:
        orgs.append({
            'id': str(row.id),
            'name': row.name,
            'github_org': row.github_org,
            'repo_count': row.repo_count,
            'finding_count': row.finding_count
        })
    return orgs


def backup_organization(session, org_id: str, org_name: str) -> dict:
    """Backup all data for a specific organization."""
    print(f"  Backing up organization: {org_name} ({org_id})")
    
    backup = {
        'metadata': {
            'backup_version': '1.0',
            'backup_date': datetime.utcnow().isoformat(),
            'organization_id': org_id,
            'organization_name': org_name
        },
        'organization': None,
        'repositories': [],
        'findings': [],
        'credentials': [],
        'api_endpoints': [],
        'credential_url_correlations': [],
        'credential_url_test_results': [],
        'scan_runs': [],
        'contributors': []
    }
    
    # Backup organization record
    org_result = session.execute(text("""
        SELECT * FROM organizations WHERE id = :org_id
    """), {'org_id': org_id})
    org_row = org_result.fetchone()
    if org_row:
        backup['organization'] = dict(org_row._mapping)
        # Convert datetime/uuid to string
        for k, v in backup['organization'].items():
            if hasattr(v, 'isoformat'):
                backup['organization'][k] = v.isoformat()
            elif hasattr(v, 'hex'):
                backup['organization'][k] = str(v)
    
    # Backup repositories
    print("    - Backing up repositories...")
    repos_result = session.execute(text("""
        SELECT * FROM repositories WHERE organization_id = :org_id
    """), {'org_id': org_id})
    for row in repos_result:
        repo = dict(row._mapping)
        for k, v in repo.items():
            if hasattr(v, 'isoformat'):
                repo[k] = v.isoformat()
            elif hasattr(v, 'hex'):
                repo[k] = str(v)
        backup['repositories'].append(repo)
    print(f"      Found {len(backup['repositories'])} repositories")
    
    # Get repository IDs for related queries
    repo_ids = [r['id'] for r in backup['repositories']]
    
    ALLOWED_TABLES = {
        'scan_results', 'findings', 'scan_schedules', 'schedule_overrides',
        'scan_runs', 'contributors', 'contributor_profiles', 'contributor_aliases',
        'language_stats', 'dependencies', 'file_commits', 'commit_analyses',
        'component_analysis', 'api_endpoints', 'api_threat_assessments',
        'openapi_specs', 'credential_url_test_results', 'architecture_versions',
    }

    def query_by_repo_ids(table_name: str) -> list:
        """Query table for all repository IDs."""
        if table_name not in ALLOWED_TABLES:
            raise ValueError(f"Invalid table name: {table_name}")
        results = []
        for repo_id in repo_ids:
            rows = session.execute(text(f"""
                SELECT * FROM {table_name} WHERE repository_id = :repo_id
            """), {'repo_id': repo_id})
            for row in rows:
                item = dict(row._mapping)
                for k, v in item.items():
                    if hasattr(v, 'isoformat'):
                        item[k] = v.isoformat()
                    elif hasattr(v, 'hex'):
                        item[k] = str(v)
                results.append(item)
        return results
    
    def safe_query(table_name: str, label: str):
        """Safely query a table, handling missing tables."""
        print(f"    - Backing up {label}...")
        try:
            results = query_by_repo_ids(table_name)
            print(f"      Found {len(results)} {label}")
            return results
        except Exception as e:
            if "does not exist" in str(e):
                print(f"      Table {table_name} does not exist, skipping")
            else:
                print(f"      Error: {e}")
            session.rollback()  # Reset transaction after error
            return []
    
    if repo_ids:
        backup['findings'] = safe_query('findings', 'findings')
        backup['credentials'] = safe_query('credentials', 'credentials')
        backup['api_endpoints'] = safe_query('api_endpoints', 'API endpoints')
        backup['credential_url_correlations'] = safe_query('credential_url_correlations', 'correlations')
        backup['credential_url_test_results'] = safe_query('credential_url_test_results', 'test results')
        backup['scan_runs'] = safe_query('scan_runs', 'scan runs')
        backup['contributors'] = safe_query('contributors', 'contributors')
    
    # Summary
    backup['metadata']['summary'] = {
        'repositories': len(backup['repositories']),
        'findings': len(backup['findings']),
        'credentials': len(backup['credentials']),
        'api_endpoints': len(backup['api_endpoints']),
        'credential_url_correlations': len(backup['credential_url_correlations']),
        'credential_url_test_results': len(backup['credential_url_test_results']),
        'scan_runs': len(backup['scan_runs']),
        'contributors': len(backup['contributors'])
    }
    
    return backup


def save_backup(backup: dict, output_dir: str, org_name: str):
    """Save backup to file."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"{org_name}_backup_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w') as f:
        json.dump(backup, f, indent=2, default=str)
    
    file_size = os.path.getsize(filepath)
    print(f"  Saved: {filepath} ({file_size / 1024:.1f} KB)")
    return filepath


def main():
    parser = argparse.ArgumentParser(description='Backup organization data')
    parser.add_argument('--org', help='Organization name to backup')
    parser.add_argument('--all', action='store_true', help='Backup all organizations')
    parser.add_argument('--list', action='store_true', help='List available organizations')
    parser.add_argument('--output', default='backups', help='Output directory (default: backups)')
    
    args = parser.parse_args()
    
    if not args.org and not args.all and not args.list:
        parser.print_help()
        sys.exit(1)
    
    session = get_session()
    
    try:
        if args.list:
            print("\nAvailable Organizations:")
            print("-" * 80)
            orgs = list_organizations(session)
            for org in orgs:
                print(f"  {org['name']:<20} {org['github_org'] or 'N/A':<25} "
                      f"Repos: {org['repo_count']:<5} Findings: {org['finding_count']}")
            print()
            return
        
        orgs = list_organizations(session)
        
        if args.all:
            print(f"\nBacking up all {len(orgs)} organizations...")
            for org in orgs:
                backup = backup_organization(session, org['id'], org['name'])
                save_backup(backup, args.output, org['name'])
            print(f"\nAll backups saved to: {args.output}/")
        
        elif args.org:
            # Find org by name
            org = next((o for o in orgs if o['name'].lower() == args.org.lower()), None)
            if not org:
                print(f"Error: Organization '{args.org}' not found")
                print("Available organizations:", [o['name'] for o in orgs])
                sys.exit(1)
            
            print(f"\nBacking up organization: {org['name']}")
            backup = backup_organization(session, org['id'], org['name'])
            filepath = save_backup(backup, args.output, org['name'])
            print(f"\nBackup complete: {filepath}")
    
    finally:
        session.close()


if __name__ == '__main__':
    main()
