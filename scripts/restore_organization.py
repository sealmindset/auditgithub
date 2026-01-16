#!/usr/bin/env python3
"""
Organization Restore Script

Restores organization data from a backup JSON file.
Can restore to the same org (update) or create a new org.

Usage:
    # Restore to same org (updates existing data)
    python scripts/restore_organization.py --file backups/myorg_backup_20241214.json
    
    # Restore as new org with different name
    python scripts/restore_organization.py --file backups/myorg_backup_20241214.json --as-new neworg
    
    # Preview what would be restored (dry run)
    python scripts/restore_organization.py --file backups/myorg_backup_20241214.json --dry-run
    
    # Force restore (skip confirmation)
    python scripts/restore_organization.py --file backups/myorg_backup_20241214.json --force
"""

import argparse
import json
import os
import sys
from datetime import datetime
from uuid import uuid4

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


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


def load_backup(filepath: str) -> dict:
    """Load backup from file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def print_backup_summary(backup: dict):
    """Print summary of backup contents."""
    meta = backup.get('metadata', {})
    summary = meta.get('summary', {})
    
    print("\nBackup Summary:")
    print("-" * 50)
    print(f"  Organization: {meta.get('organization_name', 'Unknown')}")
    print(f"  Backup Date:  {meta.get('backup_date', 'Unknown')}")
    print(f"  Version:      {meta.get('backup_version', 'Unknown')}")
    print()
    print("  Contents:")
    print(f"    Repositories:      {summary.get('repositories', 0)}")
    print(f"    Findings:          {summary.get('findings', 0)}")
    print(f"    Credentials:       {summary.get('credentials', 0)}")
    print(f"    API Endpoints:     {summary.get('api_endpoints', 0)}")
    print(f"    URL Correlations:  {summary.get('credential_url_correlations', 0)}")
    print(f"    Test Results:      {summary.get('credential_url_test_results', 0)}")
    print(f"    Scan Runs:         {summary.get('scan_runs', 0)}")
    print(f"    Contributors:      {summary.get('contributors', 0)}")
    print()


def generate_id_mapping(backup: dict, new_org_id: str = None) -> dict:
    """Generate mapping from old IDs to new IDs."""
    mapping = {
        'organization': {},
        'repositories': {},
        'findings': {},
        'credentials': {},
        'api_endpoints': {},
        'credential_url_correlations': {},
        'credential_url_test_results': {},
        'scan_runs': {},
        'contributors': {}
    }
    
    # Organization ID mapping
    old_org_id = backup['metadata']['organization_id']
    mapping['organization'][old_org_id] = new_org_id or old_org_id
    
    # Generate new IDs for all entities if creating new org
    if new_org_id:
        for repo in backup.get('repositories', []):
            mapping['repositories'][repo['id']] = str(uuid4())
        
        for finding in backup.get('findings', []):
            mapping['findings'][finding['id']] = str(uuid4())
        
        for cred in backup.get('credentials', []):
            mapping['credentials'][cred['id']] = str(uuid4())
        
        for endpoint in backup.get('api_endpoints', []):
            mapping['api_endpoints'][endpoint['id']] = str(uuid4())
        
        for corr in backup.get('credential_url_correlations', []):
            mapping['credential_url_correlations'][corr['id']] = str(uuid4())
        
        for result in backup.get('credential_url_test_results', []):
            mapping['credential_url_test_results'][result['id']] = str(uuid4())
        
        for scan in backup.get('scan_runs', []):
            mapping['scan_runs'][scan['id']] = str(uuid4())
        
        for contrib in backup.get('contributors', []):
            mapping['contributors'][contrib['id']] = str(uuid4())
    
    return mapping


def restore_organization(session, backup: dict, new_org_name: str = None, 
                         dry_run: bool = False) -> dict:
    """Restore organization from backup."""
    
    stats = {
        'organization': 0,
        'repositories': 0,
        'findings': 0,
        'credentials': 0,
        'api_endpoints': 0,
        'credential_url_correlations': 0,
        'credential_url_test_results': 0,
        'scan_runs': 0,
        'contributors': 0
    }
    
    old_org_id = backup['metadata']['organization_id']
    old_org_name = backup['metadata']['organization_name']
    
    # Determine if we're creating a new org or updating existing
    creating_new = new_org_name is not None
    
    if creating_new:
        new_org_id = str(uuid4())
        print(f"\nCreating new organization: {new_org_name}")
    else:
        new_org_id = old_org_id
        print(f"\nRestoring to existing organization: {old_org_name}")
    
    # Generate ID mapping
    id_map = generate_id_mapping(backup, new_org_id if creating_new else None)
    
    if dry_run:
        print("\n[DRY RUN] Would perform the following operations:")
    
    try:
        # 1. Restore/Create organization
        org_data = backup.get('organization', {})
        if org_data:
            if creating_new:
                if not dry_run:
                    session.execute(text("""
                        INSERT INTO organizations (id, name, github_org, description, created_at, updated_at)
                        VALUES (:id, :name, :github_org, :description, NOW(), NOW())
                        ON CONFLICT (id) DO NOTHING
                    """), {
                        'id': new_org_id,
                        'name': new_org_name,
                        'github_org': org_data.get('github_org', new_org_name),
                        'description': org_data.get('description', f'Restored from {old_org_name}')
                    })
                print(f"  + Created organization: {new_org_name}")
            else:
                print(f"  ~ Using existing organization: {old_org_name}")
            stats['organization'] = 1
        
        # 2. Restore repositories
        print("\n  Restoring repositories...")
        for repo in backup.get('repositories', []):
            new_repo_id = id_map['repositories'].get(repo['id'], repo['id'])
            
            if not dry_run:
                # Delete existing if updating
                if not creating_new:
                    session.execute(text("""
                        DELETE FROM repositories WHERE id = :id
                    """), {'id': new_repo_id})
                
                session.execute(text("""
                    INSERT INTO repositories (
                        id, organization_id, name, full_name, description, 
                        html_url, clone_url, default_branch, language,
                        is_private, is_archived, is_fork,
                        stars_count, forks_count, open_issues_count,
                        created_at, updated_at, pushed_at, last_scanned_at
                    ) VALUES (
                        :id, :organization_id, :name, :full_name, :description,
                        :html_url, :clone_url, :default_branch, :language,
                        :is_private, :is_archived, :is_fork,
                        :stars_count, :forks_count, :open_issues_count,
                        :created_at, :updated_at, :pushed_at, :last_scanned_at
                    )
                """), {
                    'id': new_repo_id,
                    'organization_id': new_org_id,
                    'name': repo.get('name'),
                    'full_name': repo.get('full_name'),
                    'description': repo.get('description'),
                    'html_url': repo.get('html_url'),
                    'clone_url': repo.get('clone_url'),
                    'default_branch': repo.get('default_branch', 'main'),
                    'language': repo.get('language'),
                    'is_private': repo.get('is_private', False),
                    'is_archived': repo.get('is_archived', False),
                    'is_fork': repo.get('is_fork', False),
                    'stars_count': repo.get('stars_count', 0),
                    'forks_count': repo.get('forks_count', 0),
                    'open_issues_count': repo.get('open_issues_count', 0),
                    'created_at': repo.get('created_at'),
                    'updated_at': repo.get('updated_at'),
                    'pushed_at': repo.get('pushed_at'),
                    'last_scanned_at': repo.get('last_scanned_at')
                })
            stats['repositories'] += 1
        print(f"    Restored {stats['repositories']} repositories")
        
        # 3. Restore findings
        print("  Restoring findings...")
        for finding in backup.get('findings', []):
            new_finding_id = id_map['findings'].get(finding['id'], finding['id'])
            new_repo_id = id_map['repositories'].get(finding.get('repository_id'), finding.get('repository_id'))
            
            if not dry_run:
                session.execute(text("""
                    INSERT INTO findings (
                        id, repository_id, scanner, category, severity, title,
                        description, file_path, line_number, code_snippet,
                        rule_id, confidence, cwe_id, owasp_category,
                        remediation, status, created_at, updated_at
                    ) VALUES (
                        :id, :repository_id, :scanner, :category, :severity, :title,
                        :description, :file_path, :line_number, :code_snippet,
                        :rule_id, :confidence, :cwe_id, :owasp_category,
                        :remediation, :status, :created_at, :updated_at
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        scanner = EXCLUDED.scanner,
                        category = EXCLUDED.category,
                        severity = EXCLUDED.severity,
                        title = EXCLUDED.title,
                        description = EXCLUDED.description,
                        updated_at = NOW()
                """), {
                    'id': new_finding_id,
                    'repository_id': new_repo_id,
                    'scanner': finding.get('scanner'),
                    'category': finding.get('category'),
                    'severity': finding.get('severity'),
                    'title': finding.get('title'),
                    'description': finding.get('description'),
                    'file_path': finding.get('file_path'),
                    'line_number': finding.get('line_number'),
                    'code_snippet': finding.get('code_snippet'),
                    'rule_id': finding.get('rule_id'),
                    'confidence': finding.get('confidence'),
                    'cwe_id': finding.get('cwe_id'),
                    'owasp_category': finding.get('owasp_category'),
                    'remediation': finding.get('remediation'),
                    'status': finding.get('status', 'open'),
                    'created_at': finding.get('created_at'),
                    'updated_at': finding.get('updated_at')
                })
            stats['findings'] += 1
        print(f"    Restored {stats['findings']} findings")
        
        # 4. Restore credentials
        print("  Restoring credentials...")
        for cred in backup.get('credentials', []):
            new_cred_id = id_map['credentials'].get(cred['id'], cred['id'])
            new_repo_id = id_map['repositories'].get(cred.get('repository_id'), cred.get('repository_id'))
            
            if not dry_run:
                session.execute(text("""
                    INSERT INTO credentials (
                        id, repository_id, credential_type, credential_value,
                        file_path, line_number, environment, confidence_score,
                        is_active, last_validated_at, created_at, updated_at
                    ) VALUES (
                        :id, :repository_id, :credential_type, :credential_value,
                        :file_path, :line_number, :environment, :confidence_score,
                        :is_active, :last_validated_at, :created_at, :updated_at
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        credential_type = EXCLUDED.credential_type,
                        updated_at = NOW()
                """), {
                    'id': new_cred_id,
                    'repository_id': new_repo_id,
                    'credential_type': cred.get('credential_type'),
                    'credential_value': cred.get('credential_value'),
                    'file_path': cred.get('file_path'),
                    'line_number': cred.get('line_number'),
                    'environment': cred.get('environment'),
                    'confidence_score': cred.get('confidence_score'),
                    'is_active': cred.get('is_active', True),
                    'last_validated_at': cred.get('last_validated_at'),
                    'created_at': cred.get('created_at'),
                    'updated_at': cred.get('updated_at')
                })
            stats['credentials'] += 1
        print(f"    Restored {stats['credentials']} credentials")
        
        # 5. Restore credential-URL test results
        print("  Restoring credential-URL test results...")
        for result in backup.get('credential_url_test_results', []):
            new_result_id = id_map['credential_url_test_results'].get(result['id'], result['id'])
            new_repo_id = id_map['repositories'].get(result.get('repository_id'), result.get('repository_id'))
            
            if not dry_run:
                session.execute(text("""
                    INSERT INTO credential_url_test_results (
                        id, organization_id, repository_id, target_url, credential_type,
                        credential_value, credential_environment, confidence_score,
                        auth_status, auth_status_code, auth_response_time_ms, auth_error_message,
                        auth_headers_used, auth_request_method, auth_request_url,
                        auth_request_headers, auth_request_body, auth_response_headers,
                        auth_response_body, auth_response_body_truncated,
                        detected_service, service_detection_score,
                        discovered_paths, discovered_paths_count, hidden_paths_found,
                        sample_data_retrieved, data_sensitivity_indicators,
                        osint_findings, github_repos_found, documentation_links_found,
                        ai_overview, ai_risk_assessment, ai_recommendations, threat_level,
                        test_mode, tested_at, test_duration_seconds,
                        llm_provider, llm_model, raw_llm_responses,
                        created_at, updated_at
                    ) VALUES (
                        :id, :organization_id, :repository_id, :target_url, :credential_type,
                        :credential_value, :credential_environment, :confidence_score,
                        :auth_status, :auth_status_code, :auth_response_time_ms, :auth_error_message,
                        :auth_headers_used, :auth_request_method, :auth_request_url,
                        :auth_request_headers, :auth_request_body, :auth_response_headers,
                        :auth_response_body, :auth_response_body_truncated,
                        :detected_service, :service_detection_score,
                        :discovered_paths, :discovered_paths_count, :hidden_paths_found,
                        :sample_data_retrieved, :data_sensitivity_indicators,
                        :osint_findings, :github_repos_found, :documentation_links_found,
                        :ai_overview, :ai_risk_assessment, :ai_recommendations, :threat_level,
                        :test_mode, :tested_at, :test_duration_seconds,
                        :llm_provider, :llm_model, :raw_llm_responses,
                        :created_at, :updated_at
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        auth_status = EXCLUDED.auth_status,
                        updated_at = NOW()
                """), {
                    'id': new_result_id,
                    'organization_id': new_org_id,
                    'repository_id': new_repo_id,
                    'target_url': result.get('target_url'),
                    'credential_type': result.get('credential_type'),
                    'credential_value': result.get('credential_value'),
                    'credential_environment': result.get('credential_environment'),
                    'confidence_score': result.get('confidence_score'),
                    'auth_status': result.get('auth_status'),
                    'auth_status_code': result.get('auth_status_code'),
                    'auth_response_time_ms': result.get('auth_response_time_ms'),
                    'auth_error_message': result.get('auth_error_message'),
                    'auth_headers_used': json.dumps(result.get('auth_headers_used', [])),
                    'auth_request_method': result.get('auth_request_method', 'GET'),
                    'auth_request_url': result.get('auth_request_url'),
                    'auth_request_headers': json.dumps(result.get('auth_request_headers', {})),
                    'auth_request_body': result.get('auth_request_body', ''),
                    'auth_response_headers': json.dumps(result.get('auth_response_headers', {})),
                    'auth_response_body': result.get('auth_response_body', ''),
                    'auth_response_body_truncated': result.get('auth_response_body_truncated', False),
                    'detected_service': result.get('detected_service'),
                    'service_detection_score': result.get('service_detection_score', 0),
                    'discovered_paths': json.dumps(result.get('discovered_paths', [])),
                    'discovered_paths_count': result.get('discovered_paths_count', 0),
                    'hidden_paths_found': result.get('hidden_paths_found', 0),
                    'sample_data_retrieved': json.dumps(result.get('sample_data_retrieved', [])),
                    'data_sensitivity_indicators': json.dumps(result.get('data_sensitivity_indicators', [])),
                    'osint_findings': json.dumps(result.get('osint_findings', [])),
                    'github_repos_found': result.get('github_repos_found', 0),
                    'documentation_links_found': result.get('documentation_links_found', 0),
                    'ai_overview': result.get('ai_overview'),
                    'ai_risk_assessment': result.get('ai_risk_assessment'),
                    'ai_recommendations': json.dumps(result.get('ai_recommendations', [])),
                    'threat_level': result.get('threat_level'),
                    'test_mode': result.get('test_mode'),
                    'tested_at': result.get('tested_at'),
                    'test_duration_seconds': result.get('test_duration_seconds'),
                    'llm_provider': result.get('llm_provider'),
                    'llm_model': result.get('llm_model'),
                    'raw_llm_responses': json.dumps(result.get('raw_llm_responses', [])),
                    'created_at': result.get('created_at'),
                    'updated_at': result.get('updated_at')
                })
            stats['credential_url_test_results'] += 1
        print(f"    Restored {stats['credential_url_test_results']} test results")
        
        if not dry_run:
            session.commit()
            print("\n✓ Restore completed successfully!")
        else:
            session.rollback()
            print("\n[DRY RUN] No changes were made.")
        
    except Exception as e:
        session.rollback()
        print(f"\n✗ Error during restore: {e}")
        raise
    
    return stats


def main():
    parser = argparse.ArgumentParser(description='Restore organization data from backup')
    parser.add_argument('--file', required=True, help='Backup file to restore from')
    parser.add_argument('--as-new', metavar='NAME', help='Create as new organization with this name')
    parser.add_argument('--dry-run', action='store_true', help='Preview without making changes')
    parser.add_argument('--force', action='store_true', help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"Error: Backup file not found: {args.file}")
        sys.exit(1)
    
    # Load backup
    print(f"Loading backup: {args.file}")
    backup = load_backup(args.file)
    print_backup_summary(backup)
    
    # Confirmation
    if not args.force and not args.dry_run:
        if args.as_new:
            prompt = f"Create new organization '{args.as_new}' from this backup?"
        else:
            prompt = f"Restore to organization '{backup['metadata']['organization_name']}'? (This will update existing data)"
        
        response = input(f"{prompt} [y/N]: ")
        if response.lower() != 'y':
            print("Cancelled.")
            sys.exit(0)
    
    session = get_session()
    
    try:
        stats = restore_organization(
            session, 
            backup, 
            new_org_name=args.as_new,
            dry_run=args.dry_run
        )
        
        print("\nRestore Summary:")
        print("-" * 30)
        for key, count in stats.items():
            if count > 0:
                print(f"  {key}: {count}")
    
    finally:
        session.close()


if __name__ == '__main__':
    main()
