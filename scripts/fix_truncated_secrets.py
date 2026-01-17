#!/usr/bin/env python3
"""
Fix truncated secret values in the database.

This script reads the original whispers JSON files and updates the database
with the full untruncated secret values.

Per policy: Secrets should NOT be masked or truncated for security analyst validation.
"""

import json
import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, '/app/src/api')
sys.path.insert(0, '/app')

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.api import models

def get_database_url():
    """Get database URL from environment."""
    url = os.environ.get(
        'DATABASE_URL',
        'postgresql://postgres:postgres@db:5432/auditgh_kb'
    )
    # Fix postgres:// to postgresql://
    if url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    return url

def fix_truncated_secrets():
    """Fix truncated secret values in the database."""
    engine = create_engine(get_database_url())
    Session = sessionmaker(bind=engine)
    db = Session()
    
    reports_dir = Path(os.environ.get('REPORTS_DIR', '/app/vulnerability_reports'))
    
    fixed_count = 0
    
    # Get all repositories
    repos = db.query(models.Repository).all()
    
    for repo in repos:
        whispers_file = reports_dir / repo.name / f"{repo.name}_whispers.json"
        
        if not whispers_file.exists():
            continue
        
        print(f"Processing {repo.name}...")
        
        try:
            with open(whispers_file, 'r') as f:
                secrets = json.load(f)
        except Exception as e:
            print(f"  Error reading {whispers_file}: {e}")
            continue
        
        if not isinstance(secrets, list):
            continue
        
        # Build a lookup of key -> full value
        secret_lookup = {}
        for secret in secrets:
            key = secret.get('key', '')
            value = secret.get('value', '')
            if key and value:
                secret_lookup[key] = value
        
        # Find truncated findings for this repo
        findings = db.query(models.Finding).filter(
            models.Finding.repository_id == repo.id,
            models.Finding.scanner_name == 'whispers',
            models.Finding.code_snippet.like('%...')
        ).all()
        
        for finding in findings:
            if not finding.code_snippet:
                continue
            
            # Extract key from code_snippet
            lines = finding.code_snippet.split('\n')
            key = None
            for line in lines:
                if line.startswith('Key: '):
                    key = line[5:].strip()
                    break
            
            if key and key in secret_lookup:
                full_value = secret_lookup[key]
                new_snippet = f"Key: {key}\nValue: {full_value}"
                
                if finding.code_snippet != new_snippet:
                    print(f"  Fixing: {key}")
                    print(f"    Old: {finding.code_snippet}")
                    print(f"    New: {new_snippet}")
                    finding.code_snippet = new_snippet
                    fixed_count += 1
    
    if fixed_count > 0:
        db.commit()
        print(f"\nFixed {fixed_count} truncated secrets.")
    else:
        print("\nNo truncated secrets found to fix.")
    
    db.close()

if __name__ == '__main__':
    fix_truncated_secrets()
