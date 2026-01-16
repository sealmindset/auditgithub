#!/usr/bin/env python3
"""
Migration script to:
1. Add new columns to findings table for secret validation tracking
2. Update existing unverified TruffleHog findings from critical to medium severity
3. Optionally re-validate existing secrets to check if they're still active
"""

import os
import sys
import json
import argparse
import logging
import requests
from datetime import datetime, timezone

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from sqlalchemy import text
from api.database import SessionLocal, engine
from api import models

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def add_columns_if_not_exist(engine):
    """Add new columns to findings table if they don't exist."""
    columns_to_add = [
        ("is_verified_by_scanner", "BOOLEAN DEFAULT FALSE"),
        ("is_validated_active", "BOOLEAN"),
        ("validation_message", "VARCHAR(500)"),
        ("validated_at", "TIMESTAMP")
    ]
    
    with engine.connect() as conn:
        for col_name, col_type in columns_to_add:
            try:
                # Check if column exists
                result = conn.execute(text(f"""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'findings' AND column_name = '{col_name}'
                """))
                if result.fetchone() is None:
                    logger.info(f"Adding column {col_name} to findings table...")
                    conn.execute(text(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}"))
                    conn.commit()
                    logger.info(f"Added column {col_name}")
                else:
                    logger.info(f"Column {col_name} already exists")
            except Exception as e:
                logger.error(f"Error adding column {col_name}: {e}")


def update_unverified_severity(db):
    """Update severity of unverified TruffleHog findings from critical to medium."""
    logger.info("Updating unverified TruffleHog findings from critical to medium...")
    
    # Find all TruffleHog findings that are critical but description says "Verified: False"
    # or is_verified_by_scanner is False
    result = db.execute(text("""
        UPDATE findings 
        SET severity = 'medium',
            updated_at = NOW()
        WHERE scanner_name = 'trufflehog' 
        AND severity = 'critical'
        AND (
            description LIKE '%Verified: False%'
            OR is_verified_by_scanner = FALSE
            OR is_verified_by_scanner IS NULL
        )
        RETURNING id
    """))
    
    updated_ids = result.fetchall()
    db.commit()
    
    logger.info(f"Updated {len(updated_ids)} unverified findings from critical to medium")
    return len(updated_ids)


def validate_github_token(token: str):
    """Validate a GitHub token."""
    try:
        response = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            timeout=5
        )
        if response.status_code == 200:
            user = response.json().get("login", "unknown")
            return True, f"Active token for GitHub user: {user}"
        elif response.status_code == 401:
            return False, "Invalid/expired token"
        else:
            return None, f"Unknown status: {response.status_code}"
    except Exception as e:
        return None, f"Validation error: {str(e)}"


def validate_jwt_token(token: str):
    """Basic JWT token validation."""
    import base64
    
    parts = token.split('.')
    if len(parts) != 3:
        return False, "Invalid JWT structure"
    
    try:
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        exp = payload.get('exp')
        if exp:
            if datetime.utcnow().timestamp() > exp:
                return False, f"JWT expired at {datetime.utcfromtimestamp(exp).isoformat()}"
            else:
                return None, f"JWT not expired, signature not verified"
        
        return None, "JWT structure valid, no expiration set"
    except Exception as e:
        return False, f"JWT decode error: {str(e)}"


def revalidate_existing_secrets(db, limit=100):
    """Re-validate existing secrets to check current status."""
    logger.info(f"Re-validating existing secrets (limit: {limit})...")
    
    # Get TruffleHog findings that haven't been validated recently
    findings = db.query(models.Finding).filter(
        models.Finding.scanner_name == 'trufflehog',
        models.Finding.status == 'open'
    ).order_by(models.Finding.severity.desc()).limit(limit).all()
    
    updated_count = 0
    for finding in findings:
        raw_secret = finding.code_snippet
        if not raw_secret:
            continue
        
        detector_name = finding.title.replace('Secret found: ', '').strip()
        is_valid = None
        message = None
        
        # Validate based on detector type
        if 'github' in detector_name.lower():
            is_valid, message = validate_github_token(raw_secret)
        elif 'jwt' in detector_name.lower():
            is_valid, message = validate_jwt_token(raw_secret)
        else:
            continue  # Skip unsupported types
        
        # Update finding
        finding.is_validated_active = is_valid
        finding.validation_message = message
        finding.validated_at = datetime.now(timezone.utc)
        
        # Update severity based on validation
        if is_valid is True:
            finding.severity = 'critical'
        elif is_valid is False:
            finding.severity = 'low'
        
        updated_count += 1
        logger.info(f"Validated {detector_name}: {message} -> severity: {finding.severity}")
    
    db.commit()
    logger.info(f"Re-validated {updated_count} secrets")
    return updated_count


def main():
    parser = argparse.ArgumentParser(description='Migrate and update secret findings')
    parser.add_argument('--add-columns', action='store_true', help='Add new columns to findings table')
    parser.add_argument('--update-severity', action='store_true', help='Update unverified findings to medium severity')
    parser.add_argument('--revalidate', action='store_true', help='Re-validate existing secrets')
    parser.add_argument('--revalidate-limit', type=int, default=100, help='Max secrets to re-validate')
    parser.add_argument('--all', action='store_true', help='Run all migration steps')
    
    args = parser.parse_args()
    
    if not any([args.add_columns, args.update_severity, args.revalidate, args.all]):
        parser.print_help()
        return
    
    db = SessionLocal()
    
    try:
        if args.all or args.add_columns:
            add_columns_if_not_exist(engine)
        
        if args.all or args.update_severity:
            update_unverified_severity(db)
        
        if args.all or args.revalidate:
            revalidate_existing_secrets(db, limit=args.revalidate_limit)
        
        logger.info("Migration completed successfully!")
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
