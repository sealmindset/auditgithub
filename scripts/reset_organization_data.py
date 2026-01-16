#!/usr/bin/env python3
"""
Organization Data Reset Script

Provides a safe way to completely reset an organization's data with:
1. Automatic timestamped backup before deletion
2. 30-day retention policy for backups
3. Clean slate for fresh scans

Usage:
    python scripts/reset_organization_data.py --target sleepnumberlabs
    python scripts/reset_organization_data.py --target sleepnumberlabs --force  # Skip confirmation
    python scripts/reset_organization_data.py --list-backups
    python scripts/reset_organization_data.py --restore sleepnumberlabs --backup-file <path>
    python scripts/reset_organization_data.py --cleanup-old-backups  # Remove backups older than 30 days
"""

import argparse
import os
import sys
import subprocess
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "backups/organizations"))
BACKUP_RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "30"))
# Database configuration - prefer POSTGRES_* vars, fallback to defaults
DB_NAME = os.getenv("POSTGRES_DB") or os.getenv("PGDATABASE", "auditgh_kb")
DB_USER = os.getenv("POSTGRES_USER") or os.getenv("PGUSER", "auditgh")
DB_HOST = os.getenv("POSTGRES_HOST") or os.getenv("PGHOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT") or os.getenv("PGPORT", "5432")


class OrganizationDataManager:
    """Manages organization data backup, reset, and restore operations."""
    
    def __init__(self):
        self.backup_dir = BACKUP_DIR
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
    def get_organization_info(self, org_name: str) -> Optional[Dict[str, Any]]:
        """Get organization details from database."""
        try:
            result = subprocess.run(
                [
                    "psql", "-U", DB_USER, "-d", DB_NAME, "-h", DB_HOST, "-p", DB_PORT,
                    "-t", "-A", "-F", "|",
                    "-c", f"SELECT id, name, github_org, total_repos, total_findings FROM organizations WHERE name = '{org_name}'"
                ],
                capture_output=True, text=True, check=True
            )
            
            if result.stdout.strip():
                parts = result.stdout.strip().split("|")
                return {
                    "id": parts[0],
                    "name": parts[1],
                    "github_org": parts[2],
                    "total_repos": int(parts[3]) if parts[3] else 0,
                    "total_findings": int(parts[4]) if parts[4] else 0
                }
            return None
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get organization info: {e.stderr}")
            return None
    
    def get_organization_stats(self, org_id: str) -> Dict[str, int]:
        """Get detailed stats for an organization."""
        tables = [
            ("repositories", "organization_id"),
            ("scan_runs", "organization_id"),
            ("findings", "organization_id"),
            ("contributors", "organization_id"),
            ("language_stats", "organization_id"),
            ("dependencies", "organization_id"),
            ("api_endpoints", "organization_id"),
            ("openapi_specs", "organization_id"),
            ("file_commits", "organization_id"),
            ("credential_url_test_results", "organization_id"),
            ("credential_url_test_status", "organization_id"),
        ]
        
        stats = {}
        for table, column in tables:
            try:
                result = subprocess.run(
                    [
                        "psql", "-U", DB_USER, "-d", DB_NAME, "-h", DB_HOST, "-p", DB_PORT,
                        "-t", "-A",
                        "-c", f"SELECT COUNT(*) FROM {table} WHERE {column} = '{org_id}'"
                    ],
                    capture_output=True, text=True, check=True
                )
                stats[table] = int(result.stdout.strip()) if result.stdout.strip() else 0
            except subprocess.CalledProcessError:
                stats[table] = 0
        
        return stats
    
    def create_backup(self, org_name: str, org_id: str) -> Optional[Path]:
        """
        Create a timestamped backup of organization data.
        
        Returns the path to the backup file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"{org_name}_{timestamp}.sql"
        metadata_file = self.backup_dir / f"{org_name}_{timestamp}.json"
        
        logger.info(f"Creating backup for organization '{org_name}'...")
        logger.info(f"Backup file: {backup_file}")
        
        # Get stats before backup
        stats = self.get_organization_stats(org_id)
        
        # Create SQL backup with organization-specific data
        backup_sql = self._generate_backup_sql(org_id)
        
        try:
            # Execute backup query and save to file
            result = subprocess.run(
                [
                    "psql", "-U", DB_USER, "-d", DB_NAME, "-h", DB_HOST, "-p", DB_PORT,
                    "-c", backup_sql
                ],
                capture_output=True, text=True, check=True
            )
            
            # Use pg_dump with custom query for each table
            with open(backup_file, 'w') as f:
                f.write(f"-- Organization Data Backup\n")
                f.write(f"-- Organization: {org_name}\n")
                f.write(f"-- Organization ID: {org_id}\n")
                f.write(f"-- Created: {datetime.now().isoformat()}\n")
                f.write(f"-- Retention: {BACKUP_RETENTION_DAYS} days\n")
                f.write(f"-- Delete after: {(datetime.now() + timedelta(days=BACKUP_RETENTION_DAYS)).isoformat()}\n")
                f.write(f"--\n\n")
                
                # Backup each table's data for this organization
                tables_to_backup = [
                    "repositories",
                    "scan_runs", 
                    "findings",
                    "contributors",
                    "language_stats",
                    "dependencies",
                    "api_endpoints",
                    "openapi_specs",
                    "file_commits",
                    "credential_url_test_results",
                    "credential_url_test_status",
                ]
                
                for table in tables_to_backup:
                    self._backup_table(f, table, org_id)
            
            # Save metadata
            metadata = {
                "organization_name": org_name,
                "organization_id": org_id,
                "created_at": datetime.now().isoformat(),
                "retention_days": BACKUP_RETENTION_DAYS,
                "delete_after": (datetime.now() + timedelta(days=BACKUP_RETENTION_DAYS)).isoformat(),
                "stats": stats,
                "backup_file": str(backup_file)
            }
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"✓ Backup created successfully")
            logger.info(f"  - SQL file: {backup_file}")
            logger.info(f"  - Metadata: {metadata_file}")
            logger.info(f"  - Stats: {stats}")
            
            return backup_file
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Backup failed: {e.stderr}")
            return None
    
    def _backup_table(self, file_handle, table: str, org_id: str):
        """Backup a single table's data for the organization."""
        try:
            # Get COPY command output for this table
            result = subprocess.run(
                [
                    "psql", "-U", DB_USER, "-d", DB_NAME, "-h", DB_HOST, "-p", DB_PORT,
                    "-c", f"\\COPY (SELECT * FROM {table} WHERE organization_id = '{org_id}') TO STDOUT WITH CSV HEADER"
                ],
                capture_output=True, text=True
            )
            
            if result.stdout.strip():
                file_handle.write(f"\n-- Table: {table}\n")
                file_handle.write(f"-- Rows: {len(result.stdout.strip().split(chr(10))) - 1}\n")
                file_handle.write(f"\\COPY {table} FROM STDIN WITH CSV HEADER;\n")
                file_handle.write(result.stdout)
                file_handle.write("\\.\n")
                
        except Exception as e:
            logger.warning(f"Could not backup table {table}: {e}")
    
    def _generate_backup_sql(self, org_id: str) -> str:
        """Generate SQL for backing up organization data."""
        return f"SELECT 1;"  # Placeholder - actual backup done via COPY
    
    def delete_organization_data(self, org_id: str, org_name: str) -> bool:
        """
        Delete all data for an organization.
        
        Deletes in correct order to respect foreign key constraints.
        """
        logger.info(f"Deleting data for organization '{org_name}'...")
        
        # Order matters due to foreign key constraints
        # Delete child tables first, then parent tables
        delete_order = [
            # Child tables first
            ("credential_url_test_status", "organization_id"),
            ("credential_url_test_results", "organization_id"),
            ("file_commits", "organization_id"),
            ("openapi_specs", "organization_id"),
            ("api_endpoints", "organization_id"),
            ("dependencies", "organization_id"),
            ("language_stats", "organization_id"),
            ("contributors", "organization_id"),
            ("findings", "organization_id"),
            ("scan_runs", "organization_id"),
            # Parent table last
            ("repositories", "organization_id"),
        ]
        
        total_deleted = 0
        
        for table, column in delete_order:
            try:
                result = subprocess.run(
                    [
                        "psql", "-U", DB_USER, "-d", DB_NAME, "-h", DB_HOST, "-p", DB_PORT,
                        "-t", "-A",
                        "-c", f"DELETE FROM {table} WHERE {column} = '{org_id}' RETURNING 1"
                    ],
                    capture_output=True, text=True, check=True
                )
                
                count = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
                if count > 0:
                    logger.info(f"  ✓ Deleted {count} rows from {table}")
                    total_deleted += count
                    
            except subprocess.CalledProcessError as e:
                logger.error(f"  ✗ Failed to delete from {table}: {e.stderr}")
                return False
        
        # Reset organization stats
        try:
            subprocess.run(
                [
                    "psql", "-U", DB_USER, "-d", DB_NAME, "-h", DB_HOST, "-p", DB_PORT,
                    "-c", f"""
                        UPDATE organizations 
                        SET total_repos = 0, 
                            total_findings = 0,
                            total_scans = 0,
                            last_scan_at = NULL,
                            scan_status = 'idle',
                            scan_progress = 0
                        WHERE id = '{org_id}'
                    """
                ],
                capture_output=True, text=True, check=True
            )
            logger.info(f"  ✓ Reset organization stats")
        except subprocess.CalledProcessError as e:
            logger.warning(f"  ⚠ Could not reset organization stats: {e.stderr}")
        
        logger.info(f"✓ Deleted {total_deleted} total rows for organization '{org_name}'")
        return True
    
    def list_backups(self, org_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all backups, optionally filtered by organization."""
        backups = []
        
        for metadata_file in self.backup_dir.glob("*.json"):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                if org_name and metadata.get("organization_name") != org_name:
                    continue
                
                # Check if backup file exists
                backup_file = Path(metadata.get("backup_file", ""))
                metadata["backup_exists"] = backup_file.exists()
                metadata["metadata_file"] = str(metadata_file)
                
                # Calculate age
                created_at = datetime.fromisoformat(metadata.get("created_at", datetime.now().isoformat()))
                metadata["age_days"] = (datetime.now() - created_at).days
                metadata["expired"] = metadata["age_days"] > BACKUP_RETENTION_DAYS
                
                backups.append(metadata)
                
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Could not read metadata file {metadata_file}: {e}")
        
        # Sort by creation date, newest first
        backups.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return backups
    
    def cleanup_old_backups(self, dry_run: bool = False) -> int:
        """Remove backups older than retention period."""
        backups = self.list_backups()
        deleted_count = 0
        
        for backup in backups:
            if backup.get("expired", False):
                backup_file = Path(backup.get("backup_file", ""))
                metadata_file = Path(backup.get("metadata_file", ""))
                
                if dry_run:
                    logger.info(f"Would delete: {backup_file.name} (age: {backup['age_days']} days)")
                else:
                    try:
                        if backup_file.exists():
                            backup_file.unlink()
                        if metadata_file.exists():
                            metadata_file.unlink()
                        logger.info(f"✓ Deleted expired backup: {backup_file.name}")
                        deleted_count += 1
                    except Exception as e:
                        logger.error(f"Failed to delete {backup_file}: {e}")
        
        return deleted_count
    
    def restore_backup(self, org_name: str, backup_file: Path) -> bool:
        """Restore organization data from a backup file."""
        if not backup_file.exists():
            logger.error(f"Backup file not found: {backup_file}")
            return False
        
        logger.info(f"Restoring backup for organization '{org_name}'...")
        logger.info(f"Backup file: {backup_file}")
        
        try:
            result = subprocess.run(
                [
                    "psql", "-U", DB_USER, "-d", DB_NAME, "-h", DB_HOST, "-p", DB_PORT,
                    "-f", str(backup_file)
                ],
                capture_output=True, text=True, check=True
            )
            
            logger.info(f"✓ Backup restored successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Restore failed: {e.stderr}")
            return False


def reset_organization(org_name: str, force: bool = False) -> bool:
    """
    Complete reset process for an organization:
    1. Verify organization exists
    2. Create timestamped backup
    3. Delete all organization data
    4. Clean up old backups
    """
    manager = OrganizationDataManager()
    
    # Step 1: Get organization info
    org_info = manager.get_organization_info(org_name)
    if not org_info:
        logger.error(f"Organization '{org_name}' not found in database")
        return False
    
    org_id = org_info["id"]
    
    # Step 2: Show current stats
    stats = manager.get_organization_stats(org_id)
    total_records = sum(stats.values())
    
    print(f"\n{'='*60}")
    print(f"Organization Reset: {org_name}")
    print(f"{'='*60}")
    print(f"Organization ID: {org_id}")
    print(f"GitHub Org: {org_info['github_org']}")
    print(f"\nCurrent Data:")
    for table, count in stats.items():
        if count > 0:
            print(f"  - {table}: {count:,} records")
    print(f"\nTotal records to delete: {total_records:,}")
    print(f"{'='*60}\n")
    
    if total_records == 0:
        logger.info(f"Organization '{org_name}' has no data to reset")
        return True
    
    # Step 3: Confirm unless forced
    if not force:
        print("⚠️  WARNING: This will permanently delete all data for this organization!")
        print(f"A backup will be created and retained for {BACKUP_RETENTION_DAYS} days.\n")
        confirm = input(f"Type '{org_name}' to confirm reset: ")
        if confirm != org_name:
            logger.info("Reset cancelled")
            return False
    
    # Step 4: Create backup
    backup_file = manager.create_backup(org_name, org_id)
    if not backup_file:
        logger.error("Backup failed - aborting reset")
        return False
    
    # Step 5: Delete data
    if not manager.delete_organization_data(org_id, org_name):
        logger.error("Data deletion failed")
        return False
    
    # Step 6: Clean up old backups
    logger.info("\nCleaning up expired backups...")
    deleted = manager.cleanup_old_backups()
    if deleted > 0:
        logger.info(f"Removed {deleted} expired backup(s)")
    
    print(f"\n{'='*60}")
    print(f"✓ Organization '{org_name}' has been reset successfully!")
    print(f"  Backup saved to: {backup_file}")
    print(f"  Backup will be retained for {BACKUP_RETENTION_DAYS} days")
    print(f"{'='*60}\n")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Reset organization data with automatic backup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Reset an organization (creates backup first)
  python scripts/reset_organization_data.py --target sleepnumberlabs
  
  # Reset without confirmation prompt
  python scripts/reset_organization_data.py --target sleepnumberlabs --force
  
  # List all backups
  python scripts/reset_organization_data.py --list-backups
  
  # List backups for specific organization
  python scripts/reset_organization_data.py --list-backups --target sleepnumberlabs
  
  # Restore from backup
  python scripts/reset_organization_data.py --restore sleepnumberlabs --backup-file backups/organizations/sleepnumberlabs_20231213_120000.sql
  
  # Clean up old backups (older than 30 days)
  python scripts/reset_organization_data.py --cleanup-old-backups
  
  # Preview cleanup without deleting
  python scripts/reset_organization_data.py --cleanup-old-backups --dry-run
        """
    )
    
    parser.add_argument("--target", "-t", type=str,
                       help="Target organization name to reset")
    parser.add_argument("--force", "-f", action="store_true",
                       help="Skip confirmation prompt")
    parser.add_argument("--list-backups", "-l", action="store_true",
                       help="List all backups")
    parser.add_argument("--restore", "-r", type=str, metavar="ORG_NAME",
                       help="Restore organization from backup")
    parser.add_argument("--backup-file", "-b", type=str,
                       help="Backup file to restore from")
    parser.add_argument("--cleanup-old-backups", "-c", action="store_true",
                       help="Remove backups older than retention period")
    parser.add_argument("--dry-run", action="store_true",
                       help="Preview actions without making changes")
    
    args = parser.parse_args()
    
    manager = OrganizationDataManager()
    
    # List backups
    if args.list_backups:
        backups = manager.list_backups(args.target)
        
        if not backups:
            print("No backups found")
            return
        
        print(f"\n{'='*80}")
        print(f"Organization Backups (Retention: {BACKUP_RETENTION_DAYS} days)")
        print(f"{'='*80}")
        
        for backup in backups:
            status = "⚠️ EXPIRED" if backup.get("expired") else "✓ Active"
            exists = "✓" if backup.get("backup_exists") else "✗ Missing"
            
            print(f"\n{backup.get('organization_name', 'Unknown')}")
            print(f"  Created: {backup.get('created_at', 'Unknown')}")
            print(f"  Age: {backup.get('age_days', 0)} days | Status: {status} | File: {exists}")
            print(f"  Stats: {backup.get('stats', {})}")
            print(f"  File: {backup.get('backup_file', 'Unknown')}")
        
        print(f"\n{'='*80}\n")
        return
    
    # Cleanup old backups
    if args.cleanup_old_backups:
        deleted = manager.cleanup_old_backups(dry_run=args.dry_run)
        if args.dry_run:
            print(f"\nDry run: Would delete {deleted} expired backup(s)")
        else:
            print(f"\nDeleted {deleted} expired backup(s)")
        return
    
    # Restore from backup
    if args.restore:
        if not args.backup_file:
            print("Error: --backup-file is required for restore")
            sys.exit(1)
        
        success = manager.restore_backup(args.restore, Path(args.backup_file))
        sys.exit(0 if success else 1)
    
    # Reset organization
    if args.target:
        success = reset_organization(args.target, force=args.force)
        sys.exit(0 if success else 1)
    
    # No action specified
    parser.print_help()


if __name__ == "__main__":
    main()
