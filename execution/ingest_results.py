#!/usr/bin/env python3
import os
import sys
import json
import logging
import psycopg2
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_db_connection():
    """Connect to PostgreSQL database."""
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    user = os.environ.get("POSTGRES_USER", "auditgh")
    password = os.environ.get("POSTGRES_PASSWORD", "auditgh_secret")
    dbname = os.environ.get("POSTGRES_DB", "auditgh_kb")
    
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=dbname
        )
        return conn
    except Exception as e:
        logger.error(f"Could not connect to database: {e}")
        return None

def get_or_create_repo(conn, repo_name: str) -> Optional[str]:
    """Get repo ID or create if not exists."""
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM repositories WHERE name = %s", (repo_name,))
            result = cur.fetchone()
            if result:
                return result[0]
            
            # Create new
            repo_id = str(uuid.uuid4())
            cur.execute(
                "INSERT INTO repositories (id, name, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                (repo_id, repo_name)
            )
            conn.commit()
            return repo_id
    except Exception as e:
        logger.error(f"Error getting/creating repo: {e}")
        conn.rollback()
        return None

def create_scan_run(conn, repo_id: str, scan_type: str = "full") -> Optional[str]:
    """Create a new scan run record."""
    try:
        scan_id = str(uuid.uuid4())
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_runs 
                (id, repository_id, scan_type, status, started_at, created_at) 
                VALUES (%s, %s, %s, 'running', NOW(), NOW())
                """,
                (scan_id, repo_id, scan_type)
            )
        conn.commit()
        return scan_id
    except Exception as e:
        logger.error(f"Error creating scan run: {e}")
        conn.rollback()
        return None

def update_scan_run(conn, scan_id: str, status: str, findings_count: int):
    """Update scan run status and counts."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_runs 
                SET status = %s, 
                    completed_at = NOW(), 
                    findings_count = %s,
                    duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))
                WHERE id = %s
                """,
                (status, findings_count, scan_id)
            )
        conn.commit()
    except Exception as e:
        logger.error(f"Error updating scan run: {e}")
        conn.rollback()

def ingest_gitleaks(conn, scan_id: str, repo_id: str, file_path: str) -> int:
    """Ingest Gitleaks findings."""
    if not os.path.exists(file_path):
        return 0
        
    count = 0
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        with conn.cursor() as cur:
            for finding in data:
                cur.execute(
                    """
                    INSERT INTO findings 
                    (repository_id, scan_run_id, scanner_name, finding_type, severity, title, description, file_path, line_start, line_end, code_snippet, status)
                    VALUES (%s, %s, 'gitleaks', 'secret', 'critical', %s, %s, %s, %s, %s, %s, 'open')
                    """,
                    (
                        repo_id, scan_id,
                        f"Secret found: {finding.get('RuleID')}",
                        finding.get('Description', 'Potential secret detected'),
                        finding.get('File'),
                        finding.get('StartLine'),
                        finding.get('EndLine'),
                        finding.get('Secret', '')[:100] + '...' # Truncate secret for safety/storage
                    )
                )
                count += 1
        conn.commit()
    except Exception as e:
        logger.error(f"Error ingesting Gitleaks: {e}")
        conn.rollback()
    return count

def ingest_semgrep(conn, scan_id: str, repo_id: str, file_path: str) -> int:
    """Ingest Semgrep findings."""
    if not os.path.exists(file_path):
        return 0
        
    count = 0
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        results = data.get('results', [])
        with conn.cursor() as cur:
            for res in results:
                severity = res.get('extra', {}).get('severity', 'medium').lower()
                cur.execute(
                    """
                    INSERT INTO findings 
                    (repository_id, scan_run_id, scanner_name, finding_type, severity, title, description, file_path, line_start, line_end, code_snippet, status)
                    VALUES (%s, %s, 'semgrep', 'sast', %s, %s, %s, %s, %s, %s, %s, 'open')
                    """,
                    (
                        repo_id, scan_id,
                        severity,
                        res.get('check_id'),
                        res.get('extra', {}).get('message'),
                        res.get('path'),
                        res.get('start', {}).get('line'),
                        res.get('end', {}).get('line'),
                        res.get('extra', {}).get('lines')
                    )
                )
                count += 1
        conn.commit()
    except Exception as e:
        logger.error(f"Error ingesting Semgrep: {e}")
        conn.rollback()
    return count

def ingest_trivy(conn, scan_id: str, repo_id: str, file_path: str) -> int:
    """Ingest Trivy findings."""
    if not os.path.exists(file_path):
        return 0
        
    count = 0
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        results = data.get('Results', [])
        with conn.cursor() as cur:
            for res in results:
                target = res.get('Target')
                for vuln in res.get('Vulnerabilities', []):
                    severity = vuln.get('Severity', 'UNKNOWN').lower()
                    cur.execute(
                        """
                        INSERT INTO findings 
                        (repository_id, scan_run_id, scanner_name, finding_type, severity, title, description, file_path, package_name, package_version, fixed_version, cve_id, status)
                        VALUES (%s, %s, 'trivy', 'vulnerability', %s, %s, %s, %s, %s, %s, %s, %s, 'open')
                        """,
                        (
                            repo_id, scan_id,
                            severity,
                            vuln.get('Title') or vuln.get('VulnerabilityID'),
                            vuln.get('Description'),
                            target,
                            vuln.get('PkgName'),
                            vuln.get('InstalledVersion'),
                            vuln.get('FixedVersion'),
                            vuln.get('VulnerabilityID')
                        )
                    )
                    count += 1
        conn.commit()
    except Exception as e:
        logger.error(f"Error ingesting Trivy: {e}")
        conn.rollback()
    return count

def ingest_checkov(conn, scan_id: str, repo_id: str, file_path: str) -> int:
    """Ingest Checkov findings."""
    if not os.path.exists(file_path):
        return 0
        
    count = 0
    try:
        with open(file_path, 'r') as f:
            # Checkov output can be a list or dict
            content = f.read()
            if not content: return 0
            data = json.loads(content)
            
        if isinstance(data, dict):
            data = [data]
            
        with conn.cursor() as cur:
            for framework in data:
                failed_checks = framework.get('results', {}).get('failed_checks', [])
                for check in failed_checks:
                    cur.execute(
                        """
                        INSERT INTO findings 
                        (repository_id, scan_run_id, scanner_name, finding_type, severity, title, description, file_path, line_start, line_end, status)
                        VALUES (%s, %s, 'checkov', 'iac', 'medium', %s, %s, %s, %s, %s, 'open')
                        """,
                        (
                            repo_id, scan_id,
                            check.get('check_id'),
                            check.get('check_name'),
                            check.get('file_path'),
                            check.get('file_line_range', [0, 0])[0],
                            check.get('file_line_range', [0, 0])[1]
                        )
                    )
                    count += 1
        conn.commit()
    except Exception as e:
        logger.error(f"Error ingesting Checkov: {e}")
        conn.rollback()
    return count

def main():
    if len(sys.argv) < 3:
        print("Usage: ingest_results.py <repo_name> <report_dir> [scan_id]")
        sys.exit(1)
        
    repo_name = sys.argv[1]
    report_dir = sys.argv[2]
    scan_id = sys.argv[3] if len(sys.argv) > 3 else None
    
    conn = get_db_connection()
    if not conn:
        logger.error("Database connection failed")
        sys.exit(1)
        
    try:
        # 1. Get/Create Repo
        repo_id = get_or_create_repo(conn, repo_name)
        if not repo_id:
            sys.exit(1)
            
        # 2. Create Scan Run if not provided
        if not scan_id:
            scan_id = create_scan_run(conn, repo_id)
            if not scan_id:
                sys.exit(1)
            logger.info(f"Created new scan run: {scan_id}")
        
        total_findings = 0
        
        # 3. Ingest Results
        logger.info("Ingesting Gitleaks...")
        total_findings += ingest_gitleaks(conn, scan_id, repo_id, os.path.join(report_dir, f"{repo_name}_secrets.json"))
        
        logger.info("Ingesting Semgrep...")
        total_findings += ingest_semgrep(conn, scan_id, repo_id, os.path.join(report_dir, f"{repo_name}_semgrep.json"))
        
        logger.info("Ingesting Trivy...")
        total_findings += ingest_trivy(conn, scan_id, repo_id, os.path.join(report_dir, f"{repo_name}_trivy_fs.json"))
        
        logger.info("Ingesting Checkov...")
        total_findings += ingest_checkov(conn, scan_id, repo_id, os.path.join(report_dir, f"{repo_name}_checkov.json"))
        
        # 4. Update Scan Run
        update_scan_run(conn, scan_id, "completed", total_findings)
        logger.info(f"Ingestion complete. Total findings: {total_findings}")
        
    finally:
        conn.close()

if __name__ == "__main__":
    main()
