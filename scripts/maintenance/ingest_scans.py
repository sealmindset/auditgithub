#!/usr/bin/env python3
import os
import json
import sys
import logging
import requests
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Tuple, Optional, Dict, Any

# Add src to path to import models
# Resolve to repo root /app in Docker or ../../ from scripts/maintenance/
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(_repo_root, 'src'))
sys.path.insert(0, _repo_root)

from api.database import SessionLocal, engine, Base
from api.database_router import database_router
from api import models

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# DOE Self-Annealing: Organization Filtering for Ingestion
# =============================================================================

class IngestionOrgSelfAnnealing:
    """
    DOE Self-Annealing for Organization Filtering during Ingestion.
    
    Detects and corrects organization context issues:
    - Findings being ingested without proper org_id
    - Repo/org mismatches during ingestion
    - Missing organization_id on repositories or findings
    
    Logs all corrections for audit trail.
    """
    
    def __init__(self):
        self.corrections = []
        self.anomalies = []
        self.org_cache = {}  # Cache: github_org -> org_id
        self.logger = logging.getLogger("DOE.SelfAnnealing.Ingestion")
    
    def resolve_org_from_github_org(self, github_org: str, db: Session) -> Optional[str]:
        """Resolve organization_id from GitHub org name."""
        if not github_org:
            return None
        
        # Check cache
        if github_org in self.org_cache:
            return self.org_cache[github_org]
        
        try:
            result = db.execute(
                text("SELECT id FROM organizations WHERE github_org = :github_org"),
                {"github_org": github_org}
            )
            row = result.fetchone()
            if row:
                org_id = str(row[0])
                self.org_cache[github_org] = org_id
                return org_id
        except Exception as e:
            self.logger.debug(f"Error resolving org from github_org: {e}")
        
        return None
    
    def resolve_org_from_repo_url(self, repo_url: str, db: Session) -> Optional[str]:
        """Extract GitHub org from repo URL and resolve to org_id."""
        if not repo_url or 'github.com' not in repo_url:
            return None
        
        try:
            parts = repo_url.rstrip('/').split('/')
            if len(parts) >= 4:
                github_org = parts[-2]
                return self.resolve_org_from_github_org(github_org, db)
        except Exception as e:
            self.logger.debug(f"Error extracting org from URL: {e}")
        
        return None
    
    def validate_and_correct_org(
        self,
        current_org_id: Optional[str],
        repo_url: str,
        repo_name: str,
        db: Session
    ) -> str:
        """
        Validate and correct organization_id for ingestion.
        
        Returns the validated/corrected org_id.
        """
        # If we have an org_id, verify it's valid
        if current_org_id:
            try:
                result = db.execute(
                    text("SELECT github_org FROM organizations WHERE id = :id"),
                    {"id": current_org_id}
                )
                row = result.fetchone()
                if row:
                    # Org exists, check if it matches repo URL
                    if repo_url and 'github.com' in repo_url:
                        parts = repo_url.rstrip('/').split('/')
                        if len(parts) >= 4:
                            url_github_org = parts[-2]
                            if url_github_org.lower() != row[0].lower():
                                # Mismatch - correct it
                                correct_org_id = self.resolve_org_from_github_org(url_github_org, db)
                                if correct_org_id:
                                    self.corrections.append({
                                        "timestamp": datetime.utcnow().isoformat(),
                                        "type": "org_mismatch",
                                        "repo_name": repo_name,
                                        "original_org_id": current_org_id,
                                        "corrected_org_id": correct_org_id,
                                        "reason": f"Repo URL indicates org '{url_github_org}', not '{row[0]}'"
                                    })
                                    self.logger.warning(
                                        f"DOE Self-Annealing: Corrected org_id for '{repo_name}' "
                                        f"from '{current_org_id}' to '{correct_org_id}'"
                                    )
                                    return correct_org_id
                    return current_org_id
            except Exception as e:
                self.logger.debug(f"Error validating org_id: {e}")
        
        # No org_id - try to resolve from repo URL
        resolved_org_id = self.resolve_org_from_repo_url(repo_url, db)
        if resolved_org_id:
            self.corrections.append({
                "timestamp": datetime.utcnow().isoformat(),
                "type": "missing_org_resolved",
                "repo_name": repo_name,
                "resolved_org_id": resolved_org_id,
                "reason": "Organization resolved from repository URL"
            })
            self.logger.info(
                f"DOE Self-Annealing: Resolved org_id '{resolved_org_id}' for '{repo_name}' from URL"
            )
            return resolved_org_id
        
        # Try to get default org
        try:
            result = db.execute(text("SELECT id FROM organizations WHERE is_default = true LIMIT 1"))
            row = result.fetchone()
            if row:
                default_org_id = str(row[0])
                self.anomalies.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "type": "fallback_to_default",
                    "repo_name": repo_name,
                    "default_org_id": default_org_id,
                    "reason": "Could not determine org, using default"
                })
                self.logger.warning(
                    f"DOE Self-Annealing: Using default org for '{repo_name}' - could not determine org"
                )
                return default_org_id
        except Exception as e:
            self.logger.debug(f"Error getting default org: {e}")
        
        # No org found
        self.anomalies.append({
            "timestamp": datetime.utcnow().isoformat(),
            "type": "no_org_found",
            "repo_name": repo_name,
            "reason": "Could not resolve organization"
        })
        self.logger.error(f"DOE Self-Annealing: No org found for '{repo_name}'")
        return None
    
    def get_summary(self) -> Dict[str, Any]:
        """Return summary of corrections and anomalies."""
        return {
            "corrections": len(self.corrections),
            "anomalies": len(self.anomalies),
            "details": {
                "corrections": self.corrections,
                "anomalies": self.anomalies
            }
        }
    
    def log_summary(self):
        """Log summary at end of ingestion."""
        if self.corrections or self.anomalies:
            self.logger.info(
                f"DOE Self-Annealing Ingestion Summary: "
                f"{len(self.corrections)} corrections, {len(self.anomalies)} anomalies"
            )


# Global instance for ingestion
ingestion_org_annealing = IngestionOrgSelfAnnealing()


def sanitize_string(s: str) -> str:
    """Remove NUL (0x00) characters from strings to prevent PostgreSQL errors."""
    if s is None:
        return None
    if isinstance(s, str):
        return s.replace('\x00', '')
    return s


def safe_json_load(file_path: Path) -> Optional[Dict[str, Any]]:
    """
    DOE Self-Annealing: Safely load JSON file, handling NUL characters.
    
    This is a defense-in-depth measure for existing reports that may contain
    NUL characters from Horusec or other scanners scanning binary files.
    
    Returns: Parsed JSON data or None if parsing fails
    """
    if not file_path.exists():
        return None
    
    try:
        # First try normal read
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check for NUL characters
        if '\x00' in content:
            nul_count = content.count('\x00')
            logger.warning(
                f"DOE Self-Annealing: Found {nul_count} NUL characters in {file_path.name}, sanitizing..."
            )
            content = content.replace('\x00', '')
            
            # Write sanitized content back to file for future reads
            with open(file_path, 'w') as f:
                f.write(content)
        
        return json.loads(content)
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in {file_path.name}: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to read {file_path.name}: {e}")
        return None


# -------------------- Token Validation Functions --------------------

def validate_github_token(token: str) -> Tuple[bool, str]:
    """
    Validate a GitHub token by making a test API call.
    Returns: (is_valid, message)
    """
    try:
        response = requests.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json"
            },
            timeout=5
        )
        if response.status_code == 200:
            user = response.json().get("login", "unknown")
            return True, f"Active token for GitHub user: {user}"
        elif response.status_code == 401:
            return False, "Invalid/expired token"
        else:
            return False, f"Unknown status: {response.status_code}"
    except Exception as e:
        return None, f"Validation error: {str(e)}"


def validate_aws_key(access_key: str, secret_key: str = None) -> Tuple[bool, str]:
    """
    Validate an AWS access key. Full validation requires secret key.
    Returns: (is_valid, message)
    """
    # AWS key format validation
    if not access_key.startswith(('AKIA', 'ABIA', 'ACCA', 'AGPA', 'AIDA', 'AIPA', 'ANPA', 'ANVA', 'AROA', 'APKA', 'ASCA', 'ASIA')):
        return False, "Invalid AWS key format"
    
    if len(access_key) != 20:
        return False, "Invalid AWS key length"
    
    # Without secret key, we can only do format validation
    if not secret_key:
        return None, "Format valid, cannot verify without secret key"
    
    # With secret key, we could make an AWS STS call to validate
    # For safety, we don't do this automatically as it could trigger alerts
    return None, "AWS key format valid, active validation skipped for safety"


def validate_jwt_token(token: str) -> Tuple[bool, str]:
    """
    Basic JWT token validation (structure only, not signature).
    Returns: (is_valid, message)
    """
    import base64
    
    parts = token.split('.')
    if len(parts) != 3:
        return False, "Invalid JWT structure"
    
    try:
        # Decode header and payload (add padding)
        header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # Check expiration
        exp = payload.get('exp')
        if exp:
            from datetime import datetime
            if datetime.utcnow().timestamp() > exp:
                return False, f"JWT expired at {datetime.utcfromtimestamp(exp).isoformat()}"
            else:
                return None, f"JWT not expired (exp: {datetime.utcfromtimestamp(exp).isoformat()}), signature not verified"
        
        return None, "JWT structure valid, no expiration set, signature not verified"
    except Exception as e:
        return False, f"JWT decode error: {str(e)}"


def validate_box_secret(secret: str) -> Tuple[Optional[bool], str]:
    """
    Validate a Box API secret format.
    Box uses OAuth 2.0, so we can't validate without both client ID and secret.
    We can only do format validation.
    
    Box Client ID: 32-character alphanumeric
    Box Client Secret: 32-character alphanumeric
    Box Developer Token: longer, typically starts with specific pattern
    """
    import re
    
    # Remove any whitespace
    secret = secret.strip()
    
    # Box secrets are typically 32 characters, alphanumeric
    if len(secret) == 32 and re.match(r'^[a-zA-Z0-9]+$', secret):
        # Could be a valid Box client ID or client secret
        # We can't validate without the paired credential
        return None, "Valid Box secret format (32-char alphanumeric). Cannot validate without paired client ID/secret."
    
    # Box Developer tokens are longer
    if len(secret) > 32 and re.match(r'^[a-zA-Z0-9]+$', secret):
        return None, "Possible Box developer token. Cannot validate without API call permissions."
    
    return False, f"Invalid Box secret format (length: {len(secret)})"


def validate_slack_webhook(url: str) -> Tuple[Optional[bool], str]:
    """
    Validate a Slack webhook URL by checking its format and optionally testing it.
    """
    import re
    
    # Slack webhook URL pattern
    webhook_pattern = r'^https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+$'
    
    if not re.match(webhook_pattern, url):
        return False, "Invalid Slack webhook URL format"
    
    # We could test the webhook, but that would send a message
    # So we just validate the format
    return None, "Valid Slack webhook URL format. Not tested to avoid sending messages."


def validate_azure_secret(secret: str) -> Tuple[Optional[bool], str]:
    """
    Validate Azure secrets format.
    Azure has various secret types: storage keys, client secrets, SAS tokens, etc.
    """
    import re
    
    secret = secret.strip()
    
    # Azure Storage Account Key (base64 encoded, ~88 chars)
    if len(secret) >= 80 and secret.endswith('=='):
        return None, "Possible Azure Storage Account Key. Cannot validate without account name."
    
    # Azure Client Secret (typically 34-40 chars, alphanumeric with special chars)
    if 30 <= len(secret) <= 50 and re.match(r'^[a-zA-Z0-9~._-]+$', secret):
        return None, "Possible Azure Client Secret format. Cannot validate without tenant/client ID."
    
    # Azure SAS Token (contains sig= parameter)
    if 'sig=' in secret or 'sv=' in secret:
        return None, "Possible Azure SAS Token. Cannot validate without full URL context."
    
    return None, f"Azure secret format unclear (length: {len(secret)})"


def validate_secret(detector_name: str, raw_secret: str) -> Tuple[Optional[bool], str]:
    """
    Validate a secret based on its detector type.
    Returns: (is_valid, message)
        - is_valid: True (active), False (invalid/expired), None (couldn't determine)
    """
    detector_lower = detector_name.lower()
    
    if 'github' in detector_lower:
        return validate_github_token(raw_secret)
    elif 'jwt' in detector_lower:
        return validate_jwt_token(raw_secret)
    elif 'aws' in detector_lower:
        return validate_aws_key(raw_secret)
    elif 'box' in detector_lower:
        return validate_box_secret(raw_secret)
    elif 'slack' in detector_lower and 'webhook' in detector_lower:
        return validate_slack_webhook(raw_secret)
    elif 'azure' in detector_lower:
        return validate_azure_secret(raw_secret)
    else:
        # For other secret types, we can't validate automatically
        return None, f"No automatic validation available for {detector_name}"


# -------------------- Database Functions --------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def ingest_trufflehog(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest TruffleHog secrets findings."""
    if not report_path.exists():
        return 0

    try:
        with open(report_path, 'r') as f:
            findings = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Failed to decode JSON from {report_path}")
        return 0

    count = 0
    for f in findings:
        # TruffleHog format
        source_metadata = f.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {})
        file_path = source_metadata.get('file', 'N/A')
        line = source_metadata.get('line', 0)
        
        # Clean up file path (remove temp dir prefix if present)
        if '/tmp/' in file_path:
            parts = file_path.split('/')
            # Try to find the repo name and take everything after
            try:
                repo_idx = parts.index(repo.name)
                file_path = '/'.join(parts[repo_idx+1:])
            except ValueError:
                pass

        # Get TruffleHog's verification status
        is_verified_by_scanner = f.get('Verified', False)
        detector_name = f.get('DetectorName', 'Unknown')
        raw_secret = f.get('Raw', '')
        
        # Perform our own validation for supported secret types
        is_validated_active = None
        validation_message = None
        validated_at = None
        
        if raw_secret:
            try:
                is_validated_active, validation_message = validate_secret(detector_name, raw_secret)
                validated_at = datetime.now(timezone.utc)
                logger.info(f"Validated {detector_name} secret: {validation_message}")
            except Exception as e:
                validation_message = f"Validation error: {str(e)}"
                logger.warning(f"Failed to validate {detector_name} secret: {e}")
        
        # Determine severity based on verification and validation status
        # Priority: our validation > TruffleHog verification
        if is_validated_active is True:
            severity = 'critical'  # Confirmed active - highest priority
        elif is_validated_active is False:
            severity = 'low'  # Confirmed invalid/expired - lowest priority
        elif is_verified_by_scanner:
            severity = 'critical'  # TruffleHog says verified
        else:
            severity = 'medium'  # Unverified, couldn't validate
        
        # Build description with validation details
        description_parts = [
            f"Detector: {f.get('DetectorDescription', 'N/A')}",
            f"Scanner Verified: {is_verified_by_scanner}"
        ]
        if validation_message:
            description_parts.append(f"Validation: {validation_message}")
        
        finding = models.Finding(
            repository_id=repo.id,
            scan_run_id=scan_run.id,
            scanner_name='trufflehog',
            finding_type='secret',
            severity=severity,
            title=f"Secret found: {detector_name}",
            description=". ".join(description_parts),
            file_path=file_path,
            line_start=line,
            line_end=line,
            code_snippet=raw_secret if raw_secret else '',  # Full unredacted for security analyst validation
            status='open',
            is_verified_by_scanner=is_verified_by_scanner,
            is_validated_active=is_validated_active,
            validation_message=validation_message,
            validated_at=validated_at
        )
        db.add(finding)
        count += 1
    
    return count

def ingest_semgrep(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest Semgrep SAST findings."""
    if not report_path.exists():
        return 0

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Failed to decode JSON from {report_path}")
        return 0

    count = 0
    findings_arr = data.get('results') or []
    for result in findings_arr:
        severity_map = {
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low'
        }
        severity = severity_map.get(result.get('extra', {}).get('severity', 'INFO'), 'low')
        
        finding = models.Finding(
            repository_id=repo.id,
            scan_run_id=scan_run.id,
            scanner_name='semgrep',
            finding_type='sast',
            severity=severity,
            title=result.get('check_id', 'Unknown Issue'),
            description=result.get('extra', {}).get('message', 'No description'),
            file_path=result.get('path', 'N/A'),
            line_start=result.get('start', {}).get('line', 0),
            line_end=result.get('end', {}).get('line', 0),
            code_snippet=result.get('extra', {}).get('lines', '')[:500],
            status='open'
        )
        db.add(finding)
        count += 1
        
    return count

def ingest_terraform(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest Terraform/IaC findings (from Trivy FS)."""
    if not report_path.exists():
        return 0

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Failed to decode JSON from {report_path}")
        return 0

    count = 0
    # Trivy FS JSON structure
    if 'Results' in data:
        for result in data['Results']:
            target = result.get('Target', 'Unknown')
            for vuln in result.get('Vulnerabilities', []):
                finding = models.Finding(
                    repository_id=repo.id,
                    scan_run_id=scan_run.id,
                    scanner_name='trivy-fs',
                    finding_type='iac',
                    severity=vuln.get('Severity', 'LOW').lower(),
                    title=vuln.get('Title') or vuln.get('VulnerabilityID', 'Unknown Issue'),
                    description=vuln.get('Description', 'No description'),
                    file_path=target,
                    line_start=0, # Trivy FS might not always give line numbers in this format
                    line_end=0,
                    code_snippet=f"VulnerabilityID: {vuln.get('VulnerabilityID')}\nPkgName: {vuln.get('PkgName')}\nInstalledVersion: {vuln.get('InstalledVersion')}\nFixedVersion: {vuln.get('FixedVersion')}",
                    status='open'
                )
                db.add(finding)
                count += 1
            
            # Also check for Misconfigurations (IaC issues)
            for misconf in result.get('Misconfigurations', []):
                 finding = models.Finding(
                    repository_id=repo.id,
                    scan_run_id=scan_run.id,
                    scanner_name='trivy-fs',
                    finding_type='iac',
                    severity=misconf.get('Severity', 'LOW').lower(),
                    title=misconf.get('Title') or misconf.get('ID', 'Unknown Issue'),
                    description=misconf.get('Description', 'No description'),
                    file_path=target,
                    line_start=misconf.get('IacMetadata', {}).get('StartLine', 0),
                    line_end=misconf.get('IacMetadata', {}).get('EndLine', 0),
                    code_snippet=misconf.get('Message', ''),
                    status='open'
                )
                 db.add(finding)
                 count += 1
                 
    return count

def ingest_oss(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest OSS findings (from Grype JSON)."""
    grype_path = report_path.parent / f"{repo.name}_grype_repo.json"
    if grype_path.exists():
        return ingest_grype(db, repo, scan_run, grype_path)
    return 0

def ingest_grype(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest OSS findings from Grype JSON."""
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return 0
        
    count = 0
    matches = data.get('matches', [])
    for match in matches:
        vuln = match.get('vulnerability', {})
        artifact = match.get('artifact', {})
        
        finding = models.Finding(
            repository_id=repo.id,
            scan_run_id=scan_run.id,
            scanner_name='grype',
            finding_type='oss',
            severity=vuln.get('severity', 'Low').lower(),
            title=vuln.get('id', 'Unknown Vuln'),
            description=vuln.get('description', 'No description'),
            file_path=artifact.get('locations', [{}])[0].get('path', 'N/A'),
            line_start=0,
            line_end=0,
            code_snippet=f"Package: {artifact.get('name')} {artifact.get('version')}\nType: {artifact.get('type')}",
            status='open'
        )
        db.add(finding)
        count += 1
        
    return count

def ingest_nuclei(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest Nuclei findings."""
    if not report_path.exists():
        return 0

    try:
        with open(report_path, 'r') as f:
            # Nuclei JSON export is a list of objects
            findings = json.load(f)
    except json.JSONDecodeError:
        return 0

    count = 0
    for f in findings:
        info = f.get('info', {})
        finding = models.Finding(
            repository_id=repo.id,
            scan_run_id=scan_run.id,
            scanner_name='nuclei',
            finding_type='dast', # Dynamic/Network scan
            severity=info.get('severity', 'low').lower(),
            title=info.get('name', f.get('template-id', 'Unknown')),
            description=info.get('description', 'No description'),
            file_path=f.get('matched-at', 'N/A'),
            line_start=0,
            line_end=0,
            code_snippet=f"Template: {f.get('template-id')}\nMatcher: {f.get('matcher-name', 'N/A')}\nExtracted: {f.get('extracted-results', [])}",
            status='open'
        )
        db.add(finding)
        count += 1
    return count

def ingest_retirejs(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest Retire.js findings."""
    if not report_path.exists():
        return 0

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return 0

    count = 0
    # Retire.js JSON might be a list or a dict with 'data' key
    if isinstance(data, dict):
        data = data.get('data', [])
    
    # Ensure data is a list (could be string if error occurred)
    if not isinstance(data, list):
        return 0
        
    # Retire.js JSON is a list of file objects
    for file_obj in data:
        # Skip if file_obj is not a dict
        if not isinstance(file_obj, dict):
            continue
            
        file_path = file_obj.get('file', 'N/A')
        for result in file_obj.get('results', []):
            component = result.get('component', 'Unknown')
            version = result.get('version', 'Unknown')
            for vuln in result.get('vulnerabilities', []):
                finding = models.Finding(
                    repository_id=repo.id,
                    scan_run_id=scan_run.id,
                    scanner_name='retirejs',
                    finding_type='oss',
                    severity=vuln.get('severity', 'medium').lower(),
                    title=f"Vulnerable JS Library: {component} {version}",
                    description=f"{vuln.get('identifiers', {}).get('summary', 'No description')}\nInfo: {vuln.get('info', [])}",
                    file_path=file_path,
                    line_start=0,
                    line_end=0,
                    code_snippet=f"Component: {component}@{version}\nVuln: {vuln.get('identifiers', {})}",
                    status='open'
                )
                db.add(finding)
                count += 1
    return count

def ingest_ossgadget(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest OSSGadget findings (SARIF)."""
    if not report_path.exists():
        return 0

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return 0

    count = 0
    # Parse SARIF
    for run in data.get('runs', []):
        tool_name = run.get('tool', {}).get('driver', {}).get('name', 'ossgadget')
        for result in run.get('results', []):
            rule_id = result.get('ruleId', 'Unknown')
            message = result.get('message', {}).get('text', 'No description')
            
            # Get location
            location = result.get('locations', [{}])[0].get('physicalLocation', {})
            file_path = location.get('artifactLocation', {}).get('uri', 'N/A')
            line = location.get('region', {}).get('startLine', 0)

            finding = models.Finding(
                repository_id=repo.id,
                scan_run_id=scan_run.id,
                scanner_name='ossgadget',
                finding_type='malware',
                severity='high', # Malware/Backdoors are high/critical
                title=f"Suspicious Pattern: {rule_id}",
                description=message,
                file_path=file_path,
                line_start=line,
                line_end=line,
                code_snippet=f"Rule: {rule_id}\nTool: {tool_name}",
                status='open'
            )
            db.add(finding)
            count += 1
    return count

    return count

def ingest_contributors(db: Session, repo: models.Repository, report_path: Path):
    """
    Ingest enhanced contributor data with file severities and AI analysis.

    Handles the new contributor schema including:
    - github_username
    - commit_percentage
    - files_contributed (with severity data)
    - folders_contributed
    - risk_score (calculated)
    - ai_summary (optional)
    """
    intel_path = report_path.parent / f"{repo.name}_intel.json"
    if not intel_path.exists():
        logger.warning(f"Intel report not found at {intel_path}")
        return 0

    try:
        with open(intel_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Failed to decode JSON from {intel_path}")
        return 0

    contributors_data = data.get('contributors', {}).get('top_contributors', [])

    if not contributors_data:
        logger.info(f"No contributors found for {repo.name}")
        return 0

    count = 0

    # Clear existing contributors for this repo to avoid duplicates/stale data
    db.query(models.Contributor).filter(models.Contributor.repository_id == repo.id).delete()

    for c in contributors_data:
        # Parse last_commit_at timestamp
        last_commit = None
        if c.get('last_commit_at'):
            try:
                last_commit_str = c['last_commit_at']
                # Handle ISO format with or without timezone
                if last_commit_str.endswith('Z'):
                    last_commit_str = last_commit_str.replace('Z', '+00:00')
                last_commit = datetime.fromisoformat(last_commit_str)
            except ValueError as e:
                logger.warning(f"Failed to parse timestamp {c.get('last_commit_at')}: {e}")

        contributor = models.Contributor(
            repository_id=repo.id,
            name=c.get('name', 'Unknown'),
            email=c.get('email', ''),
            github_username=c.get('github_username'),
            commits=c.get('commits', 0),
            commit_percentage=c.get('commit_percentage', 0),
            last_commit_at=last_commit,
            languages=c.get('languages', []),
            # Enhanced fields with file severity data
            files_contributed=c.get('files_contributed', []),  # [{"path": "", "severity": "", "findings_count": 0}]
            folders_contributed=c.get('folders_contributed', []),
            risk_score=c.get('risk_score', 0),
            ai_summary=c.get('ai_summary', '')
        )
        db.add(contributor)
        count += 1

    logger.info(f"Ingested {count} contributors for {repo.name}")
    return count

def ingest_languages(db: Session, repo: models.Repository, report_path: Path):
    """Ingest language stats from Repo Intel JSON."""
    intel_path = report_path.parent / f"{repo.name}_intel.json"
    if not intel_path.exists():
        logger.warning(f"Intel report not found at {intel_path}")
        return 0

    try:
        with open(intel_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Failed to decode JSON from {intel_path}")
        return 0

    languages_data = data.get('languages', {})
    logger.info(f"Found {len(languages_data)} languages for {repo.name}")
    count = 0
    
    # Clear existing language stats for this repo
    db.query(models.LanguageStat).filter(models.LanguageStat.repository_id == repo.id).delete()
    
    for lang_name, stats in languages_data.items():
        if not isinstance(stats, dict):
            continue
            
        lang_stat = models.LanguageStat(
            repository_id=repo.id,
            name=lang_name,
            files=stats.get('nFiles', 0),
            lines=stats.get('code', 0), # Using code lines as primary 'lines'
            blanks=stats.get('blank', 0),
            comments=stats.get('comment', 0)
        )
        db.add(lang_stat)
        count += 1
        
    return count

def ingest_sbom(db: Session, repo: models.Repository, report_path: Path):
    """Ingest SBOM data from Syft JSON."""
    syft_path = report_path.parent / f"{repo.name}_syft_repo.json"
    if not syft_path.exists():
        # Try image SBOM if repo SBOM doesn't exist
        syft_path = report_path.parent / f"{repo.name}_syft_image.json"
        if not syft_path.exists():
            return 0

    try:
        with open(syft_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Failed to decode JSON from {syft_path}")
        return 0

    # Check for CycloneDX format (components) or Syft format (artifacts)
    artifacts = data.get('artifacts', [])
    is_cyclonedx = False
    if not artifacts:
        artifacts = data.get('components', [])
        is_cyclonedx = True
        
    logger.info(f"Found {len(artifacts)} dependencies for {repo.name}")
    count = 0
    
    # Clear existing dependencies for this repo
    db.query(models.Dependency).filter(models.Dependency.repository_id == repo.id).delete()
    
    for art in artifacts:
        if is_cyclonedx:
            # CycloneDX mapping
            name = art.get('name', 'Unknown')
            version = art.get('version', 'Unknown')
            type_ = art.get('type', 'Unknown')
            
            # Extract package manager from properties or type
            package_manager = 'Unknown'
            properties = art.get('properties', [])
            for prop in properties:
                if prop.get('name') == 'syft:package:type':
                    package_manager = prop.get('value')
                    break
            
            # Extract licenses
            licenses = []
            for lic in art.get('licenses', []):
                if 'license' in lic:
                    licenses.append(lic['license'].get('id') or lic['license'].get('name'))
                elif 'expression' in lic:
                    licenses.append(lic['expression'])
            license_str = ", ".join(filter(None, licenses))
            
            # Extract locations (Syft puts them in properties in CycloneDX sometimes, or we might miss them)
            # Syft CycloneDX output often puts locations in properties like 'syft:location:0:path'
            locations = []
            for prop in properties:
                if prop.get('name', '').startswith('syft:location:'):
                    locations.append(prop.get('value'))
            
            source = art.get('purl') # Use PURL as source if available
            
        else:
            # Syft Native mapping
            name = art.get('name', 'Unknown')
            version = art.get('version', 'Unknown')
            type_ = art.get('type', 'Unknown')
            package_manager = art.get('foundBy', 'Unknown')
            license_str = str(art.get('licenses', []))
            locations = [loc.get('path') for loc in art.get('locations', [])]
            
            metadata = art.get('metadata', {})
            source = metadata.get('author') or metadata.get('maintainer') or metadata.get('homepage')
        
        dep = models.Dependency(
            repository_id=repo.id,
            name=name,
            version=version,
            type=type_,
            package_manager=package_manager,
            license=license_str,
            locations=locations,
            source=source
        )
        db.add(dep)
        count += 1
        
    return count

def ingest_api_audit(db: Session, repo: models.Repository, report_path: Path):
    """
    Ingest API audit data including endpoints and OpenAPI spec.
    Populates api_endpoints and openapi_specs tables.
    """
    import yaml
    
    endpoints_path = report_path.parent / f"{repo.name}_api_endpoints.json"
    openapi_yaml_path = report_path.parent / f"{repo.name}_openapi.yaml"
    openapi_json_path = report_path.parent / f"{repo.name}_openapi.json"
    
    count = 0
    
    # Clear existing API endpoints for this repo to avoid duplicates
    db.query(models.APIEndpoint).filter(models.APIEndpoint.repository_id == repo.id).delete()
    db.query(models.OpenAPISpec).filter(models.OpenAPISpec.repository_id == repo.id).delete()
    
    # Ingest API endpoints
    if endpoints_path.exists():
        try:
            with open(endpoints_path, 'r') as f:
                data = json.load(f)
            
            # Process inbound endpoints
            for ep in data.get('inbound_endpoints', []):
                api_endpoint = models.APIEndpoint(
                    repository_id=repo.id,
                    endpoint_url=ep.get('code', '')[:500],
                    http_method=ep.get('metadata', {}).get('http_method', 'ANY'),
                    direction='serves',
                    auth_method=ep.get('metadata', {}).get('auth_method'),
                    file_path=ep.get('path', ''),
                    line_number=ep.get('line', 0),
                    code_snippet=ep.get('code', '')[:500],
                    framework=ep.get('metadata', {}).get('framework'),
                    confidence='high'
                )
                db.add(api_endpoint)
                count += 1
            
            # Process outbound endpoints
            for ep in data.get('outbound_endpoints', []):
                api_endpoint = models.APIEndpoint(
                    repository_id=repo.id,
                    endpoint_url=ep.get('endpoint_path') or ep.get('code', '')[:500],
                    http_method=ep.get('metadata', {}).get('http_method', 'GET'),
                    direction='outbound',
                    auth_method=ep.get('metadata', {}).get('auth_method'),
                    file_path=ep.get('path', ''),
                    line_number=ep.get('line', 0),
                    code_snippet=ep.get('code', '')[:500],
                    framework=ep.get('metadata', {}).get('framework'),
                    confidence='high'
                )
                db.add(api_endpoint)
                count += 1
            
            logger.info(f"Ingested {count} API endpoints for {repo.name}")
        except Exception as e:
            logger.error(f"Failed to ingest API endpoints: {e}")
    
    # Ingest OpenAPI spec
    openapi_path = openapi_yaml_path if openapi_yaml_path.exists() else openapi_json_path
    if openapi_path.exists():
        try:
            with open(openapi_path, 'r') as f:
                spec_content = f.read()
            
            # Parse to get endpoint count
            if openapi_path.suffix == '.yaml':
                spec_data = yaml.safe_load(spec_content)
                spec_format = 'yaml'
            else:
                spec_data = json.loads(spec_content)
                spec_format = 'json'
            
            endpoint_count = len(spec_data.get('paths', {}))
            version = spec_data.get('openapi', '3.0.0')
            
            openapi_spec = models.OpenAPISpec(
                repository_id=repo.id,
                spec_content=spec_content,
                spec_format=spec_format,
                version=version,
                endpoint_count=endpoint_count,
                generated_at=datetime.now(timezone.utc)
            )
            db.add(openapi_spec)
            logger.info(f"Ingested OpenAPI spec for {repo.name}: {endpoint_count} paths, version {version}")
        except Exception as e:
            logger.error(f"Failed to ingest OpenAPI spec: {e}")
    
    return count

# =============================================================================
# NEW PHASE 1 SCANNER INGESTION (December 2024)
# =============================================================================

def ingest_horusec(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """
    Ingest Horusec multi-tool SAST findings.
    
    Uses safe_json_load for DOE self-annealing to handle NUL characters
    that may be present in Horusec output from scanning binary files.
    """
    if not report_path.exists():
        return 0
    
    # DOE Self-Annealing: Use safe_json_load to handle NUL characters
    data = safe_json_load(report_path)
    if data is None:
        logger.error(f"Failed to parse Horusec report: {report_path}")
        return 0
    
    count = 0
    vulns = data.get('analysisVulnerabilities', []) or []
    
    for vuln_wrapper in vulns:
        v = vuln_wrapper.get('vulnerabilities', {})
        
        severity = v.get('severity', 'INFO').upper()
        if severity == 'INFO':
            severity = 'low'
        elif severity == 'CRITICAL':
            severity = 'critical'
        elif severity == 'HIGH':
            severity = 'high'
        elif severity == 'MEDIUM':
            severity = 'medium'
        else:
            severity = 'low'
        
        # Parse Horusec details field - format: "Title\nDescription"
        details = sanitize_string(v.get('details', 'Horusec Finding'))
        details_parts = details.split('\n', 1)
        title = sanitize_string(details_parts[0].strip()[:500])
        description = sanitize_string(details_parts[1].strip() if len(details_parts) > 1 else '')
        
        # Code snippet is the evidence - sanitize to remove NUL characters
        code_snippet = sanitize_string(v.get('code', '')[:2000])
        
        finding = models.Finding(
            repository_id=repo.id,
            organization_id=repo.organization_id,
            scan_run_id=scan_run.id,
            scanner_name='horusec',
            finding_type='sast',  # Horusec is a SAST tool
            severity=severity,
            title=title,
            description=description[:2000] if description else f"Detected by {v.get('securityTool', 'Horusec')}",
            code_snippet=code_snippet,
            file_path=sanitize_string(v.get('file', '')),
            line_start=v.get('line', 0) if isinstance(v.get('line'), int) else 0,
            cwe_id=sanitize_string(v.get('securityTool', '')),
            status='open'
        )
        db.add(finding)
        count += 1
    
    db.commit()
    logger.info(f"Ingested {count} Horusec findings for {repo.name}")
    return count


def ingest_whispers(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest Whispers secret findings."""
    if not report_path.exists():
        return 0
    
    try:
        with open(report_path, 'r') as f:
            findings_data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Failed to parse Whispers report: {e}")
        return 0
    
    if not isinstance(findings_data, list):
        return 0
    
    count = 0
    for secret in findings_data:
        severity = secret.get('severity', 'Medium').lower()
        if severity not in ['critical', 'high', 'medium', 'low']:
            severity = 'medium'
        
        # Get the full secret value for security analyst validation (no masking per policy)
        secret_value = secret.get('value', '')
        
        finding = models.Finding(
            repository_id=repo.id,
            organization_id=repo.organization_id,
            scan_run_id=scan_run.id,
            scanner_name='whispers',
            finding_type='secret',
            severity=severity,
            title=f"Secret: {secret.get('key', 'Unknown Key')}",
            description=secret.get('message', 'Hardcoded secret detected'),
            code_snippet=f"Key: {secret.get('key', '')}\nValue: {secret_value}",  # Full unredacted for security analyst validation
            file_path=secret.get('file', ''),
            line_start=int(secret.get('line', 0)) if str(secret.get('line', '0')).isdigit() else 0,
            status='open'
        )
        db.add(finding)
        count += 1
    
    db.commit()
    logger.info(f"Ingested {count} Whispers findings for {repo.name}")
    return count


def ingest_bearer(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest Bearer data flow analysis findings."""
    if not report_path.exists():
        return 0
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Failed to parse Bearer report: {e}")
        return 0
    
    count = 0
    findings_data = data.get('findings') or []
    
    for finding_item in findings_data:
        severity = finding_item.get('severity', 'warning').lower()
        if severity not in ['critical', 'high', 'medium', 'low']:
            severity = 'medium'
        
        # Get data type info if available
        data_type = finding_item.get('data_type', {})
        data_type_name = data_type.get('name', '') if data_type else ''
        
        title = finding_item.get('title', 'Bearer Finding')
        if data_type_name:
            title = f"{title} ({data_type_name})"
        
        finding = models.Finding(
            repository_id=repo.id,
            organization_id=repo.organization_id,
            scan_run_id=scan_run.id,
            scanner_name='bearer',
            finding_type='data_flow',
            severity=severity,
            title=title[:500],
            description=finding_item.get('description', '')[:2000],
            file_path=finding_item.get('filename', ''),
            line_start=finding_item.get('line_number', 0),
            cwe_id=finding_item.get('cwe_ids', [''])[0] if finding_item.get('cwe_ids') else '',
            status='open'
        )
        db.add(finding)
        count += 1
    
    db.commit()
    logger.info(f"Ingested {count} Bearer findings for {repo.name}")
    return count


def ingest_terrascan(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest Terrascan IaC findings."""
    if not report_path.exists():
        return 0
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Failed to parse Terrascan report: {e}")
        return 0
    
    count = 0
    results = data.get('results') or {}
    violations = results.get('violations') or []  # Handle null violations
    
    for v in violations:
        severity = v.get('severity', 'LOW').lower()
        if severity not in ['critical', 'high', 'medium', 'low']:
            severity = 'medium'
        
        finding = models.Finding(
            repository_id=repo.id,
            organization_id=repo.organization_id,
            scan_run_id=scan_run.id,
            scanner_name='terrascan',
            finding_type='iac',
            severity=severity,
            title=v.get('rule_name', 'Terrascan Violation')[:500],
            description=v.get('description', '')[:2000],
            file_path=v.get('file', ''),
            line_start=v.get('line', 0) if isinstance(v.get('line'), int) else 0,
            status='open'
        )
        db.add(finding)
        count += 1
    
    db.commit()
    logger.info(f"Ingested {count} Terrascan findings for {repo.name}")
    return count


# =============================================================================
# PHASE 3 SCANNERS: Go Security & Mobile Security
# =============================================================================

def ingest_gosec(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest gosec Go security findings."""
    if not report_path.exists():
        return 0
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Failed to parse gosec report: {e}")
        return 0
    
    count = 0
    issues = data.get('Issues') or []
    
    for issue in issues:
        severity = issue.get('severity', 'MEDIUM').lower()
        if severity not in ['critical', 'high', 'medium', 'low']:
            severity = 'medium'
        
        # Extract CWE if available
        cwe_id = None
        cwe_data = issue.get('cwe', {})
        if cwe_data and cwe_data.get('id'):
            cwe_id = f"CWE-{cwe_data['id']}"
        
        finding = models.Finding(
            repository_id=repo.id,
            organization_id=repo.organization_id,
            scan_run_id=scan_run.id,
            scanner_name='gosec',
            finding_type='sast',
            severity=severity,
            title=f"[{issue.get('rule_id', 'G000')}] {issue.get('details', 'Go Security Issue')[:200]}",
            description=issue.get('details', '')[:2000],
            file_path=issue.get('file', ''),
            line_start=int(issue.get('line', 0)) if issue.get('line') else 0,
            code_snippet=issue.get('code', ''),  # Full unredacted for security analyst validation
            cwe_id=cwe_id,
            status='open',
            is_go_finding=True,
            gosec_rule_id=issue.get('rule_id')
        )
        db.add(finding)
        count += 1
    
    db.commit()
    logger.info(f"Ingested {count} gosec findings for {repo.name}")
    return count


def ingest_golangci(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest GolangCI-Lint findings (excluding gosec to avoid duplicates)."""
    if not report_path.exists():
        return 0
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Failed to parse GolangCI-Lint report: {e}")
        return 0
    
    count = 0
    issues = data.get('Issues', [])
    
    for issue in issues:
        # Skip gosec findings - they're already ingested by ingest_gosec
        linter = issue.get('FromLinter', '')
        if linter == 'gosec':
            continue
        
        # Map severity
        severity = 'medium' if issue.get('Severity') == 'error' else 'low'
        
        pos = issue.get('Pos', {})
        
        finding = models.Finding(
            repository_id=repo.id,
            organization_id=repo.organization_id,
            scan_run_id=scan_run.id,
            scanner_name=f'golangci-lint:{linter}',
            finding_type='sast',
            severity=severity,
            title=f"[{linter}] {issue.get('Text', 'Go Lint Issue')[:200]}",
            description=issue.get('Text', '')[:2000],
            file_path=pos.get('Filename', ''),
            line_start=pos.get('Line', 0),
            status='open',
            is_go_finding=True
        )
        db.add(finding)
        count += 1
    
    db.commit()
    logger.info(f"Ingested {count} GolangCI-Lint findings for {repo.name}")
    return count


def ingest_mobsf(db: Session, repo: models.Repository, scan_run: models.ScanRun, report_path: Path):
    """Ingest MobSF mobile security findings."""
    if not report_path.exists():
        return 0
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Failed to parse MobSF report: {e}")
        return 0
    
    count = 0
    platform = data.get('platform', 'unknown')
    findings_list = data.get('findings', [])
    
    for finding_data in findings_list:
        severity = finding_data.get('severity', 'medium').lower()
        if severity not in ['critical', 'high', 'medium', 'low']:
            severity = 'medium'
        
        category = finding_data.get('category', 'Mobile Security')
        
        finding = models.Finding(
            repository_id=repo.id,
            organization_id=repo.organization_id,
            scan_run_id=scan_run.id,
            scanner_name=f'mobsf:{platform}',
            finding_type='mobile',
            severity=severity,
            title=f"[{category}] {finding_data.get('title', 'Mobile Security Issue')[:200]}",
            description=finding_data.get('description', '')[:2000],
            file_path=finding_data.get('file', ''),
            line_start=finding_data.get('line', 0),
            status='open',
            is_mobile_finding=True
        )
        db.add(finding)
        count += 1
    
    db.commit()
    logger.info(f"Ingested {count} MobSF findings for {repo.name} ({platform})")
    return count


def ingest_single_repo(repo_name: str, repo_dir: str, tenant_slug: str = None, organization_id: str = None):
    """
    Ingest findings for a single repository.
    
    Multi-tenant: Uses organization_id to scope all data to the correct organization.
    """
    project_dir = Path(repo_dir)
    if not project_dir.exists():
        logger.error(f"Project directory {repo_dir} does not exist")
        return

    # Get database session - use tenant DB if specified, otherwise default
    if tenant_slug:
        logger.info(f"Using tenant database: {tenant_slug}")
        db = database_router.get_session(tenant_slug)
        if not db:
            logger.error(f"Could not get session for tenant: {tenant_slug}")
            logger.error("Make sure the tenant exists and is provisioned.")
            return
        # For tenant databases, use the tenant engine for table creation
        tenant_engine = database_router.get_engine(tenant_slug)
        if tenant_engine:
            Base.metadata.create_all(bind=tenant_engine)
    else:
        db = SessionLocal()
        Base.metadata.create_all(bind=engine)

    try:
        logger.info(f"Processing {repo_name} from {repo_dir}...")
        
        # Get organization ID for multi-tenant scoping
        org_id = organization_id
        if not org_id:
            # Try to get from environment or default organization
            from sqlalchemy import text
            result = db.execute(text("SELECT id FROM organizations WHERE is_default = true LIMIT 1"))
            row = result.fetchone()
            if row:
                org_id = str(row[0])
                logger.debug(f"Using default organization ID: {org_id}")
        
        github_org = os.getenv("GITHUB_ORG", "example-org")
        repo_url = f"https://github.com/{github_org}/{repo_name}"
        
        # 1. Get or Create Repository (scoped to organization)
        query = db.query(models.Repository).filter(models.Repository.name == repo_name)
        if org_id:
            query = query.filter(models.Repository.organization_id == org_id)
        repo = query.first()
        
        if not repo:
            repo = models.Repository(
                name=repo_name,
                organization_id=org_id,
                description=f"Imported from {repo_dir}",
                default_branch="main",
                url=repo_url
            )
            db.add(repo)
            db.commit()
            db.refresh(repo)
        elif not repo.url:
            # Fix missing URL for existing repos
            repo.url = repo_url
            if org_id and not repo.organization_id:
                repo.organization_id = org_id
            db.commit()
            logger.info(f"Updated missing URL for {repo_name}: {repo_url}")

        # 2. Create ScanRun (with organization scope)
        scan_run = models.ScanRun(
            repository_id=repo.id,
            organization_id=org_id,
            scan_type="mixed",
            status="completed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)
        
        # 3. Ingest Findings
        findings_count = 0
        
        # TruffleHog
        trufflehog_report = project_dir / f"{repo_name}_trufflehog.json"
        findings_count += ingest_trufflehog(db, repo, scan_run, trufflehog_report)
        
        # Semgrep
        semgrep_report = project_dir / f"{repo_name}_semgrep.json"
        findings_count += ingest_semgrep(db, repo, scan_run, semgrep_report)
        
        # Terraform/IaC (Trivy FS)
        trivy_report = project_dir / f"{repo_name}_trivy_fs.json"
        findings_count += ingest_terraform(db, repo, scan_run, trivy_report)
        
        # OSS (Grype)
        findings_count += ingest_oss(db, repo, scan_run, project_dir / "dummy")

        # Nuclei
        nuclei_report = project_dir / f"{repo_name}_nuclei.json"
        findings_count += ingest_nuclei(db, repo, scan_run, nuclei_report)

        # Retire.js
        retire_report = project_dir / f"{repo_name}_retire.json"
        findings_count += ingest_retirejs(db, repo, scan_run, retire_report)

        # OSSGadget (SARIF)
        ossgadget_report = project_dir / f"{repo_name}_ossgadget.sarif"
        findings_count += ingest_ossgadget(db, repo, scan_run, ossgadget_report)
        
        # =====================================================================
        # NEW PHASE 1 SCANNERS (December 2024)
        # =====================================================================
        
        # Horusec (multi-tool SAST)
        horusec_report = project_dir / f"{repo_name}_horusec.json"
        findings_count += ingest_horusec(db, repo, scan_run, horusec_report)
        
        # Whispers (secrets in config files)
        whispers_report = project_dir / f"{repo_name}_whispers.json"
        findings_count += ingest_whispers(db, repo, scan_run, whispers_report)
        
        # Bearer (data flow analysis)
        bearer_report = project_dir / f"{repo_name}_bearer.json"
        findings_count += ingest_bearer(db, repo, scan_run, bearer_report)
        
        # Terrascan (IaC security)
        terrascan_report = project_dir / f"{repo_name}_terrascan.json"
        findings_count += ingest_terrascan(db, repo, scan_run, terrascan_report)
        
        # =====================================================================
        # PHASE 3 SCANNERS: Go Security & Mobile Security
        # =====================================================================
        
        # gosec (Go security)
        gosec_report = project_dir / f"{repo_name}_gosec.json"
        findings_count += ingest_gosec(db, repo, scan_run, gosec_report)
        
        # GolangCI-Lint (Go linting with security)
        golangci_report = project_dir / f"{repo_name}_golangci.json"
        findings_count += ingest_golangci(db, repo, scan_run, golangci_report)
        
        # MobSF (Mobile security - Android/iOS)
        mobsf_report = project_dir / f"{repo_name}_mobsf.json"
        findings_count += ingest_mobsf(db, repo, scan_run, mobsf_report)
        
        # Contributors
        ingest_contributors(db, repo, project_dir / "dummy")
        
        # Languages
        ingest_languages(db, repo, project_dir / "dummy")

        # SBOM
        ingest_sbom(db, repo, project_dir / "dummy")

        # API Audit (endpoints + OpenAPI spec)
        ingest_api_audit(db, repo, project_dir / "dummy")

        # Update ScanRun stats
        scan_run.findings_count = findings_count
        scan_run.new_findings_count = findings_count

        # Update repository last_scanned_at timestamp
        repo.last_scanned_at = datetime.now(timezone.utc)

        db.commit()

        # VALIDATION: Update repository metadata from latest scan files
        try:
            # Import the metadata update function
            from ingest_reports import update_repository_metadata

            # Update metadata using org name and repo name
            update_repository_metadata(db, str(repo.id), github_org, repo_name)
        except Exception as e:
            logger.warning(f"Could not update repository metadata for {repo_name}: {e}")

        logger.info(f"Ingested {findings_count} findings for {repo_name}")
        
    except Exception as e:
        logger.error(f"Ingestion failed: {e}")
        db.rollback()
    finally:
        db.close()

def ingest_reports(report_dir: str = "vulnerability_reports", organization_id: str = None):
    """
    Main ingestion function.
    
    Multi-tenant: Uses organization_id to scope all data to the correct organization.
    
    Supports two directory structures:
    1. Flat: vulnerability_reports/{repo_name}/
    2. Org-based: vulnerability_reports/{org_name}/{repo_name}/
    """
    base_path = Path(report_dir)
    if not base_path.exists():
        logger.error(f"Report directory {report_dir} does not exist")
        return

    db = SessionLocal()
    try:
        # Create tables if they don't exist (just in case)
        Base.metadata.create_all(bind=engine)
        
        # Get all organizations from database for directory matching
        from sqlalchemy import text
        orgs_result = db.execute(text("SELECT id, name, github_org FROM organizations"))
        org_map = {row[1]: {'id': str(row[0]), 'github_org': row[2]} for row in orgs_result.fetchall()}
        logger.info(f"Found organizations: {list(org_map.keys())}")
        
        # Get default organization ID for fallback
        default_org_id = organization_id
        if not default_org_id:
            result = db.execute(text("SELECT id FROM organizations WHERE is_default = true LIMIT 1"))
            row = result.fetchone()
            if row:
                default_org_id = str(row[0])
                logger.debug(f"Using default organization ID: {default_org_id}")
        
        total_findings = 0
        
        # Check for org-based directory structure
        for item in base_path.iterdir():
            if not item.is_dir():
                continue
            
            # Check if this directory is an organization name
            if item.name in org_map:
                # Org-based structure: vulnerability_reports/{org_name}/{repo_name}/
                org_name = item.name
                org_info = org_map[org_name]
                org_id = org_info['id']
                github_org = org_info['github_org'] or org_name
                logger.info(f"📁 Processing organization directory: {org_name} (org_id: {org_id})")
                
                for project_dir in item.iterdir():
                    if not project_dir.is_dir():
                        continue
                    repo_name = project_dir.name
                    findings = _ingest_single_project(db, project_dir, repo_name, org_id, github_org)
                    total_findings += findings
            else:
                # Flat structure: vulnerability_reports/{repo_name}/
                # Try to determine org from repository in database
                repo_name = item.name
                project_dir = item
                
                # Check if repo exists in database to get its org
                repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
                if repo and repo.organization_id:
                    org_id = str(repo.organization_id)
                    # Get github_org from organization
                    org_result = db.execute(text("SELECT github_org, name FROM organizations WHERE id = :id"), {"id": org_id})
                    org_row = org_result.fetchone()
                    github_org = org_row[0] if org_row else repo_name
                else:
                    org_id = default_org_id
                    github_org = os.getenv("GITHUB_ORG", "example-org")
                
                findings = _ingest_single_project(db, project_dir, repo_name, org_id, github_org)
                total_findings += findings
        
        logger.info(f"Ingestion complete. Total findings: {total_findings}")
        
        # DOE Self-Annealing: Log summary of corrections
        ingestion_org_annealing.log_summary()
        
    finally:
        db.close()


def _ingest_single_project(db, project_dir: Path, repo_name: str, org_id: str, github_org: str) -> int:
    """
    Ingest a single project directory.
    
    Returns the number of findings ingested.
    """
    repo_url = f"https://github.com/{github_org}/{repo_name}"
    
    # DOE Self-Annealing: Validate and correct organization context
    validated_org_id = ingestion_org_annealing.validate_and_correct_org(
        current_org_id=org_id,
        repo_url=repo_url,
        repo_name=repo_name,
        db=db
    )
    if validated_org_id and validated_org_id != org_id:
        org_id = validated_org_id
        logger.info(f"DOE Self-Annealing: Using corrected org_id '{org_id}' for '{repo_name}'")
    
    # 1. Get or Create Repository (scoped to organization)
    query = db.query(models.Repository).filter(models.Repository.name == repo_name)
    if org_id:
        query = query.filter(models.Repository.organization_id == org_id)
    repo = query.first()
    
    if not repo:
        repo = models.Repository(
            name=repo_name,
            organization_id=org_id,
            description=f"Imported from vulnerability_reports",
            default_branch="main",
            url=repo_url
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)
    elif not repo.url:
        # Fix missing URL for existing repos
        repo.url = repo_url
        if org_id and not repo.organization_id:
            repo.organization_id = org_id
        db.commit()
        logger.info(f"Updated missing URL for {repo_name}: {repo_url}")

    # 2. Create ScanRun (with organization scope)
    scan_run = models.ScanRun(
        repository_id=repo.id,
        organization_id=org_id,
        scan_type="mixed",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    
    # 3. Ingest Findings
    findings_count = 0
    
    # TruffleHog
    trufflehog_report = project_dir / f"{repo_name}_trufflehog.json"
    findings_count += ingest_trufflehog(db, repo, scan_run, trufflehog_report)
    
    # Semgrep
    semgrep_report = project_dir / f"{repo_name}_semgrep.json"
    findings_count += ingest_semgrep(db, repo, scan_run, semgrep_report)
    
    # Terraform/IaC (Trivy FS)
    trivy_report = project_dir / f"{repo_name}_trivy_fs.json"
    findings_count += ingest_terraform(db, repo, scan_run, trivy_report)
    
    # OSS (Grype)
    findings_count += ingest_oss(db, repo, scan_run, project_dir / "dummy")

    # Nuclei
    nuclei_report = project_dir / f"{repo_name}_nuclei.json"
    findings_count += ingest_nuclei(db, repo, scan_run, nuclei_report)

    # Retire.js
    retire_report = project_dir / f"{repo_name}_retire.json"
    findings_count += ingest_retirejs(db, repo, scan_run, retire_report)

    # OSSGadget (SARIF)
    ossgadget_report = project_dir / f"{repo_name}_ossgadget.sarif"
    findings_count += ingest_ossgadget(db, repo, scan_run, ossgadget_report)
    
    # Phase 1 Scanners
    horusec_report = project_dir / f"{repo_name}_horusec.json"
    findings_count += ingest_horusec(db, repo, scan_run, horusec_report)
    
    whispers_report = project_dir / f"{repo_name}_whispers.json"
    findings_count += ingest_whispers(db, repo, scan_run, whispers_report)
    
    bearer_report = project_dir / f"{repo_name}_bearer.json"
    findings_count += ingest_bearer(db, repo, scan_run, bearer_report)
    
    terrascan_report = project_dir / f"{repo_name}_terrascan.json"
    findings_count += ingest_terrascan(db, repo, scan_run, terrascan_report)
    
    # Phase 3 Scanners
    gosec_report = project_dir / f"{repo_name}_gosec.json"
    findings_count += ingest_gosec(db, repo, scan_run, gosec_report)
    
    golangci_report = project_dir / f"{repo_name}_golangci.json"
    findings_count += ingest_golangci(db, repo, scan_run, golangci_report)
    
    mobsf_report = project_dir / f"{repo_name}_mobsf.json"
    findings_count += ingest_mobsf(db, repo, scan_run, mobsf_report)
    
    # Contributors
    ingest_contributors(db, repo, project_dir / "dummy")
    
    # Languages
    ingest_languages(db, repo, project_dir / "dummy")

    # SBOM
    ingest_sbom(db, repo, project_dir / "dummy")

    # API Audit (endpoints + OpenAPI spec)
    ingest_api_audit(db, repo, project_dir / "dummy")

    # Update ScanRun stats
    scan_run.findings_count = findings_count
    scan_run.new_findings_count = findings_count

    # Update repository last_scanned_at timestamp
    repo.last_scanned_at = datetime.now(timezone.utc)

    db.commit()

    # VALIDATION: Update repository metadata from latest scan files
    try:
        # Import the metadata update function
        from ingest_reports import update_repository_metadata

        # Update metadata using org name and repo name
        update_repository_metadata(db, str(repo.id), github_org, repo_name)
    except Exception as e:
        logger.warning(f"Could not update repository metadata for {repo_name}: {e}")

    logger.info(f"Ingested {findings_count} findings for {repo_name}")
    return findings_count


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ingest vulnerability reports into the database.")
    parser.add_argument("--report-dir", type=str, default="vulnerability_reports", help="Directory containing report subdirectories")
    parser.add_argument("--repo-name", type=str, help="Single repository name to ingest")
    parser.add_argument("--repo-dir", type=str, help="Directory for the single repository reports")
    parser.add_argument("--tenant", type=str, help="Tenant slug/ID to ingest data into (multi-tenant mode)")
    parser.add_argument("--organization-id", type=str, help="Explicit Organization ID to link findings to")
    
    args = parser.parse_args()
    
    if args.repo_name and args.repo_dir:
        ingest_single_repo(args.repo_name, args.repo_dir, args.tenant, args.organization_id)
    else:
        ingest_reports(args.report_dir)
