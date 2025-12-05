#!/usr/bin/env python3
import os
import json
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy.orm import Session

# Add src to path to import models
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from api.database import SessionLocal, engine, Base
from api import models

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

        finding = models.Finding(
            repository_id=repo.id,
            scan_run_id=scan_run.id,
            scanner_name='trufflehog',
            finding_type='secret',
            severity='critical', # Secrets are usually critical
            title=f"Secret found: {f.get('DetectorName', 'Unknown')}",
            description=f"Detector: {f.get('DetectorDescription', 'N/A')}",
            file_path=file_path,
            line_start=line,
            line_end=line,
            code_snippet=f.get('Raw', '')[:200], # Truncate for safety
            status='open'
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
    for result in data.get('results', []):
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
        
    # Retire.js JSON is a list of file objects
    for file_obj in data:
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
    """Ingest contributor data from Repo Intel JSON."""
    intel_path = report_path.parent / f"{repo.name}_intel.json"
    if not intel_path.exists():
        return 0

    try:
        with open(intel_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return 0

    contributors_data = data.get('contributors', {}).get('top_contributors', [])
    count = 0
    
    # Clear existing contributors for this repo to avoid duplicates/stale data
    db.query(models.Contributor).filter(models.Contributor.repository_id == repo.id).delete()
    
    for c in contributors_data:
        contributor = models.Contributor(
            repository_id=repo.id,
            name=c.get('name', 'Unknown'),
            email=c.get('email', ''),
            commits=c.get('commits', 0),
            last_commit_at=datetime.fromisoformat(c.get('last_commit_at')) if c.get('last_commit_at') else None,
            languages=c.get('languages', []),
            risk_score=0 # Placeholder
        )
        db.add(contributor)
        count += 1
        
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

def ingest_single_repo(repo_name: str, repo_dir: str):
    """Ingest findings for a single repository."""
    project_dir = Path(repo_dir)
    if not project_dir.exists():
        logger.error(f"Project directory {repo_dir} does not exist")
        return

    db = SessionLocal()
    try:
        # Create tables if they don't exist
        Base.metadata.create_all(bind=engine)
        
        logger.info(f"Processing {repo_name} from {repo_dir}...")
        
        # 1. Get or Create Repository
        repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
        if not repo:
            github_org = os.getenv("GITHUB_ORG", "sealmindset")
            repo_url = f"https://github.com/{github_org}/{repo_name}"
            repo = models.Repository(
                name=repo_name,
                description=f"Imported from {repo_dir}",
                default_branch="main",
                url=repo_url
            )
            db.add(repo)
            db.commit()
            db.refresh(repo)
            db.refresh(repo)
        
        # 2. Create ScanRun
        scan_run = models.ScanRun(
            repository_id=repo.id,
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
        
        # Contributors
        ingest_contributors(db, repo, project_dir / "dummy")
        
        # Languages
        ingest_languages(db, repo, project_dir / "dummy")

        # SBOM
        ingest_sbom(db, repo, project_dir / "dummy")
        
        # Update ScanRun stats
        scan_run.findings_count = findings_count
        scan_run.new_findings_count = findings_count
        db.commit()
        
        logger.info(f"Ingested {findings_count} findings for {repo_name}")
        
    except Exception as e:
        logger.error(f"Ingestion failed: {e}")
        db.rollback()
    finally:
        db.close()

def ingest_reports(report_dir: str = "vulnerability_reports"):
    """Main ingestion function."""
    base_path = Path(report_dir)
    if not base_path.exists():
        logger.error(f"Report directory {report_dir} does not exist")
        return

    db = SessionLocal()
    try:
        # Create tables if they don't exist (just in case)
        Base.metadata.create_all(bind=engine)
        
        total_findings = 0
        
        for project_dir in base_path.iterdir():
            if not project_dir.is_dir():
                continue
                
            repo_name = project_dir.name
            logger.info(f"Processing {repo_name}...")
            
            # 1. Get or Create Repository
            repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
            if not repo:
                github_org = os.getenv("GITHUB_ORG", "sealmindset")
                repo_url = f"https://github.com/{github_org}/{repo_name}"
                repo = models.Repository(
                    name=repo_name,
                    description=f"Imported from {report_dir}",
                    default_branch="main",
                    url=repo_url
                )
                db.add(repo)
                db.commit()
                db.refresh(repo)
            
            # 2. Create ScanRun
            scan_run = models.ScanRun(
                repository_id=repo.id,
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
            # We pass the directory or a dummy path, the function handles finding the file
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
            
            # Contributors
            ingest_contributors(db, repo, project_dir / "dummy")
            
            # Languages
            ingest_languages(db, repo, project_dir / "dummy")

            # SBOM
            ingest_sbom(db, repo, project_dir / "dummy")
            
            # Update ScanRun stats
            scan_run.findings_count = findings_count
            scan_run.new_findings_count = findings_count # Simplified for now
            db.commit()
            
            total_findings += findings_count
            logger.info(f"Ingested {findings_count} findings for {repo_name}")
            
        logger.info(f"Ingestion complete. Total findings: {total_findings}")
        
    except Exception as e:
        logger.error(f"Ingestion failed: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ingest vulnerability reports into the database.")
    parser.add_argument("--report-dir", type=str, default="vulnerability_reports", help="Directory containing report subdirectories")
    parser.add_argument("--repo-name", type=str, help="Single repository name to ingest")
    parser.add_argument("--repo-dir", type=str, help="Directory for the single repository reports")
    
    args = parser.parse_args()
    
    if args.repo_name and args.repo_dir:
        ingest_single_repo(args.repo_name, args.repo_dir)
    else:
        ingest_reports(args.report_dir)
