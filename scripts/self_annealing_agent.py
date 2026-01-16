#!/usr/bin/env python3
"""
Self-Annealing Data Integrity Agent

This agent implements Design of Experiments (DOE) principles to:
1. DETECT data integrity issues across all repositories
2. DIAGNOSE root causes of missing or inconsistent data
3. REPAIR issues automatically when possible
4. REPORT on data quality metrics and trends
5. PREVENT future issues through continuous monitoring

DOE Approach:
- Systematic exploration of all data dimensions
- Statistical analysis of data completeness
- Automated hypothesis testing for root causes
- Iterative refinement of repair strategies
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from src.api.database import SessionLocal, engine
from src.api import models

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IssueType(Enum):
    """Types of data integrity issues."""
    MISSING_CONTRIBUTORS = "missing_contributors"
    MISSING_LANGUAGES = "missing_languages"
    MISSING_SBOM = "missing_sbom"
    MISSING_FINDINGS = "missing_findings"
    STALE_DATA = "stale_data"
    ORPHANED_RECORDS = "orphaned_records"
    INCORRECT_FINDING_TYPE = "incorrect_finding_type"
    MISSING_SCAN_RUN = "missing_scan_run"


class IssueSeverity(Enum):
    """Severity levels for issues."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DataIssue:
    """Represents a detected data integrity issue."""
    issue_type: IssueType
    severity: IssueSeverity
    repository_id: str
    repository_name: str
    organization_name: str
    description: str
    source_file: Optional[str] = None
    expected_count: int = 0
    actual_count: int = 0
    can_auto_repair: bool = False
    repair_action: Optional[str] = None


@dataclass
class RepairResult:
    """Result of a repair operation."""
    issue: DataIssue
    success: bool
    records_affected: int = 0
    error_message: Optional[str] = None


@dataclass
class AnnealingReport:
    """Comprehensive report from the self-annealing process."""
    timestamp: datetime
    total_repositories: int = 0
    repositories_scanned: int = 0
    issues_detected: List[DataIssue] = field(default_factory=list)
    issues_repaired: List[RepairResult] = field(default_factory=list)
    issues_failed: List[RepairResult] = field(default_factory=list)
    data_quality_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class SelfAnnealingAgent:
    """
    AI Agent for detecting and resolving data integrity issues.
    
    Implements DOE (Design of Experiments) methodology:
    1. Factor Identification: Identify all data dimensions
    2. Level Setting: Define expected vs actual states
    3. Experimental Design: Systematic scanning approach
    4. Analysis: Statistical evaluation of data quality
    5. Optimization: Iterative improvement of data integrity
    """
    
    def __init__(self, report_dir: str = "vulnerability_reports", dry_run: bool = False):
        self.report_dir = Path(report_dir)
        self.dry_run = dry_run
        self.db = SessionLocal()
        self.report = AnnealingReport(timestamp=datetime.now(timezone.utc))
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.db.close()
        
    def run(self) -> AnnealingReport:
        """Execute the full self-annealing process."""
        logger.info("=" * 60)
        logger.info("SELF-ANNEALING DATA INTEGRITY AGENT")
        logger.info("=" * 60)
        
        # Phase 1: Detection
        logger.info("\n[Phase 1] DETECTION - Scanning for data integrity issues...")
        self._detect_all_issues()
        
        # Phase 2: Diagnosis
        logger.info(f"\n[Phase 2] DIAGNOSIS - Analyzing {len(self.report.issues_detected)} issues...")
        self._diagnose_issues()
        
        # Phase 3: Repair
        if not self.dry_run:
            logger.info("\n[Phase 3] REPAIR - Fixing auto-repairable issues...")
            self._repair_issues()
        else:
            logger.info("\n[Phase 3] REPAIR - Skipped (dry-run mode)")
        
        # Phase 4: Report
        logger.info("\n[Phase 4] REPORT - Generating quality metrics...")
        self._generate_report()
        
        return self.report
    
    def _detect_all_issues(self):
        """Detect all types of data integrity issues."""
        # Get all repositories
        repos = self.db.query(models.Repository).all()
        self.report.total_repositories = len(repos)
        
        for repo in repos:
            self.report.repositories_scanned += 1
            org_name = "unknown"
            if repo.organization_id:
                org = self.db.query(models.Organization).filter(
                    models.Organization.id == repo.organization_id
                ).first()
                if org:
                    org_name = org.name
            
            # Check each data dimension
            self._check_contributors(repo, org_name)
            self._check_languages(repo, org_name)
            self._check_sbom(repo, org_name)
            self._check_findings(repo, org_name)
            self._check_finding_types(repo, org_name)
    
    def _check_contributors(self, repo: models.Repository, org_name: str):
        """Check for missing contributor data."""
        db_count = self.db.query(models.Contributor).filter(
            models.Contributor.repository_id == repo.id
        ).count()
        
        # Check if intel file exists with contributor data
        intel_path = self.report_dir / repo.name / f"{repo.name}_intel.json"
        file_count = 0
        if intel_path.exists():
            try:
                with open(intel_path) as f:
                    data = json.load(f)
                    file_count = len(data.get('contributors', {}).get('top_contributors', []))
            except (json.JSONDecodeError, Exception):
                pass
        
        if file_count > 0 and db_count == 0:
            self.report.issues_detected.append(DataIssue(
                issue_type=IssueType.MISSING_CONTRIBUTORS,
                severity=IssueSeverity.MEDIUM,
                repository_id=str(repo.id),
                repository_name=repo.name,
                organization_name=org_name,
                description=f"Contributors exist in intel file ({file_count}) but not in database",
                source_file=str(intel_path),
                expected_count=file_count,
                actual_count=db_count,
                can_auto_repair=True,
                repair_action="ingest_contributors"
            ))
    
    def _check_languages(self, repo: models.Repository, org_name: str):
        """Check for missing language data."""
        db_count = self.db.query(models.LanguageStat).filter(
            models.LanguageStat.repository_id == repo.id
        ).count()
        
        intel_path = self.report_dir / repo.name / f"{repo.name}_intel.json"
        file_count = 0
        if intel_path.exists():
            try:
                with open(intel_path) as f:
                    data = json.load(f)
                    file_count = len(data.get('languages', {}))
            except (json.JSONDecodeError, Exception):
                pass
        
        if file_count > 0 and db_count == 0:
            self.report.issues_detected.append(DataIssue(
                issue_type=IssueType.MISSING_LANGUAGES,
                severity=IssueSeverity.LOW,
                repository_id=str(repo.id),
                repository_name=repo.name,
                organization_name=org_name,
                description=f"Languages exist in intel file ({file_count}) but not in database",
                source_file=str(intel_path),
                expected_count=file_count,
                actual_count=db_count,
                can_auto_repair=True,
                repair_action="ingest_languages"
            ))
    
    def _check_sbom(self, repo: models.Repository, org_name: str):
        """Check for missing SBOM/dependency data."""
        db_count = self.db.query(models.Dependency).filter(
            models.Dependency.repository_id == repo.id
        ).count()
        
        syft_path = self.report_dir / repo.name / f"{repo.name}_syft_repo.json"
        file_count = 0
        if syft_path.exists():
            try:
                with open(syft_path) as f:
                    data = json.load(f)
                    file_count = len(data.get('artifacts', []) or data.get('components', []))
            except (json.JSONDecodeError, Exception):
                pass
        
        if file_count > 0 and db_count == 0:
            self.report.issues_detected.append(DataIssue(
                issue_type=IssueType.MISSING_SBOM,
                severity=IssueSeverity.MEDIUM,
                repository_id=str(repo.id),
                repository_name=repo.name,
                organization_name=org_name,
                description=f"SBOM exists in syft file ({file_count} deps) but not in database",
                source_file=str(syft_path),
                expected_count=file_count,
                actual_count=db_count,
                can_auto_repair=True,
                repair_action="ingest_sbom"
            ))
    
    def _check_findings(self, repo: models.Repository, org_name: str):
        """Check for missing findings data."""
        db_count = self.db.query(models.Finding).filter(
            models.Finding.repository_id == repo.id
        ).count()
        
        # Check multiple scanner files
        scanners = [
            ('semgrep', f"{repo.name}_semgrep.json", 'results'),
            ('horusec', f"{repo.name}_horusec.json", 'analysisVulnerabilities'),
            ('trufflehog', f"{repo.name}_trufflehog.json", None),  # List format
            ('grype', f"{repo.name}_grype_repo.json", 'matches'),
        ]
        
        total_file_count = 0
        for scanner, filename, key in scanners:
            file_path = self.report_dir / repo.name / filename
            if file_path.exists():
                try:
                    with open(file_path) as f:
                        data = json.load(f)
                        if key:
                            total_file_count += len(data.get(key, []))
                        elif isinstance(data, list):
                            total_file_count += len(data)
                except (json.JSONDecodeError, Exception):
                    pass
        
        # Only flag if we have significant findings in files but none in DB
        if total_file_count > 10 and db_count == 0:
            self.report.issues_detected.append(DataIssue(
                issue_type=IssueType.MISSING_FINDINGS,
                severity=IssueSeverity.HIGH,
                repository_id=str(repo.id),
                repository_name=repo.name,
                organization_name=org_name,
                description=f"Findings exist in scanner files (~{total_file_count}) but not in database",
                expected_count=total_file_count,
                actual_count=db_count,
                can_auto_repair=True,
                repair_action="reingest_repo"
            ))
    
    def _check_finding_types(self, repo: models.Repository, org_name: str):
        """Check for incorrect finding type classifications."""
        # Check for horusec findings incorrectly typed as 'vulnerability'
        bad_horusec = self.db.query(models.Finding).filter(
            models.Finding.repository_id == repo.id,
            models.Finding.scanner_name == 'horusec',
            models.Finding.finding_type == 'vulnerability'
        ).count()
        
        if bad_horusec > 0:
            self.report.issues_detected.append(DataIssue(
                issue_type=IssueType.INCORRECT_FINDING_TYPE,
                severity=IssueSeverity.MEDIUM,
                repository_id=str(repo.id),
                repository_name=repo.name,
                organization_name=org_name,
                description=f"Horusec findings incorrectly typed as 'vulnerability' instead of 'sast'",
                expected_count=0,
                actual_count=bad_horusec,
                can_auto_repair=True,
                repair_action="fix_horusec_type"
            ))
    
    def _diagnose_issues(self):
        """Analyze and categorize detected issues."""
        # Group issues by type
        by_type = {}
        for issue in self.report.issues_detected:
            key = issue.issue_type.value
            if key not in by_type:
                by_type[key] = []
            by_type[key].append(issue)
        
        logger.info("\nIssue Summary:")
        for issue_type, issues in sorted(by_type.items()):
            logger.info(f"  {issue_type}: {len(issues)} repositories affected")
        
        # Generate recommendations
        if by_type.get('missing_contributors'):
            self.report.recommendations.append(
                "Run contributor ingestion for affected repositories"
            )
        if by_type.get('missing_languages'):
            self.report.recommendations.append(
                "Run language stats ingestion for affected repositories"
            )
        if by_type.get('missing_sbom'):
            self.report.recommendations.append(
                "Run SBOM ingestion for affected repositories"
            )
        if by_type.get('incorrect_finding_type'):
            self.report.recommendations.append(
                "Update finding_type for horusec findings from 'vulnerability' to 'sast'"
            )
    
    def _repair_issues(self):
        """Attempt to repair auto-repairable issues."""
        from ingest_scans import ingest_contributors, ingest_languages, ingest_sbom
        
        repairable = [i for i in self.report.issues_detected if i.can_auto_repair]
        logger.info(f"Attempting to repair {len(repairable)} issues...")
        
        for issue in repairable:
            try:
                result = self._repair_single_issue(issue)
                if result.success:
                    self.report.issues_repaired.append(result)
                    logger.info(f"  ✓ Repaired: {issue.repository_name} - {issue.issue_type.value}")
                else:
                    self.report.issues_failed.append(result)
                    logger.warning(f"  ✗ Failed: {issue.repository_name} - {result.error_message}")
            except Exception as e:
                self.report.issues_failed.append(RepairResult(
                    issue=issue,
                    success=False,
                    error_message=str(e)
                ))
                logger.error(f"  ✗ Error: {issue.repository_name} - {e}")
    
    def _repair_single_issue(self, issue: DataIssue) -> RepairResult:
        """Repair a single issue."""
        from ingest_scans import ingest_contributors, ingest_languages, ingest_sbom
        
        repo = self.db.query(models.Repository).filter(
            models.Repository.id == issue.repository_id
        ).first()
        
        if not repo:
            return RepairResult(issue=issue, success=False, error_message="Repository not found")
        
        report_path = self.report_dir / repo.name / "dummy"
        
        if issue.repair_action == "ingest_contributors":
            count = ingest_contributors(self.db, repo, report_path)
            self.db.commit()
            return RepairResult(issue=issue, success=True, records_affected=count)
        
        elif issue.repair_action == "ingest_languages":
            count = ingest_languages(self.db, repo, report_path)
            self.db.commit()
            return RepairResult(issue=issue, success=True, records_affected=count)
        
        elif issue.repair_action == "ingest_sbom":
            count = ingest_sbom(self.db, repo, report_path)
            self.db.commit()
            return RepairResult(issue=issue, success=True, records_affected=count)
        
        elif issue.repair_action == "fix_horusec_type":
            result = self.db.execute(text("""
                UPDATE findings 
                SET finding_type = 'sast' 
                WHERE repository_id = :repo_id 
                  AND scanner_name = 'horusec' 
                  AND finding_type = 'vulnerability'
            """), {"repo_id": issue.repository_id})
            self.db.commit()
            return RepairResult(issue=issue, success=True, records_affected=result.rowcount)
        
        elif issue.repair_action == "reingest_repo":
            # Full re-ingestion requires calling the ingest_single_repo function
            # This is a heavier operation, so we log it as needing manual intervention
            logger.warning(f"  → Repository {repo.name} needs full re-ingestion. Run:")
            logger.warning(f"    python ingest_scans.py --repo-name {repo.name} --repo-dir vulnerability_reports/{repo.name}")
            return RepairResult(
                issue=issue, 
                success=False, 
                error_message="Full re-ingestion required - run manually"
            )
        
        return RepairResult(issue=issue, success=False, error_message="Unknown repair action")
    
    def _generate_report(self):
        """Generate final quality metrics and report."""
        # Calculate data quality score
        total_checks = self.report.repositories_scanned * 4  # 4 data dimensions
        issues_count = len(self.report.issues_detected)
        repaired_count = len(self.report.issues_repaired)
        
        if total_checks > 0:
            # Score = (total - issues + repaired) / total * 100
            self.report.data_quality_score = (
                (total_checks - issues_count + repaired_count) / total_checks * 100
            )
        
        logger.info("\n" + "=" * 60)
        logger.info("SELF-ANNEALING REPORT")
        logger.info("=" * 60)
        logger.info(f"Timestamp: {self.report.timestamp}")
        logger.info(f"Repositories Scanned: {self.report.repositories_scanned}")
        logger.info(f"Issues Detected: {len(self.report.issues_detected)}")
        logger.info(f"Issues Repaired: {len(self.report.issues_repaired)}")
        logger.info(f"Issues Failed: {len(self.report.issues_failed)}")
        logger.info(f"Data Quality Score: {self.report.data_quality_score:.1f}%")
        
        if self.report.recommendations:
            logger.info("\nRecommendations:")
            for rec in self.report.recommendations:
                logger.info(f"  • {rec}")
        
        # Save report to file
        report_file = Path("logs") / f"annealing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file.parent.mkdir(exist_ok=True)
        
        report_data = {
            "timestamp": self.report.timestamp.isoformat(),
            "repositories_scanned": self.report.repositories_scanned,
            "data_quality_score": self.report.data_quality_score,
            "issues_detected": len(self.report.issues_detected),
            "issues_repaired": len(self.report.issues_repaired),
            "issues_failed": len(self.report.issues_failed),
            "issues": [
                {
                    "type": i.issue_type.value,
                    "severity": i.severity.value,
                    "repository": i.repository_name,
                    "organization": i.organization_name,
                    "description": i.description,
                    "can_auto_repair": i.can_auto_repair
                }
                for i in self.report.issues_detected
            ],
            "recommendations": self.report.recommendations
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"\nReport saved to: {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Self-Annealing Data Integrity Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Detect issues only (dry run)
  python self_annealing_agent.py --dry-run
  
  # Detect and repair issues
  python self_annealing_agent.py
  
  # Custom report directory
  python self_annealing_agent.py --report-dir /path/to/reports
        """
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true",
        help="Detect issues without repairing them"
    )
    parser.add_argument(
        "--report-dir",
        default="vulnerability_reports",
        help="Directory containing vulnerability reports"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    with SelfAnnealingAgent(report_dir=args.report_dir, dry_run=args.dry_run) as agent:
        report = agent.run()
        
        # Exit with error code if issues remain
        remaining_issues = len(report.issues_detected) - len(report.issues_repaired)
        if remaining_issues > 0 and not args.dry_run:
            sys.exit(1)


if __name__ == "__main__":
    main()
