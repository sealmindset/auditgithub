"""
AI RAG (Retrieval-Augmented Generation) Service
Retrieves and prepares context for AI conversations
"""

import logging
from typing import List, Dict, Any, Optional
from uuid import UUID
from sqlalchemy.orm import Session
from src.api.models import Repository, ScanRun, Finding
import json

logger = logging.getLogger(__name__)


class AIRAGService:
    """Service for retrieving context for AI conversations"""

    def __init__(self, db: Session):
        self.db = db

    async def gather_context(
        self,
        project_id: int,
        repository_id: UUID,
        focus: str = "security_architecture",
        max_tokens: int = 50000
    ) -> Dict[str, Any]:
        """
        Gather relevant context for AI conversation

        Args:
            project_id: Project ID
            repository_id: Repository ID
            focus: Conversation focus (e.g., "security_architecture", "zero_trust")
            max_tokens: Maximum tokens to include in context

        Returns:
            Dictionary containing organized context
        """
        context = {
            "repository": await self._get_repository_context(repository_id),
            "technical_overview": await self._get_technical_overview(project_id, repository_id),
            "scan_results": await self._get_scan_results(repository_id, limit=20),
            "vulnerabilities": await self._get_vulnerabilities(repository_id, limit=50),
            "findings": await self._get_findings(repository_id, limit=100),
            "security_metrics": await self._get_security_metrics(repository_id),
            "architecture_patterns": await self._get_architecture_patterns(repository_id),
        }

        # Add focus-specific context
        if focus == "security_architecture":
            context["zero_trust_analysis"] = await self._analyze_zero_trust(repository_id)
        elif focus == "vulnerabilities":
            context["critical_vulnerabilities"] = await self._get_critical_vulnerabilities(repository_id)

        # Calculate token usage and trim if necessary
        context = self._optimize_context(context, max_tokens)

        return context

    async def _get_repository_context(self, repository_id: UUID) -> Dict[str, Any]:
        """Get repository basic information"""
        repo = self.db.query(Repository).filter(Repository.id == repository_id).first()
        if not repo:
            return {}

        return {
            "name": repo.name,
            "full_name": repo.full_name,
            "description": repo.description,
            "language": repo.language,
            "size_kb": repo.size_kb,
            "default_branch": repo.default_branch,
            "topics": repo.topics or [],
            "created_at": repo.github_created_at.isoformat() if repo.github_created_at else None,
            "updated_at": repo.github_updated_at.isoformat() if repo.github_updated_at else None,
            "is_private": repo.is_private,
            "is_fork": repo.is_fork,
        }

    async def _get_technical_overview(self, project_id: int, repository_id: UUID) -> Optional[str]:
        """Get AI-generated technical overview from system architecture report"""
        # Get architecture report from repository
        repo = self.db.query(Repository).filter(Repository.id == repository_id).first()
        if repo and repo.architecture_report:
            return repo.architecture_report
        return None

    async def _get_scan_results(self, repository_id: UUID, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent scan results"""
        scans = (
            self.db.query(ScanRun)
            .filter(ScanRun.repository_id == repository_id)
            .order_by(ScanRun.created_at.desc())
            .limit(limit)
            .all()
        )

        results = []
        for scan in scans:
            results.append({
                "id": str(scan.id),
                "scan_type": scan.scan_type,
                "status": scan.status,
                "findings_count": scan.findings_count,
                "new_findings_count": scan.new_findings_count,
                "resolved_findings_count": scan.resolved_findings_count,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": scan.duration_seconds,
            })

        return results

    async def _get_vulnerabilities(self, repository_id: UUID, limit: int = 50) -> List[Dict[str, Any]]:
        """Get vulnerabilities found in repository (findings with CVE/CWE)"""
        vulnerabilities = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                (Finding.cve_id.isnot(None)) | (Finding.cwe_id.isnot(None))
            )
            .order_by(Finding.severity.desc(), Finding.created_at.desc())
            .limit(limit)
            .all()
        )

        results = []
        for vuln in vulnerabilities:
            results.append({
                "id": str(vuln.id),
                "title": vuln.title,
                "severity": vuln.severity,
                "cve_id": vuln.cve_id,
                "cwe_id": vuln.cwe_id,
                "description": vuln.description[:500] if vuln.description else None,  # Truncate
                "package_name": vuln.package_name,
                "package_version": vuln.package_version,
                "fixed_version": vuln.fixed_version,
            })

        return results

    async def _get_findings(self, repository_id: UUID, limit: int = 100) -> List[Dict[str, Any]]:
        """Get security findings"""
        findings = (
            self.db.query(Finding)
            .filter(Finding.repository_id == repository_id)
            .order_by(Finding.severity.desc(), Finding.created_at.desc())
            .limit(limit)
            .all()
        )

        results = []
        for finding in findings:
            results.append({
                "id": str(finding.id),
                "title": finding.title,
                "severity": finding.severity,
                "finding_type": finding.finding_type,
                "scanner_name": finding.scanner_name,
                "description": finding.description[:300] if finding.description else None,  # Truncate
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "cwe_id": finding.cwe_id,
                "cve_id": finding.cve_id,
            })

        return results

    async def _get_security_metrics(self, repository_id: UUID) -> Dict[str, Any]:
        """Calculate security metrics for the repository"""
        # Count findings by severity
        finding_counts = {}
        findings = self.db.query(Finding).filter(Finding.repository_id == repository_id).all()
        for finding in findings:
            severity = finding.severity or "unknown"
            finding_counts[severity] = finding_counts.get(severity, 0) + 1

        # Calculate security score (0-100, higher is better)
        total_critical = finding_counts.get("critical", 0)
        total_high = finding_counts.get("high", 0)
        total_medium = finding_counts.get("medium", 0)
        total_low = finding_counts.get("low", 0)

        # Simple scoring: deduct points for issues
        security_score = 100
        security_score -= total_critical * 10
        security_score -= total_high * 5
        security_score -= total_medium * 2
        security_score -= total_low * 0.5
        security_score = max(0, min(100, security_score))

        return {
            "finding_counts": finding_counts,
            "total_critical": total_critical,
            "total_high": total_high,
            "total_medium": total_medium,
            "total_low": total_low,
            "security_score": round(security_score, 1),
        }

    async def _get_architecture_patterns(self, repository_id: UUID) -> Dict[str, Any]:
        """Identify architecture patterns from scans and findings"""
        # This would analyze findings to identify common patterns
        # For now, returning placeholder structure
        return {
            "authentication": self._analyze_auth_patterns(repository_id),
            "authorization": self._analyze_authz_patterns(repository_id),
            "encryption": self._analyze_encryption_patterns(repository_id),
            "input_validation": self._analyze_input_validation(repository_id),
            "api_security": self._analyze_api_security(repository_id),
        }

    def _analyze_auth_patterns(self, repository_id: UUID) -> Dict[str, Any]:
        """Analyze authentication patterns"""
        # Look for authentication-related findings
        auth_findings = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                Finding.finding_type.in_(["authentication", "session_management"])
            )
            .all()
        )

        return {
            "findings_count": len(auth_findings),
            "has_mfa": None,  # Would need deeper analysis
            "session_management": None,
            "concerns": [f.title for f in auth_findings[:5]],
        }

    def _analyze_authz_patterns(self, repository_id: UUID) -> Dict[str, Any]:
        """Analyze authorization patterns"""
        authz_findings = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                Finding.finding_type.in_(["authorization", "access_control"])
            )
            .all()
        )

        return {
            "findings_count": len(authz_findings),
            "rbac_implemented": None,
            "concerns": [f.title for f in authz_findings[:5]],
        }

    def _analyze_encryption_patterns(self, repository_id: UUID) -> Dict[str, Any]:
        """Analyze encryption usage"""
        crypto_findings = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                Finding.finding_type.in_(["cryptography", "encryption"])
            )
            .all()
        )

        return {
            "findings_count": len(crypto_findings),
            "weak_crypto_detected": len([f for f in crypto_findings if "weak" in f.title.lower()]) > 0,
            "concerns": [f.title for f in crypto_findings[:5]],
        }

    def _analyze_input_validation(self, repository_id: UUID) -> Dict[str, Any]:
        """Analyze input validation patterns"""
        validation_findings = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                Finding.finding_type.in_(["input_validation", "injection"])
            )
            .all()
        )

        return {
            "findings_count": len(validation_findings),
            "injection_risks": len([f for f in validation_findings if "injection" in f.title.lower()]),
            "concerns": [f.title for f in validation_findings[:5]],
        }

    def _analyze_api_security(self, repository_id: UUID) -> Dict[str, Any]:
        """Analyze API security patterns"""
        api_findings = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                Finding.finding_type.in_(["api_security", "web_service"])
            )
            .all()
        )

        return {
            "findings_count": len(api_findings),
            "concerns": [f.title for f in api_findings[:5]],
        }

    async def _analyze_zero_trust(self, repository_id: UUID) -> Dict[str, Any]:
        """Analyze zero-trust architecture principles"""
        return {
            "principle_verification": {
                "always_verify": self._check_always_verify(repository_id),
                "least_privilege": self._check_least_privilege(repository_id),
                "assume_breach": self._check_assume_breach(repository_id),
            },
            "implementation_status": {
                "identity_verification": "unknown",
                "device_verification": "unknown",
                "network_segmentation": "unknown",
                "continuous_monitoring": "unknown",
            },
            "gaps": self._identify_zero_trust_gaps(repository_id),
        }

    def _check_always_verify(self, repository_id: UUID) -> Dict[str, Any]:
        """Check if 'always verify' principle is implemented"""
        # Look for authentication/authorization on all endpoints
        auth_coverage = self._estimate_auth_coverage(repository_id)

        return {
            "implemented": auth_coverage > 0.8,
            "coverage_estimate": auth_coverage,
            "concerns": []
        }

    def _check_least_privilege(self, repository_id: UUID) -> Dict[str, Any]:
        """Check if least privilege principle is implemented"""
        # Look for overly permissive access controls
        authz_findings = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                Finding.finding_type == "authorization"
            )
            .all()
        )

        return {
            "implemented": len(authz_findings) == 0,
            "concerns": [f.title for f in authz_findings[:3]]
        }

    def _check_assume_breach(self, repository_id: UUID) -> Dict[str, Any]:
        """Check if 'assume breach' principle is considered"""
        # Look for logging, monitoring, encryption in transit
        return {
            "implemented": None,  # Would need deeper analysis
            "logging_present": None,
            "encryption_in_transit": None,
            "concerns": []
        }

    def _estimate_auth_coverage(self, repository_id: UUID) -> float:
        """Estimate percentage of endpoints with authentication"""
        # This would require analyzing the codebase
        # For now, returning a placeholder
        return 0.5

    def _identify_zero_trust_gaps(self, repository_id: UUID) -> List[str]:
        """Identify gaps in zero-trust implementation"""
        gaps = []

        # Check for common gaps
        findings = self.db.query(Finding).filter(Finding.repository_id == repository_id).all()

        if any(f.finding_type and "authentication" in f.finding_type.lower() for f in findings):
            gaps.append("Authentication weaknesses detected")

        if any(f.finding_type and "authorization" in f.finding_type.lower() for f in findings):
            gaps.append("Authorization gaps detected")

        if any(f.finding_type and "encryption" in f.finding_type.lower() for f in findings):
            gaps.append("Encryption weaknesses detected")

        return gaps

    async def _get_critical_vulnerabilities(self, repository_id: UUID) -> List[Dict[str, Any]]:
        """Get critical and high severity vulnerabilities (findings with CVE/CWE)"""
        vulns = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                Finding.severity.in_(["critical", "high"]),
                (Finding.cve_id.isnot(None)) | (Finding.cwe_id.isnot(None))
            )
            .order_by(Finding.severity.desc())
            .limit(20)
            .all()
        )

        results = []
        for vuln in vulns:
            results.append({
                "id": str(vuln.id),
                "title": vuln.title,
                "severity": vuln.severity,
                "cve_id": vuln.cve_id,
                "cwe_id": vuln.cwe_id,
                "description": vuln.description,
                "package_name": vuln.package_name,
                "package_version": vuln.package_version,
                "fixed_version": vuln.fixed_version,
            })

        return results

    def _optimize_context(self, context: Dict[str, Any], max_tokens: int) -> Dict[str, Any]:
        """
        Optimize context to fit within token limit
        Prioritizes most important information
        """
        # Rough estimation: 1 token ≈ 4 characters
        context_str = json.dumps(context)
        estimated_tokens = len(context_str) / 4

        if estimated_tokens <= max_tokens:
            return context

        # If over limit, start trimming less important data
        # Keep repository, technical_overview, security_metrics always
        # Reduce scan_results, vulnerabilities, findings

        if "findings" in context:
            context["findings"] = context["findings"][:50]  # Reduce to 50

        if "scan_results" in context:
            context["scan_results"] = context["scan_results"][:10]  # Reduce to 10

        if "vulnerabilities" in context:
            context["vulnerabilities"] = context["vulnerabilities"][:30]  # Reduce to 30

        return context

    async def search_relevant_content(
        self,
        query: str,
        repository_id: UUID,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Search for relevant content based on query
        This is a simple keyword search; could be enhanced with embeddings
        """
        results = []

        # Search in findings
        findings = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                Finding.title.ilike(f"%{query}%") | Finding.description.ilike(f"%{query}%")
            )
            .limit(limit)
            .all()
        )

        for finding in findings:
            results.append({
                "type": "finding",
                "id": str(finding.id),
                "title": finding.title,
                "content": finding.description,
                "severity": finding.severity,
                "file_path": finding.file_path,
            })

        # Search in vulnerabilities (findings with CVE/CWE)
        vulns = (
            self.db.query(Finding)
            .filter(
                Finding.repository_id == repository_id,
                (Finding.cve_id.isnot(None)) | (Finding.cwe_id.isnot(None)),
                (Finding.title.ilike(f"%{query}%") | Finding.description.ilike(f"%{query}%"))
            )
            .limit(limit)
            .all()
        )

        for vuln in vulns:
            results.append({
                "type": "vulnerability",
                "id": str(vuln.id),
                "title": vuln.title,
                "content": vuln.description,
                "severity": vuln.severity,
                "cve_id": vuln.cve_id,
            })

        return results[:limit]
