"""
Attack Paths Router - Phase 4.1

Visualizes potential attack paths based on chained findings across repositories.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel

from ..dependencies import get_tenant_db
from .. import models
from src.rbac.dependencies import require_permissions

router = APIRouter(
    prefix="/attack-paths",
    tags=["attack-paths"]
)


# =============================================================================
# Pydantic Models
# =============================================================================

class AttackNode(BaseModel):
    """A node in an attack path."""
    id: str
    label: str
    type: str  # secret, vulnerability, dependency, infrastructure
    severity: str
    repo_name: str
    details: Dict[str, Any]


class AttackEdge(BaseModel):
    """An edge connecting attack nodes."""
    source: str
    target: str
    relationship: str  # exposes, enables, chains_to


class AttackPath(BaseModel):
    """A single attack path."""
    id: str
    name: str
    risk_score: int
    nodes: List[AttackNode]
    edges: List[AttackEdge]
    description: str


class AttackPathsResponse(BaseModel):
    """Response containing attack paths."""
    total_paths: int
    high_risk_paths: int
    paths: List[AttackPath]
    mermaid_diagram: str


class RepoAttackSurface(BaseModel):
    """Attack surface for a single repository."""
    repo_id: str
    repo_name: str
    total_findings: int
    critical_count: int
    high_count: int
    active_secrets: int
    vulnerable_deps: int
    risk_score: int
    attack_vectors: List[str]


# =============================================================================
# Helper Functions
# =============================================================================

def generate_mermaid_diagram(paths: List[AttackPath]) -> str:
    """Generate a Mermaid flowchart from attack paths."""
    lines = ["flowchart TD"]
    lines.append("    %% Attack Path Visualization")
    
    node_ids = set()
    
    for path in paths[:5]:  # Limit to 5 paths for readability
        for node in path.nodes:
            if node.id not in node_ids:
                # Style based on severity
                style = ""
                if node.severity == "critical":
                    style = ":::critical"
                elif node.severity == "high":
                    style = ":::high"
                elif node.type == "secret":
                    style = ":::secret"
                
                label = node.label[:30] + "..." if len(node.label) > 30 else node.label
                lines.append(f'    {node.id}["{label}"]{style}')
                node_ids.add(node.id)
        
        for edge in path.edges:
            lines.append(f'    {edge.source} -->|{edge.relationship}| {edge.target}')
    
    # Add styles
    lines.append("")
    lines.append("    classDef critical fill:#dc2626,color:#fff")
    lines.append("    classDef high fill:#ea580c,color:#fff")
    lines.append("    classDef secret fill:#7c3aed,color:#fff")
    
    return "\n".join(lines)


def calculate_attack_surface(
    findings: List[models.Finding],
    repo: models.Repository
) -> RepoAttackSurface:
    """Calculate attack surface metrics for a repository."""
    critical = sum(1 for f in findings if f.severity == 'critical')
    high = sum(1 for f in findings if f.severity == 'high')
    
    # Count active secrets
    secret_scanners = ['trufflehog', 'gitleaks']
    secrets = [f for f in findings if (f.scanner_name or '').lower() in secret_scanners]
    active_secrets = sum(1 for s in secrets if s.is_validated_active is True)
    
    # Count vulnerable dependencies (Snyk/Dependabot findings)
    dep_scanners = ['snyk', 'dependabot', 'npm audit']
    vulnerable_deps = sum(1 for f in findings if any(d in (f.scanner_name or '').lower() for d in dep_scanners))
    
    # Determine attack vectors
    vectors = []
    if active_secrets > 0:
        vectors.append("credential_exposure")
    if vulnerable_deps > 5:
        vectors.append("supply_chain")
    if critical > 3:
        vectors.append("critical_vulnerabilities")
    if repo.visibility == 'public':
        vectors.append("public_exposure")
    
    # Calculate risk score
    risk_score = min(100, (
        critical * 15 +
        high * 8 +
        active_secrets * 25 +
        vulnerable_deps * 3 +
        (20 if repo.visibility == 'public' else 0)
    ))
    
    return RepoAttackSurface(
        repo_id=str(repo.id),
        repo_name=repo.name,
        total_findings=len(findings),
        critical_count=critical,
        high_count=high,
        active_secrets=active_secrets,
        vulnerable_deps=vulnerable_deps,
        risk_score=risk_score,
        attack_vectors=vectors
    )


def build_attack_paths(
    repos_data: List[Dict],
    db: Session
) -> List[AttackPath]:
    """Build attack paths from repository data."""
    paths = []
    path_count = 0
    
    for repo_data in sorted(repos_data, key=lambda x: x['risk_score'], reverse=True)[:10]:
        repo = repo_data['repo']
        findings = repo_data['findings']
        
        # Skip repos with low risk
        if repo_data['risk_score'] < 20:
            continue
        
        path_count += 1
        nodes = []
        edges = []
        
        # Entry point node (the repo itself)
        repo_node_id = f"repo_{repo.id}"[:12]
        nodes.append(AttackNode(
            id=repo_node_id,
            label=repo.name,
            type="repository",
            severity="info",
            repo_name=repo.name,
            details={"visibility": repo.visibility, "stars": repo.stargazers_count}
        ))
        
        # Add critical/high findings as nodes
        priority_findings = [f for f in findings if f.severity in ['critical', 'high']][:5]
        
        prev_node = repo_node_id
        for i, f in enumerate(priority_findings):
            node_id = f"f_{str(f.finding_uuid)[:8]}"
            
            finding_type = "vulnerability"
            if (f.scanner_name or '').lower() in ['trufflehog', 'gitleaks']:
                finding_type = "secret"
            elif 'dependency' in (f.title or '').lower():
                finding_type = "dependency"
            
            nodes.append(AttackNode(
                id=node_id,
                label=f.title[:40] if f.title else "Unknown",
                type=finding_type,
                severity=f.severity,
                repo_name=repo.name,
                details={"scanner": f.scanner_name, "file": f.file_path}
            ))
            
            # Chain findings
            relationship = "exposes" if finding_type == "secret" else "contains"
            edges.append(AttackEdge(
                source=prev_node,
                target=node_id,
                relationship=relationship
            ))
            prev_node = node_id
        
        # Create path
        paths.append(AttackPath(
            id=f"path_{path_count}",
            name=f"Attack Vector: {repo.name}",
            risk_score=repo_data['risk_score'],
            nodes=nodes,
            edges=edges,
            description=f"Potential attack path through {repo.name} with {len(priority_findings)} high-severity findings"
        ))
    
    return paths


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/", response_model=AttackPathsResponse, dependencies=[Depends(require_permissions("findings:read"))])
def get_attack_paths(
    limit: int = Query(10, le=20),
    min_risk: int = Query(30, description="Minimum risk score to include"),
    db: Session = Depends(get_tenant_db)
):
    """
    Generate attack path visualization for high-risk repositories.
    Returns structured data and a Mermaid diagram.
    """
    # Get high-risk repos with open findings
    repos_with_findings = db.query(models.Repository).join(models.Finding).filter(
        models.Finding.status == 'open'
    ).distinct().all()
    
    repos_data = []
    for repo in repos_with_findings:
        findings = db.query(models.Finding).filter(
            models.Finding.repository_id == repo.id,
            models.Finding.status == 'open'
        ).all()
        
        surface = calculate_attack_surface(findings, repo)
        if surface.risk_score >= min_risk:
            repos_data.append({
                'repo': repo,
                'findings': findings,
                'risk_score': surface.risk_score,
                'surface': surface
            })
    
    # Build attack paths
    paths = build_attack_paths(repos_data, db)
    paths = paths[:limit]
    
    # Generate Mermaid diagram
    mermaid = generate_mermaid_diagram(paths)
    
    high_risk = sum(1 for p in paths if p.risk_score >= 70)
    
    return AttackPathsResponse(
        total_paths=len(paths),
        high_risk_paths=high_risk,
        paths=paths,
        mermaid_diagram=mermaid
    )


@router.get("/repo/{repo_id}", response_model=RepoAttackSurface, dependencies=[Depends(require_permissions("findings:read"))])
def get_repo_attack_surface(repo_id: str, db: Session = Depends(get_tenant_db)):
    """Get attack surface analysis for a specific repository."""
    import uuid
    
    try:
        repo_uuid = uuid.UUID(repo_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    
    repo = db.query(models.Repository).filter(models.Repository.id == repo_uuid).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == repo.id,
        models.Finding.status == 'open'
    ).all()
    
    return calculate_attack_surface(findings, repo)


@router.get("/summary", dependencies=[Depends(require_permissions("findings:read"))])
def get_attack_surface_summary(db: Session = Depends(get_tenant_db)):
    """Get overall attack surface summary across all repositories."""
    # Get stats
    total_repos = db.query(models.Repository).count()
    repos_with_findings = db.query(models.Repository).join(models.Finding).filter(
        models.Finding.status == 'open'
    ).distinct().count()
    
    # Get severity counts
    severity_counts = db.query(
        models.Finding.severity,
        func.count(models.Finding.id)
    ).filter(
        models.Finding.status == 'open'
    ).group_by(models.Finding.severity).all()
    
    # Get active secrets count
    active_secrets = db.query(models.Finding).filter(
        models.Finding.is_validated_active == True,
        models.Finding.status == 'open'
    ).count()
    
    # Count high-risk repos (those with critical findings)
    high_risk_repos = db.query(models.Repository).join(models.Finding).filter(
        models.Finding.severity == 'critical',
        models.Finding.status == 'open'
    ).distinct().count()
    
    return {
        "total_repositories": total_repos,
        "repos_with_open_findings": repos_with_findings,
        "high_risk_repositories": high_risk_repos,
        "active_secrets": active_secrets,
        "by_severity": {s[0]: s[1] for s in severity_counts},
        "attack_vectors": {
            "credential_exposure": active_secrets > 0,
            "supply_chain": severity_counts[0][1] > 10 if severity_counts else False,
            "public_exposure": db.query(models.Repository).filter(
                models.Repository.visibility == 'public'
            ).join(models.Finding).filter(
                models.Finding.severity == 'critical'
            ).count() > 0
        }
    }


@router.post("/generate", dependencies=[Depends(require_permissions("findings:write"))])
def generate_attack_path_report(
    repo_ids: Optional[List[str]] = None,
    db: Session = Depends(get_tenant_db)
):
    """Generate a detailed attack path report for specific repositories."""
    import uuid
    
    if repo_ids:
        repos = db.query(models.Repository).filter(
            models.Repository.id.in_([uuid.UUID(rid) for rid in repo_ids])
        ).all()
    else:
        # Get top 5 riskiest repos
        repos = db.query(models.Repository).join(models.Finding).filter(
            models.Finding.severity.in_(['critical', 'high']),
            models.Finding.status == 'open'
        ).distinct().limit(5).all()
    
    report_sections = []
    
    for repo in repos:
        findings = db.query(models.Finding).filter(
            models.Finding.repository_id == repo.id,
            models.Finding.status == 'open'
        ).order_by(
            models.Finding.severity.desc()
        ).all()
        
        surface = calculate_attack_surface(findings, repo)
        
        critical_findings = [f for f in findings if f.severity == 'critical'][:3]
        
        report_sections.append({
            "repository": repo.name,
            "risk_score": surface.risk_score,
            "attack_vectors": surface.attack_vectors,
            "summary": {
                "critical": surface.critical_count,
                "high": surface.high_count,
                "active_secrets": surface.active_secrets,
                "vulnerable_dependencies": surface.vulnerable_deps
            },
            "top_critical_findings": [
                {
                    "title": f.title,
                    "scanner": f.scanner_name,
                    "file": f.file_path
                }
                for f in critical_findings
            ]
        })
    
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "reports": report_sections
    }
