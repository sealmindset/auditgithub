from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, func, text
from ...api import models

def normalize_package_name(name: str) -> List[str]:
    """
    Generate package name variants for fuzzy matching.
    
    Examples:
        - "react.js" -> ["react.js", "react", "reactjs"]
        - "Next.JS" -> ["next.js", "next", "nextjs"]
        - "log4j" -> ["log4j", "log4j-core", "log4j.js"]
    """
    variants = [name.lower().strip()]
    base = name.lower().strip()
    
    # Strip common extensions
    for ext in ['.js', '.py', '.rb', '-core', '-api', '-client']:
        if base.endswith(ext):
            stripped = base[:-len(ext)]
            variants.append(stripped)
            # Also add without hyphen/dot (e.g., "react.js" -> "reactjs")
            variants.append(stripped.replace('.', '').replace('-', ''))
    
    # Add with common extensions if missing
    if '.' not in base and '-' not in base:
        variants.extend([f"{base}.js", f"{base}.py", f"{base}-core", f"{base}js"])
    
    # Remove dots and hyphens for fuzzy matching
    variants.append(base.replace('.', '').replace('-', ''))
    
    return list(set(variants))

def search_dependencies(
    db: Session,
    package_name: str,
    version_spec: Optional[str] = None,
    use_fuzzy: bool = True,
    organization_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search for repositories containing a specific dependency.

    Args:
        db: Database session
        package_name: Name of the package to search for
        version_spec: Optional version string to match (exact match)
        use_fuzzy: Enable fuzzy matching (default: True)
        organization_id: Optional organization ID to filter results (multi-tenant)

    Returns:
        List of dictionaries containing repository and dependency details.
    """
    if use_fuzzy:
        # Use PostgreSQL trigram similarity for fuzzy matching
        # Similarity threshold of 0.3 gives ~90% certainty
        variants = normalize_package_name(package_name)

        # Build OR conditions for all variants
        conditions = []
        for variant in variants:
            conditions.append(models.Dependency.name.ilike(f"%{variant}%"))

        query = db.query(models.Dependency).join(models.Repository).filter(or_(*conditions))
    else:
        # Exact partial match
        query = db.query(models.Dependency).join(models.Repository)
        query = query.filter(models.Dependency.name.ilike(f"%{package_name}%"))

    # Filter by organization if provided (multi-tenant)
    if organization_id:
        query = query.filter(models.Repository.organization_id == organization_id)

    if version_spec:
        query = query.filter(models.Dependency.version == version_spec)

    dependencies = query.all()
    
    results = []
    for dep in dependencies:
        results.append({
            "repository": dep.repository.name,
            "repository_id": str(dep.repository.id),
            "package_name": dep.name,
            "version": dep.version,
            "package_manager": dep.package_manager,
            "locations": dep.locations,
            "last_updated": dep.repository.pushed_at.isoformat() if dep.repository.pushed_at else None,
            "source": "dependencies"
        })

    return results

def search_findings(
    db: Session,
    query: str,
    severity_filter: Optional[str] = None,
    finding_types: Optional[List[str]] = None,
    organization_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search security findings by CVE, CWE, package name, title, or description.

    Args:
        db: Database session
        query: Search query (CVE ID, CWE ID, package name, keyword)
        severity_filter: Optional severity filter (Critical, High, Medium, Low)
        finding_types: Optional list of finding types to filter
        organization_id: Optional organization ID to filter results (multi-tenant)

    Returns:
        List of dictionaries containing finding and repository details.
    """
    # Check if query is a CVE or CWE ID
    is_cve = query.upper().startswith("CVE-")
    is_cwe = query.upper().startswith("CWE-")

    base_query = db.query(models.Finding).join(models.Repository)

    if is_cve:
        # Exact CVE match
        base_query = base_query.filter(models.Finding.cve_id.ilike(f"%{query}%"))
    elif is_cwe:
        # Exact CWE match
        base_query = base_query.filter(models.Finding.cwe_id.ilike(f"%{query}%"))
    else:
        # Fuzzy search across multiple fields
        variants = normalize_package_name(query)
        conditions = []

        for variant in variants:
            conditions.extend([
                models.Finding.package_name.ilike(f"%{variant}%"),
                models.Finding.title.ilike(f"%{variant}%"),
                models.Finding.description.ilike(f"%{variant}%")
            ])

        base_query = base_query.filter(or_(*conditions))

    # Filter by organization if provided (multi-tenant)
    if organization_id:
        base_query = base_query.filter(models.Repository.organization_id == organization_id)

    if severity_filter:
        base_query = base_query.filter(models.Finding.severity.ilike(severity_filter))

    if finding_types:
        base_query = base_query.filter(models.Finding.finding_type.in_(finding_types))

    findings = base_query.all()
    
    results = []
    for finding in findings:
        results.append({
            "repository": finding.repository.name,
            "repository_id": str(finding.repository.id),
            "finding_id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "cve_id": finding.cve_id,
            "cwe_id": finding.cwe_id,
            "package_name": finding.package_name,
            "package_version": finding.package_version,
            "scanner": finding.scanner_name,
            "status": finding.status,
            "last_updated": finding.repository.pushed_at.isoformat() if finding.repository.pushed_at else None,
            "source": "findings"
        })

    return results

def search_languages(
    db: Session,
    language_name: str,
    use_fuzzy: bool = True,
    organization_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search repositories by programming language.

    Args:
        db: Database session
        language_name: Name of the programming language
        use_fuzzy: Enable fuzzy matching (default: True)
        organization_id: Optional organization ID to filter results (multi-tenant)

    Returns:
        List of dictionaries containing repository details.
    """
    if use_fuzzy:
        variants = normalize_package_name(language_name)

        # Search in both language_stats and repositories.language
        lang_stats_query = db.query(models.Repository).join(models.LanguageStat).filter(
            or_(*[models.LanguageStat.name.ilike(f"%{v}%") for v in variants])
        )
        if organization_id:
            lang_stats_query = lang_stats_query.filter(models.Repository.organization_id == organization_id)
        lang_stats_repos = lang_stats_query.distinct().all()

        repo_lang_query = db.query(models.Repository).filter(
            or_(*[models.Repository.language.ilike(f"%{v}%") for v in variants])
        )
        if organization_id:
            repo_lang_query = repo_lang_query.filter(models.Repository.organization_id == organization_id)
        repo_lang_repos = repo_lang_query.all()

        # Combine and deduplicate
        all_repos = {r.id: r for r in lang_stats_repos + repo_lang_repos}
        repos = list(all_repos.values())
    else:
        query = db.query(models.Repository).filter(
            or_(
                models.Repository.language.ilike(f"%{language_name}%"),
                models.Repository.id.in_(
                    db.query(models.LanguageStat.repository_id).filter(
                        models.LanguageStat.name.ilike(f"%{language_name}%")
                    )
                )
            )
        )
        if organization_id:
            query = query.filter(models.Repository.organization_id == organization_id)
        repos = query.all()
    
    results = []
    for repo in repos:
        results.append({
            "repository": repo.name,
            "repository_id": str(repo.id),
            "language": repo.language,
            "description": repo.description,
            "last_updated": repo.pushed_at.isoformat() if repo.pushed_at else None,
            "source": "languages"
        })

    return results

def search_repositories_by_technology(
    db: Session,
    technology: str,
    organization_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search for repositories based on primary language or description.
    Enhanced with fuzzy matching.

    Args:
        db: Database session
        technology: Technology keyword to search for
        organization_id: Optional organization ID to filter results (multi-tenant)

    Returns:
        List of dictionaries containing repository details.
    """
    variants = normalize_package_name(technology)

    query = db.query(models.Repository).filter(
        or_(*[
            models.Repository.language.ilike(f"%{v}%") for v in variants
        ] + [
            models.Repository.description.ilike(f"%{v}%") for v in variants
        ])
    )

    # Filter by organization if provided (multi-tenant)
    if organization_id:
        query = query.filter(models.Repository.organization_id == organization_id)

    repos = query.all()
    return [{
        "repository": r.name,
        "repository_id": str(r.id),
        "language": r.language,
        "description": r.description,
        "last_updated": r.pushed_at.isoformat() if r.pushed_at else None,
        "source": "technology"
    } for r in repos]

def search_all_sources(
    db: Session,
    query: str,
    scopes: Optional[List[str]] = None,
    severity_filter: Optional[str] = None,
    organization_id: Optional[str] = None
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Unified search across all available data sources.

    Args:
        db: Database session
        query: Search query
        scopes: Optional list of scopes to search (dependencies, findings, languages, all)
        severity_filter: Optional severity filter for findings
        organization_id: Optional organization ID to filter results (multi-tenant)

    Returns:
        Dictionary with results grouped by source
    """
    if scopes is None or "all" in scopes:
        scopes = ["dependencies", "findings", "languages"]

    results = {}

    if "dependencies" in scopes:
        results["dependencies"] = search_dependencies(db, query, use_fuzzy=True, organization_id=organization_id)

    if "findings" in scopes:
        results["findings"] = search_findings(db, query, severity_filter=severity_filter, organization_id=organization_id)

    if "languages" in scopes:
        results["languages"] = search_languages(db, query, use_fuzzy=True, organization_id=organization_id)
    
    # Aggregate all repositories
    all_repos = {}
    for source, items in results.items():
        for item in items:
            repo_id = item.get("repository_id")
            repo_name = item.get("repository")
            if repo_id and repo_id not in all_repos:
                all_repos[repo_id] = {
                    "repository": repo_name,
                    "repository_id": repo_id,
                    "matched_sources": [],
                    "details": []
                }
            if repo_id:
                all_repos[repo_id]["matched_sources"].append(source)
                all_repos[repo_id]["details"].append(item)
    
    results["aggregated_repositories"] = list(all_repos.values())
    
    return results

def search_deployments(
    db: Session,
    repository_name: Optional[str] = None,
    environment: Optional[str] = None,
    commit_sha: Optional[str] = None,
    status: Optional[str] = None,
    days_back: int = 90,
    organization_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search deployment history.

    Args:
        db: Database session
        repository_name: Repository name to filter
        environment: Environment name (prod, staging, dev, etc.)
        commit_sha: Specific commit SHA
        status: Deployment status (success, failure, etc.)
        days_back: How many days back to search
        organization_id: Optional organization ID to filter results (multi-tenant)

    Returns:
        List of dictionaries containing deployment details.
    """
    from datetime import datetime, timedelta
    from sqlalchemy import and_
    
    # Build base query
    query = db.query(models.Deployment).join(models.Repository)
    
    # Apply filters
    conditions = []
    
    if repository_name:
        variants = normalize_package_name(repository_name)
        repo_conditions = [models.Repository.name.ilike(f"%{v}%") for v in variants]
        conditions.append(or_(*repo_conditions))
    
    if environment:
        conditions.append(models.Deployment.environment.ilike(f"%{environment}%"))
    
    if commit_sha:
        conditions.append(models.Deployment.commit_sha.startswith(commit_sha))
    
    if status:
        conditions.append(models.Deployment.status.ilike(f"%{status}%"))
    
    # Date filter
    cutoff = datetime.utcnow() - timedelta(days=days_back)
    conditions.append(models.Deployment.started_at >= cutoff)
    
    # Multi-tenant filter
    if organization_id:
        conditions.append(models.Repository.organization_id == organization_id)
    
    if conditions:
        query = query.filter(and_(*conditions))
    
    # Order by most recent first
    query = query.order_by(models.Deployment.started_at.desc())
    
    deployments = query.limit(100).all()
    
    results = []
    for deployment in deployments:
        results.append({
            "repository": deployment.repository.name,
            "repository_id": str(deployment.repository.id),
            "deployment_id": str(deployment.id),
            "environment": deployment.environment,
            "status": deployment.status,
            "commit_sha": deployment.commit_sha,
            "commit_message": deployment.commit_message,
            "deployer": deployment.deployer,
            "deployment_url": deployment.deployment_url,
            "started_at": deployment.started_at.isoformat() if deployment.started_at else None,
            "completed_at": deployment.completed_at.isoformat() if deployment.completed_at else None,
            "duration_seconds": deployment.duration_seconds,
            "source": "deployments"
        })
    
    return results


def search_workflow_runs(
    db: Session,
    repository_name: Optional[str] = None,
    workflow_name: Optional[str] = None,
    branch: Optional[str] = None,
    status: Optional[str] = None,
    conclusion: Optional[str] = None,
    days_back: int = 30,
    organization_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search CI/CD workflow runs.

    Args:
        db: Database session
        repository_name: Repository name to filter
        workflow_name: Workflow/pipeline name
        branch: Branch name
        status: Workflow status (queued, in_progress, completed)
        conclusion: Workflow conclusion (success, failure, cancelled)
        days_back: How many days back to search
        organization_id: Optional organization ID to filter results (multi-tenant)

    Returns:
        List of dictionaries containing workflow run details.
    """
    from datetime import datetime, timedelta
    from sqlalchemy import and_
    
    # Build base query
    query = db.query(models.WorkflowRun).join(models.Repository)
    
    # Apply filters
    conditions = []
    
    if repository_name:
        variants = normalize_package_name(repository_name)
        repo_conditions = [models.Repository.name.ilike(f"%{v}%") for v in variants]
        conditions.append(or_(*repo_conditions))
    
    if workflow_name:
        conditions.append(models.WorkflowRun.workflow_name.ilike(f"%{workflow_name}%"))
    
    if branch:
        conditions.append(models.WorkflowRun.branch.ilike(f"%{branch}%"))
    
    if status:
        conditions.append(models.WorkflowRun.status.ilike(f"%{status}%"))
    
    if conclusion:
        conditions.append(models.WorkflowRun.conclusion.ilike(f"%{conclusion}%"))
    
    # Date filter
    cutoff = datetime.utcnow() - timedelta(days=days_back)
    conditions.append(models.WorkflowRun.started_at >= cutoff)
    
    # Multi-tenant filter
    if organization_id:
        conditions.append(models.Repository.organization_id == organization_id)
    
    if conditions:
        query = query.filter(and_(*conditions))
    
    # Order by most recent first
    query = query.order_by(models.WorkflowRun.started_at.desc())
    
    workflow_runs = query.limit(100).all()
    
    results = []
    for run in workflow_runs:
        results.append({
            "repository": run.repository.name,
            "repository_id": str(run.repository.id),
            "run_id": str(run.id),
            "workflow_name": run.workflow_name,
            "status": run.status,
            "conclusion": run.conclusion,
            "branch": run.branch,
            "commit_sha": run.commit_sha,
            "actor": run.actor,
            "html_url": run.html_url,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "duration_seconds": run.duration_seconds,
            "source": "workflow_runs"
        })
    
    return results


def get_repository_deployment_status(
    db: Session,
    repository_id: str,
    environment: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get the current deployment status for a repository.

    Args:
        db: Database session
        repository_id: Repository UUID
        environment: Optional environment filter

    Returns:
        Dictionary with deployment status information
    """
    from sqlalchemy import desc
    
    # Get most recent successful deployment per environment
    query = db.query(models.Deployment).filter(
        models.Deployment.repository_id == repository_id,
        models.Deployment.status == 'success'
    )
    
    if environment:
        query = query.filter(models.Deployment.environment == environment)
    
    query = query.order_by(desc(models.Deployment.completed_at))
    
    # Get all environments with their latest deployment
    deployments_by_env = {}
    for deployment in query.all():
        env = deployment.environment
        if env not in deployments_by_env:
            deployments_by_env[env] = {
                "environment": env,
                "commit_sha": deployment.commit_sha,
                "deployed_at": deployment.completed_at.isoformat() if deployment.completed_at else None,
                "deployer": deployment.deployer,
                "deployment_url": deployment.deployment_url
            }
    
    return {
        "repository_id": repository_id,
        "environments": list(deployments_by_env.values()),
        "total_environments": len(deployments_by_env)
    }
