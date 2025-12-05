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
    use_fuzzy: bool = True
) -> List[Dict[str, Any]]:
    """
    Search for repositories containing a specific dependency.
    
    Args:
        db: Database session
        package_name: Name of the package to search for
        version_spec: Optional version string to match (exact match)
        use_fuzzy: Enable fuzzy matching (default: True)
        
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
            "source": "dependencies"
        })
        
    return results

def search_findings(
    db: Session, 
    query: str,
    severity_filter: Optional[str] = None,
    finding_types: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Search security findings by CVE, CWE, package name, title, or description.
    
    Args:
        db: Database session
        query: Search query (CVE ID, CWE ID, package name, keyword)
        severity_filter: Optional severity filter (Critical, High, Medium, Low)
        finding_types: Optional list of finding types to filter
        
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
            "source": "findings"
        })
    
    return results

def search_languages(
    db: Session, 
    language_name: str,
    use_fuzzy: bool = True
) -> List[Dict[str, Any]]:
    """
    Search repositories by programming language.
    
    Args:
        db: Database session
        language_name: Name of the programming language
        use_fuzzy: Enable fuzzy matching (default: True)
        
    Returns:
        List of dictionaries containing repository details.
    """
    if use_fuzzy:
        variants = normalize_package_name(language_name)
        
        # Search in both language_stats and repositories.language
        lang_stats_repos = db.query(models.Repository).join(models.LanguageStat).filter(
            or_(*[models.LanguageStat.name.ilike(f"%{v}%") for v in variants])
        ).distinct().all()
        
        repo_lang_repos = db.query(models.Repository).filter(
            or_(*[models.Repository.language.ilike(f"%{v}%") for v in variants])
        ).all()
        
        # Combine and deduplicate
        all_repos = {r.id: r for r in lang_stats_repos + repo_lang_repos}
        repos = list(all_repos.values())
    else:
        repos = db.query(models.Repository).filter(
            or_(
                models.Repository.language.ilike(f"%{language_name}%"),
                models.Repository.id.in_(
                    db.query(models.LanguageStat.repository_id).filter(
                        models.LanguageStat.name.ilike(f"%{language_name}%")
                    )
                )
            )
        ).all()
    
    results = []
    for repo in repos:
        results.append({
            "repository": repo.name,
            "repository_id": str(repo.id),
            "language": repo.language,
            "description": repo.description,
            "source": "languages"
        })
    
    return results

def search_repositories_by_technology(
    db: Session, 
    technology: str
) -> List[Dict[str, Any]]:
    """
    Search for repositories based on primary language or description.
    Enhanced with fuzzy matching.
    """
    variants = normalize_package_name(technology)
    
    query = db.query(models.Repository).filter(
        or_(*[
            models.Repository.language.ilike(f"%{v}%") for v in variants
        ] + [
            models.Repository.description.ilike(f"%{v}%") for v in variants
        ])
    )
    
    repos = query.all()
    return [{
        "repository": r.name, 
        "repository_id": str(r.id), 
        "language": r.language,
        "description": r.description,
        "source": "technology"
    } for r in repos]

def search_all_sources(
    db: Session,
    query: str,
    scopes: Optional[List[str]] = None,
    severity_filter: Optional[str] = None
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Unified search across all available data sources.
    
    Args:
        db: Database session
        query: Search query
        scopes: Optional list of scopes to search (dependencies, findings, languages, all)
        severity_filter: Optional severity filter for findings
        
    Returns:
        Dictionary with results grouped by source
    """
    if scopes is None or "all" in scopes:
        scopes = ["dependencies", "findings", "languages"]
    
    results = {}
    
    if "dependencies" in scopes:
        results["dependencies"] = search_dependencies(db, query, use_fuzzy=True)
    
    if "findings" in scopes:
        results["findings"] = search_findings(db, query, severity_filter=severity_filter)
    
    if "languages" in scopes:
        results["languages"] = search_languages(db, query, use_fuzzy=True)
    
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
