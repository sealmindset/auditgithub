"""
GitHub metadata sync router.
Provides endpoints to sync and access GitHub API data stored locally.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
import os
import requests
from loguru import logger

from ..dependencies import get_tenant_db
from .. import models
from src.rbac.dependencies import require_permissions
from src.api.schemas.common import CRUD_ERRORS, LIST_ERRORS, CREATE_ERRORS

router = APIRouter(
    prefix="/github",
    tags=["github"]
)


# =============================================================================
# Pydantic Models
# =============================================================================

class RepositoryMetadata(BaseModel):
    """GitHub repository metadata."""
    id: str = Field(..., description="Unique identifier for the repository")
    name: str = Field(..., description="Repository name")
    full_name: Optional[str] = Field(None, description="Full name including org prefix (e.g. org/repo)")
    description: Optional[str] = Field(None, description="Repository description from GitHub")
    url: Optional[str] = Field(None, description="HTML URL of the repository on GitHub")
    default_branch: Optional[str] = Field(None, description="Default branch name (e.g. main)")
    language: Optional[str] = Field(None, description="Primary programming language")
    pushed_at: Optional[datetime] = Field(None, description="Timestamp of the last push to the repository")
    github_created_at: Optional[datetime] = Field(None, description="When the repository was created on GitHub")
    github_updated_at: Optional[datetime] = Field(None, description="When the repository was last updated on GitHub")
    stargazers_count: int = Field(0, description="Number of stars on the repository")
    watchers_count: int = Field(0, description="Number of watchers on the repository")
    forks_count: int = Field(0, description="Number of forks of the repository")
    open_issues_count: int = Field(0, description="Number of open issues")
    size_kb: int = Field(0, description="Repository size in kilobytes")
    is_fork: bool = Field(False, description="Whether this repository is a fork")
    is_archived: bool = Field(False, description="Whether this repository is archived")
    is_private: bool = Field(True, description="Whether this repository is private")
    visibility: Optional[str] = Field(None, description="Repository visibility (public, private, internal)")
    topics: Optional[List[str]] = Field(None, description="List of repository topics/tags")
    license_name: Optional[str] = Field(None, description="SPDX license identifier or license name")

    model_config = {"from_attributes": True}


class FileCommitInfo(BaseModel):
    """File commit information."""
    file_path: str = Field(..., description="Path of the file within the repository")
    last_commit_sha: Optional[str] = Field(None, description="SHA hash of the last commit that modified the file")
    last_commit_date: Optional[datetime] = Field(None, description="Date of the last commit that modified the file")
    last_commit_author: Optional[str] = Field(None, description="Author name of the last commit")
    last_commit_message: Optional[str] = Field(None, description="Commit message of the last commit")

    model_config = {"from_attributes": True}


class SyncResult(BaseModel):
    """Result of a sync operation."""
    success: bool = Field(..., description="Whether the sync operation succeeded")
    message: str = Field(..., description="Human-readable status message")
    repos_synced: int = Field(0, description="Number of repositories successfully synced")
    files_synced: int = Field(0, description="Number of files successfully synced")


# =============================================================================
# GitHub API Helper
# =============================================================================

class GitHubClient:
    """Simple GitHub API client for metadata fetching."""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        self.org = os.getenv("GITHUB_ORG")
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "AuditGH/1.0"
            })
    
    def get_repo(self, repo_name: str) -> Optional[dict]:
        """Fetch repository metadata from GitHub API."""
        if not self.token or not self.org:
            return None
        try:
            resp = self.session.get(f"{self.BASE_URL}/repos/{self.org}/{repo_name}")
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(f"Failed to fetch repo {repo_name}: {e}")
            return None
    
    def get_file_commits(self, repo_name: str, file_path: str, per_page: int = 1) -> Optional[list]:
        """Fetch commit history for a specific file."""
        if not self.token or not self.org:
            return None
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/repos/{self.org}/{repo_name}/commits",
                params={"path": file_path, "per_page": per_page}
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(f"Failed to fetch commits for {repo_name}/{file_path}: {e}")
            return None


github_client = GitHubClient()


# =============================================================================
# Helper Functions
# =============================================================================

def parse_github_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Parse GitHub API datetime string to datetime object."""
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except Exception:
        return None


def sync_repo_metadata(db: Session, repo: models.Repository, github_data: dict) -> bool:
    """Update repository with GitHub API metadata."""
    try:
        repo.pushed_at = parse_github_datetime(github_data.get('pushed_at'))
        repo.github_created_at = parse_github_datetime(github_data.get('created_at'))
        repo.github_updated_at = parse_github_datetime(github_data.get('updated_at'))
        repo.stargazers_count = github_data.get('stargazers_count', 0)
        repo.watchers_count = github_data.get('watchers_count', 0)
        repo.forks_count = github_data.get('forks_count', 0)
        repo.open_issues_count = github_data.get('open_issues_count', 0)
        repo.size_kb = github_data.get('size', 0)
        repo.is_fork = github_data.get('fork', False)
        repo.is_archived = github_data.get('archived', False)
        repo.is_disabled = github_data.get('disabled', False)
        repo.is_private = github_data.get('private', True)
        repo.visibility = github_data.get('visibility')
        repo.topics = github_data.get('topics', [])
        repo.default_branch = github_data.get('default_branch', 'main')
        repo.full_name = github_data.get('full_name')
        repo.url = github_data.get('html_url')
        repo.description = github_data.get('description')
        repo.language = github_data.get('language')
        
        # License
        license_info = github_data.get('license')
        if license_info and isinstance(license_info, dict):
            repo.license_name = license_info.get('spdx_id') or license_info.get('name')
        
        # Wiki/Pages/Discussions
        repo.has_wiki = github_data.get('has_wiki', False)
        repo.has_pages = github_data.get('has_pages', False)
        repo.has_discussions = github_data.get('has_discussions', False)
        
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to sync repo metadata for {repo.name}: {e}")
        db.rollback()
        return False


def sync_file_commit(db: Session, repo: models.Repository, file_path: str) -> Optional[models.FileCommit]:
    """Fetch and store file commit information from GitHub API."""
    commits = github_client.get_file_commits(repo.name, file_path)
    if not commits or len(commits) == 0:
        return None
    
    commit_data = commits[0]
    commit_info = commit_data.get('commit', {})
    author_info = commit_info.get('author', {})
    
    try:
        # Upsert file commit record
        file_commit = db.query(models.FileCommit).filter(
            models.FileCommit.repository_id == repo.id,
            models.FileCommit.file_path == file_path
        ).first()
        
        if not file_commit:
            file_commit = models.FileCommit(
                repository_id=repo.id,
                file_path=file_path
            )
            db.add(file_commit)
        
        file_commit.last_commit_sha = commit_data.get('sha')
        file_commit.last_commit_date = parse_github_datetime(author_info.get('date'))
        file_commit.last_commit_author = author_info.get('name')
        file_commit.last_commit_message = commit_info.get('message', '')[:500]  # Truncate long messages
        
        db.commit()
        db.refresh(file_commit)
        return file_commit
    except Exception as e:
        logger.error(f"Failed to sync file commit for {repo.name}/{file_path}: {e}")
        db.rollback()
        return None


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "/repos/{repo_name}/metadata",
    response_model=RepositoryMetadata,
    dependencies=[Depends(require_permissions("repositories:read"))],
    summary="Get repository GitHub metadata",
    responses={**CRUD_ERRORS, 403: {"description": "Missing repositories:read permission"}, 404: {"description": "Repository not found"}},
)
def get_repo_metadata(repo_name: str, db: Session = Depends(get_tenant_db)):
    """Retrieve locally-stored GitHub metadata for a single repository.

    Requires the **repositories:read** permission. Returns metadata fields
    fetched from the GitHub API during the last sync.
    """
    repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    return RepositoryMetadata(
        id=str(repo.id),
        name=repo.name,
        full_name=repo.full_name,
        description=repo.description,
        url=repo.url,
        default_branch=repo.default_branch,
        language=repo.language,
        pushed_at=repo.pushed_at,
        github_created_at=repo.github_created_at,
        github_updated_at=repo.github_updated_at,
        stargazers_count=repo.stargazers_count or 0,
        watchers_count=repo.watchers_count or 0,
        forks_count=repo.forks_count or 0,
        open_issues_count=repo.open_issues_count or 0,
        size_kb=repo.size_kb or 0,
        is_fork=repo.is_fork or False,
        is_archived=repo.is_archived or False,
        is_private=repo.is_private if repo.is_private is not None else True,
        visibility=repo.visibility,
        topics=repo.topics or [],
        license_name=repo.license_name
    )


@router.post(
    "/repos/{repo_name}/sync",
    response_model=SyncResult,
    dependencies=[Depends(require_permissions("repositories:write"))],
    summary="Sync single repository from GitHub",
    responses={**CRUD_ERRORS, 403: {"description": "Missing repositories:write permission"}, 404: {"description": "Repository not found in local database"}, 502: {"description": "Failed to fetch data from GitHub API"}},
)
def sync_repo_from_github(repo_name: str, db: Session = Depends(get_tenant_db)):
    """Fetch the latest metadata for a repository from the GitHub API and store it locally.

    Requires the **repositories:write** permission. Contacts the GitHub API to
    refresh repository statistics, topics, and other metadata.
    """
    repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    github_data = github_client.get_repo(repo_name)
    if not github_data:
        raise HTTPException(status_code=502, detail="Failed to fetch data from GitHub API")
    
    success = sync_repo_metadata(db, repo, github_data)
    
    return SyncResult(
        success=success,
        message=f"Synced metadata for {repo_name}" if success else f"Failed to sync {repo_name}",
        repos_synced=1 if success else 0
    )


@router.post(
    "/sync-all",
    response_model=SyncResult,
    dependencies=[Depends(require_permissions("repositories:write"))],
    summary="Sync all repositories from GitHub",
    responses={**CREATE_ERRORS, 403: {"description": "Missing repositories:write permission"}, 500: {"description": "Internal server error during sync"}},
)
def sync_all_repos(background_tasks: BackgroundTasks, db: Session = Depends(get_tenant_db)):
    """Queue a background job that syncs metadata for every repository from the GitHub API.

    Requires the **repositories:write** permission. The sync runs asynchronously;
    use the sync-status endpoint to monitor progress.
    """
    repos = db.query(models.Repository).all()
    
    def sync_all(repo_names: List[str]):
        """Background task to sync all repos."""
        db_session = next(get_db())
        synced = 0
        for name in repo_names:
            repo = db_session.query(models.Repository).filter(models.Repository.name == name).first()
            if repo:
                github_data = github_client.get_repo(name)
                if github_data and sync_repo_metadata(db_session, repo, github_data):
                    synced += 1
        logger.info(f"Synced {synced}/{len(repo_names)} repositories")
    
    repo_names = [r.name for r in repos]
    background_tasks.add_task(sync_all, repo_names)
    
    return SyncResult(
        success=True,
        message=f"Started syncing {len(repos)} repositories in background",
        repos_synced=0  # Will be updated in background
    )


@router.get(
    "/repos/{repo_name}/files/{file_path:path}/commit",
    response_model=FileCommitInfo,
    dependencies=[Depends(require_permissions("repositories:read"))],
    summary="Get last commit info for a file",
    responses={**CRUD_ERRORS, 403: {"description": "Missing repositories:read permission"}, 404: {"description": "Repository or file commit data not found"}},
)
def get_file_commit(repo_name: str, file_path: str, refresh: bool = False, db: Session = Depends(get_tenant_db)):
    """Return the last commit information for a specific file in a repository.

    Requires the **repositories:read** permission. Returns cached data by
    default; set `refresh=true` to fetch fresh commit data from the GitHub API.
    """
    repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    # Check if we have cached data
    file_commit = db.query(models.FileCommit).filter(
        models.FileCommit.repository_id == repo.id,
        models.FileCommit.file_path == file_path
    ).first()
    
    # Fetch from GitHub if no cache or refresh requested
    if not file_commit or refresh:
        file_commit = sync_file_commit(db, repo, file_path)
        if not file_commit:
            raise HTTPException(status_code=404, detail="No commit data found for this file")
    
    return FileCommitInfo(
        file_path=file_commit.file_path,
        last_commit_sha=file_commit.last_commit_sha,
        last_commit_date=file_commit.last_commit_date,
        last_commit_author=file_commit.last_commit_author,
        last_commit_message=file_commit.last_commit_message
    )


@router.post(
    "/repos/{repo_name}/files/sync",
    response_model=SyncResult,
    dependencies=[Depends(require_permissions("repositories:write"))],
    summary="Sync file commit data for a repository",
    responses={**CRUD_ERRORS, 403: {"description": "Missing repositories:write permission"}, 404: {"description": "Repository not found"}},
)
def sync_files_for_findings(repo_name: str, db: Session = Depends(get_tenant_db)):
    """Fetch commit data from GitHub for every file that has findings in the given repository.

    Requires the **repositories:write** permission. Iterates over distinct file
    paths associated with findings and refreshes their last-commit metadata.
    """
    repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    # Get unique file paths from findings
    file_paths = db.query(models.Finding.file_path).filter(
        models.Finding.repository_id == repo.id,
        models.Finding.file_path.isnot(None)
    ).distinct().all()
    
    synced = 0
    for (file_path,) in file_paths:
        if file_path:
            result = sync_file_commit(db, repo, file_path)
            if result:
                synced += 1
    
    return SyncResult(
        success=True,
        message=f"Synced commit data for {synced}/{len(file_paths)} files",
        files_synced=synced
    )


@router.post(
    "/sync-all-files",
    response_model=SyncResult,
    dependencies=[Depends(require_permissions("repositories:write"))],
    summary="Sync file commit data for all repositories",
    responses={**CREATE_ERRORS, 403: {"description": "Missing repositories:write permission"}, 500: {"description": "Internal server error during sync"}},
)
def sync_all_files_for_findings(background_tasks: BackgroundTasks, db: Session = Depends(get_tenant_db)):
    """Queue a background job to sync file commit data for ALL files with findings across all repositories.

    Requires the **repositories:write** permission. This may take a while for
    large numbers of files. Use GET /github/sync-status to check progress.
    """
    from ..database import SessionLocal
    
    # Get all unique repo + file path combinations from findings
    findings_files = db.query(
        models.Finding.repository_id,
        models.Finding.file_path
    ).filter(
        models.Finding.file_path.isnot(None)
    ).distinct().all()
    
    # Group by repository
    repo_files: dict = {}
    for repo_id, file_path in findings_files:
        if repo_id and file_path:
            if repo_id not in repo_files:
                repo_files[repo_id] = []
            repo_files[repo_id].append(file_path)
    
    total_files = sum(len(files) for files in repo_files.values())
    
    def sync_all_files_task():
        """Background task to sync all file commits."""
        db_session = SessionLocal()
        try:
            synced = 0
            failed = 0
            for repo_id, file_paths in repo_files.items():
                repo = db_session.query(models.Repository).filter(models.Repository.id == repo_id).first()
                if not repo:
                    continue
                for file_path in file_paths:
                    try:
                        result = sync_file_commit(db_session, repo, file_path)
                        if result:
                            synced += 1
                        else:
                            failed += 1
                    except Exception as e:
                        logger.warning(f"Failed to sync {repo.name}/{file_path}: {e}")
                        failed += 1
            logger.info(f"File commit sync complete: {synced} synced, {failed} failed out of {total_files} total")
        finally:
            db_session.close()
    
    background_tasks.add_task(sync_all_files_task)
    
    return SyncResult(
        success=True,
        message=f"Started syncing {total_files} files across {len(repo_files)} repositories in background",
        files_synced=0  # Updates in background
    )


@router.get(
    "/sync-status",
    dependencies=[Depends(require_permissions("repositories:read"))],
    summary="Get sync status overview",
    responses={**LIST_ERRORS, 403: {"description": "Missing repositories:read permission"}},
)
def get_sync_status(db: Session = Depends(get_tenant_db)):
    """Return aggregate sync status showing how many repositories and files have been synced.

    Requires the **repositories:read** permission. Provides counts and
    percentages for repositories with metadata, files with commit data,
    and findings with associated file commit information.
    """
    # Count repos with GitHub metadata
    repos_with_metadata = db.query(models.Repository).filter(
        models.Repository.pushed_at.isnot(None)
    ).count()
    
    total_repos = db.query(models.Repository).count()
    
    # Count files with commit data
    files_with_commits = db.query(models.FileCommit).count()
    
    # Count unique files in findings
    total_finding_files = db.query(models.Finding.file_path).filter(
        models.Finding.file_path.isnot(None)
    ).distinct().count()
    
    # Count findings with file commit data
    findings_with_file_data = db.query(models.Finding).join(
        models.FileCommit,
        (models.Finding.repository_id == models.FileCommit.repository_id) &
        (models.Finding.file_path == models.FileCommit.file_path)
    ).count()
    
    total_findings = db.query(models.Finding).count()
    
    return {
        "repositories": {
            "total": total_repos,
            "with_github_metadata": repos_with_metadata,
            "percent_synced": round(repos_with_metadata / total_repos * 100, 1) if total_repos > 0 else 0
        },
        "files": {
            "total_with_findings": total_finding_files,
            "with_commit_data": files_with_commits,
            "percent_synced": round(files_with_commits / total_finding_files * 100, 1) if total_finding_files > 0 else 0
        },
        "findings": {
            "total": total_findings,
            "with_file_commit_data": findings_with_file_data,
            "percent_with_file_data": round(findings_with_file_data / total_findings * 100, 1) if total_findings > 0 else 0
        }
    }

