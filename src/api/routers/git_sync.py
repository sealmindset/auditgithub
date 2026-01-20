"""
Git Sync Router - Handles pushing architecture artifacts to GitHub repositories
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
import subprocess
import tempfile
import shutil
import os
from pathlib import Path
from loguru import logger
from typing import Optional
import base64

from ..dependencies import get_tenant_db
from .. import models

router = APIRouter(
    prefix="/git-sync",
    tags=["git-sync"]
)


class GitPushREADMERequest(BaseModel):
    project_id: str
    organization: str


class GitPushDiagramRequest(BaseModel):
    project_id: str
    organization: str


def get_github_token_for_org(org: str) -> Optional[str]:
    """Get GitHub token from environment for the specified organization."""
    # Try org-specific token first
    org_upper = org.upper().replace("-", "").replace("_", "")
    token = os.getenv(f"ORG_{org_upper}_TOKEN") or os.getenv(f"{org_upper}_GITHUB_TOKEN")

    if not token:
        # Fall back to default GitHub token
        token = os.getenv("GITHUB_TOKEN")

    return token


def get_github_org_name(org: str) -> str:
    """Get the GitHub organization name from environment or use the provided org."""
    org_upper = org.upper().replace("-", "").replace("_", "")
    github_org = os.getenv(f"ORG_{org_upper}_GITHUB")

    return github_org or org


def clone_and_update_repo(
    repo_url: str,
    github_token: str,
    file_path: str,
    file_content: bytes,
    commit_message: str,
    repo_name: str
) -> dict:
    """
    Clone a repository, update a file, commit and push changes.

    Returns dict with success status and message.
    """
    temp_dir = tempfile.mkdtemp(prefix=f"git_sync_{repo_name}_")

    try:
        # Add token to URL for authentication
        if github_token and "github.com" in repo_url:
            # Convert https://github.com/org/repo to https://TOKEN@github.com/org/repo
            auth_url = repo_url.replace("https://", f"https://{github_token}@")
        else:
            auth_url = repo_url

        # Clone repository
        logger.info(f"Cloning repository: {repo_url}")
        result = subprocess.run(
            ["git", "clone", auth_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            raise Exception(f"Git clone failed: {result.stderr}")

        # Write file
        file_full_path = os.path.join(temp_dir, file_path)
        os.makedirs(os.path.dirname(file_full_path), exist_ok=True)

        if isinstance(file_content, bytes):
            with open(file_full_path, 'wb') as f:
                f.write(file_content)
        else:
            with open(file_full_path, 'w') as f:
                f.write(file_content)

        # Configure git
        subprocess.run(
            ["git", "config", "user.name", "AuditGH Bot"],
            cwd=temp_dir,
            check=True
        )
        subprocess.run(
            ["git", "config", "user.email", "noreply@auditgh.local"],
            cwd=temp_dir,
            check=True
        )

        # Stage changes
        subprocess.run(
            ["git", "add", file_path],
            cwd=temp_dir,
            check=True
        )

        # Check if there are changes to commit
        status_result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=temp_dir,
            capture_output=True,
            text=True
        )

        if not status_result.stdout.strip():
            return {
                "success": True,
                "message": "No changes to commit (file content unchanged)",
                "skipped": True
            }

        # Commit changes
        subprocess.run(
            ["git", "commit", "-m", commit_message],
            cwd=temp_dir,
            check=True
        )

        # Push changes
        logger.info("Pushing changes to remote...")
        push_result = subprocess.run(
            ["git", "push", "origin", "HEAD"],
            cwd=temp_dir,
            capture_output=True,
            text=True,
            timeout=60
        )

        if push_result.returncode != 0:
            raise Exception(f"Git push failed: {push_result.stderr}")

        return {
            "success": True,
            "message": f"Successfully pushed {file_path} to repository",
            "skipped": False
        }

    except subprocess.TimeoutExpired:
        raise Exception("Git operation timed out")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Git command failed: {e.stderr if hasattr(e, 'stderr') else str(e)}")
    except Exception as e:
        raise Exception(f"Git sync failed: {str(e)}")
    finally:
        # Cleanup temp directory
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp dir {temp_dir}: {e}")


@router.post("/push-readme")
async def push_readme_to_git(
    request: GitPushREADMERequest,
    db: Session = Depends(get_tenant_db)
):
    """
    Push architecture report to README.md in the repository.
    """
    try:
        # Get repository
        repo = db.query(models.Repository).filter(
            models.Repository.id == request.project_id
        ).first()

        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")

        # Verify repository belongs to the specified organization
        org = db.query(models.Organization).filter(
            models.Organization.id == repo.organization_id
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found for repository")

        # Verify the organization matches the request
        if org.name.lower() != request.organization.lower() and org.github_org.lower() != request.organization.lower():
            raise HTTPException(
                status_code=403,
                detail=f"Repository belongs to {org.name}, not {request.organization}"
            )

        if not repo.architecture_report:
            raise HTTPException(status_code=400, detail="No architecture report available")

        if not repo.url:
            raise HTTPException(status_code=400, detail="Repository URL not found")

        # Get GitHub token for this specific organization
        github_token = get_github_token_for_org(org.github_org or org.name)
        if not github_token:
            raise HTTPException(
                status_code=500,
                detail=f"GitHub token not configured for organization: {org.github_org or org.name}"
            )

        # Get GitHub org name from database
        github_org = org.github_org or org.name

        # Prepare README content (replace entire README)
        readme_content = repo.architecture_report.encode('utf-8')

        # Push to repository
        result = clone_and_update_repo(
            repo_url=repo.url,
            github_token=github_token,
            file_path="README.md",
            file_content=readme_content,
            commit_message="Update README with architecture report [automated]",
            repo_name=repo.name
        )

        return {
            "success": result["success"],
            "message": result["message"],
            "skipped": result.get("skipped", False),
            "repository": repo.name,
            "file": "README.md"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to push README: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/push-diagram")
async def push_diagram_to_git(
    request: GitPushDiagramRequest,
    db: Session = Depends(get_tenant_db)
):
    """
    Convert Mermaid diagram to PNG and push to repository root.
    """
    try:
        # Get repository
        repo = db.query(models.Repository).filter(
            models.Repository.id == request.project_id
        ).first()

        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")

        # Verify repository belongs to the specified organization
        org = db.query(models.Organization).filter(
            models.Organization.id == repo.organization_id
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found for repository")

        # Verify the organization matches the request
        if org.name.lower() != request.organization.lower() and org.github_org.lower() != request.organization.lower():
            raise HTTPException(
                status_code=403,
                detail=f"Repository belongs to {org.name}, not {request.organization}"
            )

        if not repo.architecture_diagram:
            raise HTTPException(status_code=400, detail="No architecture diagram available")

        if not repo.url:
            raise HTTPException(status_code=400, detail="Repository URL not found")

        # Get GitHub token for this specific organization
        github_token = get_github_token_for_org(org.github_org or org.name)
        if not github_token:
            raise HTTPException(
                status_code=500,
                detail=f"GitHub token not configured for organization: {org.github_org or org.name}"
            )

        # TODO: Convert Mermaid to PNG
        # For now, return an error indicating this needs to be implemented
        raise HTTPException(
            status_code=501,
            detail="PNG conversion not yet implemented. Please use the download fallback."
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to push diagram: {e}")
        raise HTTPException(status_code=500, detail=str(e))
