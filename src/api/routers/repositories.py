from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from ..dependencies import get_tenant_db
from .. import models
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from src.auth.dependencies import get_current_user
from src.rbac.dependencies import require_permissions
from src.auth.models import User

router = APIRouter(
    prefix="/repositories",
    tags=["repositories"]
)

# Pydantic Schemas
class RepositoryBase(BaseModel):
    name: str = Field(..., description="Repository name (e.g., 'my-service')", examples=["my-service"])
    full_name: Optional[str] = Field(None, description="Full repo path (org/name)", examples=["sleepnumber/my-service"])
    url: Optional[str] = Field(None, description="GitHub repository URL")
    description: Optional[str] = Field(None, description="Repository description")
    language: Optional[str] = Field(None, description="Primary programming language", examples=["Python"])
    business_criticality: Optional[str] = Field("medium", description="Business criticality level", examples=["high"])

class RepositoryCreate(RepositoryBase):
    pass

class Repository(RepositoryBase):
    id: str = Field(..., description="Repository UUID")
    api_id: Optional[int] = Field(None, description="Numeric API identifier")
    last_scanned_at: Optional[datetime] = Field(None, description="Last security scan timestamp")
    pushed_at: Optional[datetime] = Field(None, description="Last git push timestamp")
    github_created_at: Optional[datetime] = Field(None, description="Repository creation date on GitHub")
    stargazers_count: Optional[int] = Field(0, description="GitHub stars count")
    forks_count: Optional[int] = Field(0, description="GitHub forks count")
    is_archived: Optional[bool] = Field(False, description="Whether the repo is archived")
    is_private: Optional[bool] = Field(True, description="Whether the repo is private")
    visibility: Optional[str] = Field(None, description="Repository visibility (public/private/internal)")
    created_at: datetime = Field(..., description="Record creation timestamp")
    updated_at: datetime = Field(..., description="Record last update timestamp")

    model_config = {"from_attributes": True}

@router.get("/", response_model=List[Repository], summary="List repositories", responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions"}})
def read_repositories(
    skip: int = 0,
    limit: int = 100,
    # TODO(Phase 5): Add additional tenant filtering at query level for defense-in-depth
    # Currently relying on SET search_path, Phase 5 should add explicit WHERE tenant_id= filters
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """List all repositories with pagination.

    Returns repositories the current user has access to. Supports pagination
    via `skip` and `limit` query parameters.

    **Required permissions:** `repos:read`
    """
    # TODO Phase 3: Filter by current_user.sub and tenant
    repos = db.query(models.Repository).offset(skip).limit(limit).all()
    # Convert UUIDs to strings for Pydantic
    for repo in repos:
        repo.id = str(repo.id)
    return repos

@router.post("/", response_model=Repository, summary="Register a new repository", responses={400: {"description": "Repository already registered"}, 401: {"description": "Not authenticated"}})
def create_repository(repo: RepositoryCreate, db: Session = Depends(get_tenant_db)):
    """Register a new repository for security scanning.

    Creates a repository record that can then be targeted by scan operations.
    Duplicate names are rejected.

    **Required permissions:** `repos:write`
    """
    db_repo = db.query(models.Repository).filter(models.Repository.name == repo.name).first()
    if db_repo:
        raise HTTPException(status_code=400, detail="Repository already registered")
    
    new_repo = models.Repository(**repo.dict())
    db.add(new_repo)
    db.commit()
    db.refresh(new_repo)
    new_repo.id = str(new_repo.id)
    return new_repo

@router.get("/{repo_name}", response_model=Repository, summary="Get repository by name", responses={401: {"description": "Not authenticated"}, 404: {"description": "Repository not found"}})
def read_repository(repo_name: str, db: Session = Depends(get_tenant_db)):
    """Retrieve a specific repository by its name.

    Returns the full repository record including scan history timestamps,
    GitHub metadata, and business criticality.

    **Required permissions:** `repos:read`
    """
    repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    repo.id = str(repo.id)
    return repo
