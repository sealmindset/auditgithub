from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from ..dependencies import get_tenant_db
from .. import models
from pydantic import BaseModel
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
    name: str
    full_name: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    language: Optional[str] = None
    business_criticality: Optional[str] = "medium"

class RepositoryCreate(RepositoryBase):
    pass

class Repository(RepositoryBase):
    id: str  # UUID as string
    api_id: Optional[int] = None
    last_scanned_at: Optional[datetime] = None
    pushed_at: Optional[datetime] = None
    github_created_at: Optional[datetime] = None
    stargazers_count: Optional[int] = 0
    forks_count: Optional[int] = 0
    is_archived: Optional[bool] = False
    is_private: Optional[bool] = True
    visibility: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

@router.get("/", response_model=List[Repository])
def read_repositories(
    skip: int = 0,
    limit: int = 100,
    # TODO(Phase 5): Add additional tenant filtering at query level for defense-in-depth
    # Currently relying on SET search_path, Phase 5 should add explicit WHERE tenant_id= filters
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user)
):
    """Get all repositories."""
    # TODO Phase 3: Filter by current_user.sub and tenant
    repos = db.query(models.Repository).offset(skip).limit(limit).all()
    # Convert UUIDs to strings for Pydantic
    for repo in repos:
        repo.id = str(repo.id)
    return repos

@router.post("/", response_model=Repository)
def create_repository(repo: RepositoryCreate, db: Session = Depends(get_tenant_db)):
    """Register a new repository."""
    db_repo = db.query(models.Repository).filter(models.Repository.name == repo.name).first()
    if db_repo:
        raise HTTPException(status_code=400, detail="Repository already registered")
    
    new_repo = models.Repository(**repo.dict())
    db.add(new_repo)
    db.commit()
    db.refresh(new_repo)
    new_repo.id = str(new_repo.id)
    return new_repo

@router.get("/{repo_name}", response_model=Repository)
def read_repository(repo_name: str, db: Session = Depends(get_tenant_db)):
    """Get a specific repository by name."""
    repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    repo.id = str(repo.id)
    return repo
