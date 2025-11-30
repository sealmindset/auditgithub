from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from ..database import get_db
from .. import models
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

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
    api_id: int
    last_scanned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

@router.get("/", response_model=List[Repository])
def read_repositories(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all repositories."""
    repos = db.query(models.Repository).offset(skip).limit(limit).all()
    # Convert UUIDs to strings for Pydantic
    for repo in repos:
        repo.id = str(repo.id)
    return repos

@router.post("/", response_model=Repository)
def create_repository(repo: RepositoryCreate, db: Session = Depends(get_db)):
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
def read_repository(repo_name: str, db: Session = Depends(get_db)):
    """Get a specific repository by name."""
    repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    repo.id = str(repo.id)
    return repo
