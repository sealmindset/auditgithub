from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from ..database import get_db
from .. import models
from pydantic import BaseModel
from datetime import datetime
import uuid

router = APIRouter(
    prefix="/findings",
    tags=["findings"]
)

class FindingResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    scanner_name: Optional[str]
    file_path: Optional[str]
    line_start: Optional[int]
    code_snippet: Optional[str]
    created_at: datetime
    repo_name: str

    class Config:
        orm_mode = True

@router.get("/", response_model=List[FindingResponse])
def get_findings(
    skip: int = 0, 
    limit: int = 100, 
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get all findings with optional filtering."""
    query = db.query(models.Finding)
    
    if severity:
        query = query.filter(models.Finding.severity == severity)
    
    if status:
        query = query.filter(models.Finding.status == status)
        
    findings = query.order_by(models.Finding.created_at.desc()).offset(skip).limit(limit).all()
    
    return [FindingResponse(
        id=str(f.finding_uuid),
        title=f.title,
        description=f.description,
        severity=f.severity,
        status=f.status,
        scanner_name=f.scanner_name,
        file_path=f.file_path,
        line_start=f.line_start,
        code_snippet=f.code_snippet,
        created_at=f.created_at,
        repo_name=f.repository.name if f.repository else "Unknown"
    ) for f in findings]

@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    """Get a specific finding by UUID."""
    # Try to parse UUID
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        # Fallback to check primary key id if finding_uuid fails (though model uses finding_uuid for public access usually)
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingResponse(
        id=str(finding.finding_uuid),
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        status=finding.status,
        scanner_name=finding.scanner_name,
        file_path=finding.file_path,
        line_start=finding.line_start,
        code_snippet=finding.code_snippet,
        created_at=finding.created_at,
        repo_name=finding.repository.name if finding.repository else "Unknown"
    )
