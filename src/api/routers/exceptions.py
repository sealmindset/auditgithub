from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from ..database import get_db
from .. import models
from ...ai_agent.agent import AIAgent
import os
import uuid

router = APIRouter(
    prefix="/findings",
    tags=["exceptions"]
)

# Initialize AI Agent (singleton-ish)
ai_agent = AIAgent(
    openai_api_key=os.getenv("OPENAI_API_KEY"),
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
    provider=os.getenv("AI_PROVIDER", "openai"),
    model=os.getenv("AI_MODEL", "gpt-4o")
)

class ExceptionRequest(BaseModel):
    scope: str  # 'global' or 'specific'
    delete_finding: bool = False
    dry_run: bool = False

class ExceptionResponse(BaseModel):
    rule: Dict[str, Any]
    deleted_count: int
    status: str
    message: str

@router.post("/{finding_id}/exception", response_model=ExceptionResponse)
async def create_exception(
    finding_id: str,
    request: ExceptionRequest,
    db: Session = Depends(get_db)
):
    """
    Generate an exception rule and optionally delete matching findings.
    """
    # 1. Fetch Finding
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # 2. Generate Rule via AI Agent
    # Only generate rule if not just a dry run check for deletion? 
    # Actually, we might want to see the rule too.
    finding_dict = {
        "title": finding.title,
        "description": finding.description,
        "scanner_name": finding.scanner_name,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "code_snippet": finding.code_snippet,
        "severity": finding.severity
    }
    
    try:
        result = await ai_agent.generate_exception_rule(finding=finding_dict, scope=request.scope)
        rule = result.get("rule", {})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Agent failed: {str(e)}")

    deleted_count = 0
    message = "Exception rule generated."

    # 3. Handle Deletion (if requested)
    if request.delete_finding:
        query = db.query(models.Finding)
        
        # Safety Check Criteria
        if request.scope == "global":
            # Match: Scanner + File Path (exact)
            if finding.file_path:
                query = query.filter(
                    models.Finding.scanner_name == finding.scanner_name,
                    models.Finding.file_path == finding.file_path
                )
                message += " Matches all findings for this file and scanner."
            else:
                # If no file path, fallback to specific deletion to be safe
                query = query.filter(models.Finding.finding_uuid == uuid_obj)
                message += " (Global scope requires file path, fell back to specific deletion)."
                
        else:
            # Specific: Delete only this finding
            query = query.filter(models.Finding.finding_uuid == uuid_obj)
            message += " Matches this specific finding."

        # Count matches
        findings_to_delete = query.all()
        deleted_count = len(findings_to_delete)
        
        if not request.dry_run:
            for f in findings_to_delete:
                db.delete(f)
            db.commit()
            message = message.replace("Matches", "Deleted")
        else:
            message = f"Dry Run: Would delete {deleted_count} finding(s)."

    return ExceptionResponse(
        rule=rule,
        deleted_count=deleted_count,
        status="success" if not request.dry_run else "dry_run",
        message=message
    )
