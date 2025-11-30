from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models
import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/integrations/jira",
    tags=["integrations"]
)

@router.post("/webhook")
async def jira_webhook(request: Request, db: Session = Depends(get_db)):
    """Handle incoming webhooks from Jira."""
    try:
        payload = await request.json()
        event = payload.get("webhookEvent")
        
        logger.info(f"Received Jira webhook: {event}")
        
        if event == "jira:issue_updated":
            issue = payload.get("issue", {})
            issue_key = issue.get("key")
            fields = issue.get("fields", {})
            status = fields.get("status", {}).get("name")
            
            # Find finding associated with this ticket
            finding = db.query(models.Finding).filter(
                models.Finding.jira_ticket_key == issue_key
            ).first()
            
            if finding:
                logger.info(f"Updating finding {finding.id} status to {status}")
                # Map Jira status to internal status
                # This logic would need to be customized based on Jira workflow
                if status.lower() in ["done", "resolved", "closed"]:
                    finding.status = "resolved"
                    finding.resolution = "fixed"
                elif status.lower() in ["in progress"]:
                    finding.status = "in_progress"
                
                db.commit()
                
        return {"status": "received"}
        
    except Exception as e:
        logger.error(f"Error processing Jira webhook: {e}")
        raise HTTPException(status_code=500, detail="Error processing webhook")
