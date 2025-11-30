from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any
import logging
from ..config import settings
from ...ai_agent.agent import AIAgent

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/ai",
    tags=["ai"]
)

# Initialize AI Agent
# In a real app, this might be a dependency to allow for mocking/lazy loading
try:
    ai_agent = AIAgent(
        openai_api_key=settings.OPENAI_API_KEY,
        anthropic_api_key=settings.ANTHROPIC_API_KEY,
        provider=settings.AI_PROVIDER,
        model=settings.AI_MODEL
    )
except Exception as e:
    logger.warning(f"Failed to initialize AI Agent: {e}")
    ai_agent = None

class RemediationRequest(BaseModel):
    vuln_type: str
    description: str
    context: str
    language: str

class RemediationResponse(BaseModel):
    remediation: str
    diff: str

@router.post("/remediate", response_model=RemediationResponse)
async def generate_remediation(request: RemediationRequest):
    """Generate remediation for a vulnerability."""
    if not ai_agent:
        raise HTTPException(status_code=503, detail="AI Agent not initialized")
    
    try:
        result = await ai_agent.generate_remediation(
            vuln_type=request.vuln_type,
            description=request.description,
            context=request.context,
            language=request.language
        )
        return RemediationResponse(
            remediation=result.get("remediation", ""),
            diff=result.get("diff", "")
        )
    except Exception as e:
        logger.error(f"Error generating remediation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class TriageRequest(BaseModel):
    title: str
    description: str
    severity: str
    scanner: str

class TriageResponse(BaseModel):
    priority: str
    confidence: float
    reasoning: str
    false_positive_probability: float

@router.post("/triage", response_model=TriageResponse)
async def triage_finding(request: TriageRequest):
    """Analyze and triage a finding."""
    if not ai_agent:
        raise HTTPException(status_code=503, detail="AI Agent not initialized")
        
    # This would delegate to a new method in AIAgent/ReasoningEngine
    # For now, we'll implement a basic version or placeholder
    # TODO: Implement full triage logic in ReasoningEngine
    
    return TriageResponse(
        priority="High",
        confidence=0.85,
        reasoning="AI Analysis not fully implemented yet.",
        false_positive_probability=0.1
    )
