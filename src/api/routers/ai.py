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

# Initialize Diagrams Index
from ..utils.diagrams_indexer import get_diagrams_index
diagrams_index = {}
try:
    diagrams_index = get_diagrams_index()
except Exception as e:
    logger.warning(f"Failed to initialize diagrams index: {e}")

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
        
    try:
        result = await ai_agent.triage_finding(
            title=request.title,
            description=request.description,
            severity=request.severity,
            scanner=request.scanner
        )
        return TriageResponse(
            priority=result.get("priority", "Medium"),
            confidence=result.get("confidence", 0.0),
            reasoning=result.get("reasoning", "Analysis failed"),
            false_positive_probability=result.get("false_positive_probability", 0.0)
        )
    except Exception as e:
        logger.error(f"Error triaging finding: {e}")
        raise HTTPException(status_code=500, detail=str(e))

from ..database import get_db
from .. import models
from sqlalchemy.orm import Session
from ..utils.repo_context import get_repo_context, clone_repo_to_temp, cleanup_repo
import uuid

import re

import subprocess
import base64
import os
import tempfile

class ArchitectureRequest(BaseModel):
    project_id: str

class ArchitectureUpdateRequest(BaseModel):
    report: str
    diagram: Optional[str] = None

class PromptRequest(BaseModel):
    project_id: str
    prompt: Optional[str] = None

@router.post("/architecture/prompt")
async def get_architecture_prompt(
    request: ArchitectureRequest,
    db: Session = Depends(get_db),
    settings: settings = Depends(lambda: settings)
):
    """Get the constructed architecture prompt for a project."""
    try:
        p_uuid = uuid.UUID(request.project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == request.project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if not project.url:
        raise HTTPException(status_code=400, detail="Project repository URL is missing")

    # Clone repo to temp dir to analyze structure
    try:
        # clone_repo_to_temp creates a new temp dir and returns the path
        temp_dir = clone_repo_to_temp(project.url, settings.GITHUB_TOKEN)
        
        try:
            # Analyze structure
            from ..utils.repo_context import get_repo_structure, get_config_files
            file_structure = get_repo_structure(temp_dir)
            config_files = get_config_files(temp_dir)
            
            # Build prompt
            from ...ai_agent.providers.openai import OpenAIProvider
            provider = OpenAIProvider(api_key=settings.OPENAI_API_KEY, model=settings.AI_MODEL)
            prompt = provider.build_architecture_prompt(project.name, file_structure, config_files, diagrams_index)
            
            return {"prompt": prompt}
        finally:
            cleanup_repo(temp_dir)
            
    except Exception as e:
        logger.error(f"Error building prompt: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/architecture/validate")
async def validate_architecture_prompt(
    request: PromptRequest,
    settings: settings = Depends(lambda: settings)
):
    """Execute a custom architecture prompt."""
    if not request.prompt:
        raise HTTPException(status_code=400, detail="Prompt is required")

    try:
        from ...ai_agent.providers.openai import OpenAIProvider
        provider = OpenAIProvider(api_key=settings.OPENAI_API_KEY, model=settings.AI_MODEL)
        response = await provider.execute_prompt(request.prompt)
        return {"response": response}
        
    except Exception as e:
        logger.error(f"Error validating prompt: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class RefineRequest(BaseModel):
    project_id: str
    code: str

@router.post("/architecture/refine")
async def refine_architecture_diagram(
    request: RefineRequest,
    settings: settings = Depends(lambda: settings)
):
    """Refine diagram code to use correct cloud provider icons."""
    if not request.code:
        raise HTTPException(status_code=400, detail="Code is required")

    try:
        from ...ai_agent.providers.openai import OpenAIProvider
        provider = OpenAIProvider(api_key=settings.OPENAI_API_KEY, model=settings.AI_MODEL)
        
        # We pass a specific "error" message that acts as the instruction
        instruction = "Refine this code to use the correct cloud provider icons based on the detected technology. Enforce the Cloud Provider Preference strictly."
        
        refined_code = await provider.fix_and_enhance_diagram_code(request.code, instruction, diagrams_index)
        
        # Clean up code block if present
        code_match = re.search(r"```python\n(.*?)```", refined_code, re.DOTALL)
        if code_match:
            refined_code = code_match.group(1).strip()
        else:
            refined_code = refined_code.replace("```python", "").replace("```", "").strip()
            
        return {"code": refined_code}
        
    except Exception as e:
        logger.error(f"Error refining diagram: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class ArchitectureResponse(BaseModel):
    report: str
    diagram: Optional[str] = None # Python code
    image: Optional[str] = None # Base64 PNG

@router.get("/architecture/{project_id}", response_model=ArchitectureResponse)
async def get_architecture(project_id: str, db: Session = Depends(get_db)):
    """Get saved architecture overview for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()
        
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # If we have code but no image (e.g. from old data or failed run), we could try to regen,
    # but for GET let's just return what we have.
    # Actually, we don't store the image in DB, so we need to generate it or store it.
    # Storing base64 in DB might be heavy.
    # Let's regenerate on the fly if missing? No, that's slow.
    # Let's assume we store the code, and maybe we should store the image too?
    # The user asked to "save their edits", implying code edits.
    # If we don't save the image, we have to run the code every time we view? That's slow and risky.
    # Let's add an `architecture_image` column to the DB?
    # Or just return the code and let the frontend trigger a generation if needed?
    # The requirement says "The Python script will then take that specs to create the diagram."
    # Let's stick to generating it on save/generate and returning it.
    # For now, if we don't have the image stored, we might return null and let the UI ask for regen?
    # Or better: let's execute the code if we have it.
    
    image_b64 = None
    if project.architecture_diagram:
        try:
            image_b64 = execute_diagram_code(project.architecture_diagram)
        except Exception as e:
            logger.error(f"Failed to generate image from saved code: {e}")

    return ArchitectureResponse(
        report=project.architecture_report or "",
        diagram=project.architecture_diagram,
        image=image_b64
    )

@router.put("/architecture/{project_id}", response_model=ArchitectureResponse)
async def update_architecture(project_id: str, request: ArchitectureUpdateRequest, db: Session = Depends(get_db)):
    """Update architecture overview (e.g. after user edits)."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()
        
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    project.architecture_report = request.report
    image_b64 = None
    
    if request.diagram is not None:
        project.architecture_diagram = request.diagram
        # Execute code to verify and generate image
        # Execute code to verify and generate image
        try:
            image_b64 = execute_diagram_code(request.diagram)
        except Exception as e:
            logger.warning(f"Updated diagram generation failed: {e}. Attempting auto-fix...")
            try:
                # Auto-fix
                from ...ai_agent.providers.openai import OpenAIProvider
                provider = OpenAIProvider(api_key=settings.OPENAI_API_KEY, model=settings.AI_MODEL)
                
                fixed_code = await provider.fix_and_enhance_diagram_code(request.diagram, str(e), diagrams_index)
                
                # Clean up code block if present
                code_match_fix = re.search(r"```python\n(.*?)```", fixed_code, re.DOTALL)
                if code_match_fix:
                    fixed_code = code_match_fix.group(1).strip()
                else:
                    fixed_code = fixed_code.replace("```python", "").replace("```", "").strip()
                    
                project.architecture_diagram = fixed_code
                image_b64 = execute_diagram_code(fixed_code)
                logger.info("Auto-fix successful")
            except Exception as fix_error:
                logger.error(f"Auto-fix failed: {fix_error}")
                # raise HTTPException(status_code=400, detail=f"Failed to generate diagram: {str(e)}")
        
    db.commit()
    
    return ArchitectureResponse(
        report=project.architecture_report,
        diagram=project.architecture_diagram,
        image=image_b64
    )

def execute_diagram_code(code: str) -> str:
    """Execute Python code to generate diagram and return base64 image."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write code to file
        script_path = os.path.join(tmpdir, "diagram_script.py")
        
        # Ensure the code saves to the right filename
        # We look for `filename="architecture_diagram"` or similar and enforce output path
        # Or we just run it and look for the .png file.
        # The prompt instructs `filename="architecture_diagram"`.
        # So we expect `architecture_diagram.png` in the CWD.
        
        with open(script_path, "w") as f:
            f.write(code)
            
        # Run script
        try:
            subprocess.check_output(
                ["python3", script_path],
                cwd=tmpdir,
                stderr=subprocess.STDOUT,
                timeout=30
            )
        except subprocess.CalledProcessError as e:
            raise Exception(f"Script execution failed: {e.output.decode()}")
            
        # Find PNG
        png_path = os.path.join(tmpdir, "architecture_diagram.png")
        if not os.path.exists(png_path):
             # Try finding any png
            files = [f for f in os.listdir(tmpdir) if f.endswith('.png')]
            if files:
                png_path = os.path.join(tmpdir, files[0])
            else:
                raise Exception("No PNG image generated by the script")
            
        with open(png_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")

@router.post("/architecture", response_model=ArchitectureResponse)
async def generate_architecture(request: ArchitectureRequest, db: Session = Depends(get_db)):
    """Generate an architecture overview for a project."""
    if not ai_agent:
        raise HTTPException(status_code=503, detail="AI Agent not initialized")
        
    # Get project
    try:
        p_uuid = uuid.UUID(request.project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == request.project_id).first()
        
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    if not project.url:
        raise HTTPException(status_code=400, detail="Project repository URL is missing")
        
    repo_path = None
    try:
        # Clone repo to temp
        # Use GITHUB_TOKEN from settings if available
        token = settings.GITHUB_TOKEN
        repo_path = clone_repo_to_temp(project.url, token)
        
        # Get context
        structure, configs = get_repo_context(repo_path)
        
        # Generate overview
        full_response = await ai_agent.generate_architecture_overview(
            repo_name=project.name,
            file_structure=structure,
            config_files=configs
        )
        
        # Parse Python code from response
        diagram_code = None
        report = full_response
        image_b64 = None
        
        code_match = re.search(r"```python\n(.*?)```", full_response, re.DOTALL)
        if code_match:
            diagram_code = code_match.group(1).strip()
            # Remove the code block from the report
            report = full_response.replace(code_match.group(0), "").strip()
            
            # Generate image
            # Generate image
            try:
                image_b64 = execute_diagram_code(diagram_code)
            except Exception as e:
                logger.warning(f"Initial diagram generation failed: {e}. Attempting auto-fix...")
                try:
                    # Auto-fix
                    from ...ai_agent.providers.openai import OpenAIProvider
                    provider = OpenAIProvider(api_key=settings.OPENAI_API_KEY, model=settings.AI_MODEL)
                    
                    fixed_code = await provider.fix_and_enhance_diagram_code(diagram_code, str(e), diagrams_index)
                    
                    # Clean up code block if present
                    code_match_fix = re.search(r"```python\n(.*?)```", fixed_code, re.DOTALL)
                    if code_match_fix:
                        fixed_code = code_match_fix.group(1).strip()
                    else:
                        fixed_code = fixed_code.replace("```python", "").replace("```", "").strip()
                        
                    diagram_code = fixed_code
                    image_b64 = execute_diagram_code(diagram_code)
                    logger.info("Auto-fix successful")
                except Exception as fix_error:
                    logger.error(f"Auto-fix failed: {fix_error}")
                    # We still save the code so user can fix it
            
        # Save to DB
        project.architecture_report = report
        project.architecture_diagram = diagram_code
        db.commit()
        
        return ArchitectureResponse(
            report=report,
            diagram=diagram_code,
            image=image_b64
        )
        
    except Exception as e:
        logger.error(f"Error generating architecture: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Cleanup
        if repo_path:
            cleanup_repo(repo_path)
