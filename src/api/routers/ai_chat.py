"""
AI Chat API Routes
Handles AI conversation endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, Field
from ..database import get_db
from src.services.ai_chat_service import AIChatService
from models.ai_conversation import AIConversation, AIMessage, MessageRole
import logging

# Mock authentication for now - replace with actual auth
def get_current_user():
    class MockUser:
        # Using sleepnumberlabs organization UUID from database
        organization_id = UUID('b8afdd8e-56e0-4dce-8331-d7964c707fc8')
    return MockUser()

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api",
    tags=["ai-chat"]
)


class ChatMessageRequest(BaseModel):
    """Request model for sending a chat message"""
    conversation_id: Optional[str] = Field(None, description="Existing conversation ID (null for new)")
    message: str = Field(..., min_length=1, max_length=10000, description="User message")
    context: Optional[dict] = Field(None, description="Additional context from frontend")
    focus: str = Field("security_architecture", description="Conversation focus")


class CitationResponse(BaseModel):
    """Response model for citation"""
    id: str
    type: str
    source: str
    reference: str
    excerpt: Optional[str] = None
    url: Optional[str] = None


class ChatMessageResponse(BaseModel):
    """Response model for chat message"""
    conversation_id: str
    message_id: str
    content: str
    thinking: Optional[str] = None
    needs_clarification: bool = False
    clarification_question: Optional[str] = None
    citations: List[CitationResponse] = []
    timestamp: str
    web_search_performed: bool = False


class ConversationHistoryResponse(BaseModel):
    """Response model for conversation history"""
    id: str
    title: str
    focus: str
    message_count: int
    created_at: str
    updated_at: str
    last_message_at: Optional[str] = None


class MessageHistoryResponse(BaseModel):
    """Response model for message in history"""
    id: str
    role: str
    content: str
    timestamp: str
    citations: List[CitationResponse] = []
    needs_clarification: bool = False


@router.post(
    "/projects/{project_id}/repositories/{repository_id}/ai-chat",
    response_model=ChatMessageResponse,
    summary="Send message to AI assistant",
    description="Send a message to the AI security architect and get a response with context-aware analysis"
)
async def send_ai_message(
    project_id: int,
    repository_id: UUID,
    request: ChatMessageRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Send a message to the AI security architect

    The AI will analyze your question with context from:
    - Repository code and structure
    - Scan results and vulnerability reports
    - Technical architecture overview
    - External security research (when needed)

    Focus areas:
    - security_architecture: General security architecture and design
    - zero_trust: Zero-trust architecture principles
    - vulnerabilities: Specific vulnerability analysis
    """
    try:
        # Get organization ID from current user
        organization_id = current_user.organization_id

        # Initialize AI chat service
        chat_service = AIChatService(db)

        # Process the message
        response = await chat_service.process_message(
            project_id=project_id,
            repository_id=repository_id,
            organization_id=organization_id,
            conversation_id=request.conversation_id,
            user_message=request.message,
            context=request.context,
            focus=request.focus,
        )

        return ChatMessageResponse(**response)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error in AI chat: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process AI message"
        )


@router.get(
    "/projects/{project_id}/repositories/{repository_id}/ai-conversations",
    response_model=List[ConversationHistoryResponse],
    summary="Get conversation history",
    description="Get list of AI conversations for this repository"
)
async def get_conversations(
    project_id: int,
    repository_id: UUID,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get list of AI conversations for this repository"""
    try:
        conversations = (
            db.query(AIConversation)
            .filter(
                AIConversation.project_id == project_id,
                AIConversation.repository_id == repository_id,
                AIConversation.organization_id == current_user.organization_id
            )
            .order_by(AIConversation.last_message_at.desc())
            .limit(limit)
            .all()
        )

        return [
            ConversationHistoryResponse(
                id=conv.conversation_id,
                title=conv.title or "Untitled Conversation",
                focus=conv.focus or "general",
                message_count=conv.message_count,
                created_at=conv.created_at.isoformat(),
                updated_at=conv.updated_at.isoformat(),
                last_message_at=conv.last_message_at.isoformat() if conv.last_message_at else None,
            )
            for conv in conversations
        ]

    except Exception as e:
        logger.error(f"Error getting conversations: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch conversations"
        )


@router.get(
    "/projects/{project_id}/repositories/{repository_id}/ai-conversations/{conversation_id}",
    response_model=List[MessageHistoryResponse],
    summary="Get conversation messages",
    description="Get all messages in a conversation"
)
async def get_conversation_messages(
    project_id: int,
    repository_id: UUID,
    conversation_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get all messages in a conversation"""
    try:
        # Verify conversation exists and belongs to user's organization
        conversation = (
            db.query(AIConversation)
            .filter(
                AIConversation.conversation_id == conversation_id,
                AIConversation.project_id == project_id,
                AIConversation.repository_id == repository_id,
                AIConversation.organization_id == current_user.organization_id
            )
            .first()
        )

        if not conversation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Conversation not found"
            )

        # Get messages
        messages = (
            db.query(AIMessage)
            .filter(AIMessage.conversation_id == conversation.id)
            .order_by(AIMessage.created_at.asc())
            .all()
        )

        result = []
        for msg in messages:
            citations = [
                CitationResponse(
                    id=cit.citation_id,
                    type=cit.type.value,
                    source=cit.source,
                    reference=cit.reference,
                    excerpt=cit.excerpt,
                    url=cit.url,
                )
                for cit in msg.citations
            ]

            result.append(
                MessageHistoryResponse(
                    id=msg.message_id,
                    role=msg.role.value,
                    content=msg.content,
                    timestamp=msg.created_at.isoformat(),
                    citations=citations,
                    needs_clarification=msg.needs_clarification or False,
                )
            )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting conversation messages: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch messages"
        )


@router.delete(
    "/projects/{project_id}/repositories/{repository_id}/ai-conversations/{conversation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete conversation",
    description="Delete an AI conversation and all its messages"
)
async def delete_conversation(
    project_id: int,
    repository_id: UUID,
    conversation_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete an AI conversation"""
    try:
        conversation = (
            db.query(AIConversation)
            .filter(
                AIConversation.conversation_id == conversation_id,
                AIConversation.project_id == project_id,
                AIConversation.repository_id == repository_id,
                AIConversation.organization_id == current_user.organization_id
            )
            .first()
        )

        if not conversation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Conversation not found"
            )

        db.delete(conversation)
        db.commit()

        return None

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting conversation: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete conversation"
        )


@router.get(
    "/projects/{project_id}/repositories/{repository_id}/ai-context",
    summary="Get AI context summary",
    description="Get a summary of the context available for AI conversations"
)
async def get_ai_context_summary(
    project_id: int,
    repository_id: UUID,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get summary of available context for AI"""
    try:
        from services.ai_rag_service import AIRAGService

        rag_service = AIRAGService(db)
        context = await rag_service.gather_context(project_id, repository_id)

        # Return summary only
        return {
            "repository": context.get("repository", {}).get("name"),
            "has_technical_overview": context.get("technical_overview") is not None,
            "scan_results_count": len(context.get("scan_results", [])),
            "vulnerabilities_count": len(context.get("vulnerabilities", [])),
            "findings_count": len(context.get("findings", [])),
            "security_score": context.get("security_metrics", {}).get("security_score"),
        }

    except Exception as e:
        logger.error(f"Error getting AI context summary: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get context summary"
        )
