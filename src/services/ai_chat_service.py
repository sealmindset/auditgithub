"""
AI Chat Service
Handles AI conversations using Claude API with RAG context
"""

import logging
import os
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
import anthropic
from .ai_rag_service import AIRAGService
from models.ai_conversation import (
    AIConversation,
    AIMessage,
    AICitation,
    MessageRole,
    CitationType,
)
import json
import re

logger = logging.getLogger(__name__)


class AIChatService:
    """Service for AI-powered conversations"""

    def __init__(self, db: Session):
        self.db = db
        self.rag_service = AIRAGService(db)
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        # System prompt for security architecture focus
        self.system_prompt = """You are an expert security architect and zero-trust architecture specialist. Your role is to help users understand and improve the security posture of their software projects.

## Your Capabilities:
- Deep analysis of code architecture and security patterns
- Zero-trust architecture principles and implementation guidance
- Vulnerability assessment and remediation recommendations
- Security best practices across multiple technologies
- OWASP Top 10 and CWE knowledge
- Secure-by-design principles

## Critical Rules:
1. **NO HALLUCINATIONS**: Only provide information based on the provided context or well-established security principles. If you don't have enough information, explicitly state what's missing.
2. **CITE SOURCES**: Always reference specific findings, vulnerabilities, or scan results when making claims.
3. **ASK FOR CLARIFICATION**: If the user's question is ambiguous, ask clarifying questions before providing an answer.
4. **ZERO-TRUST FOCUS**: When discussing architecture, emphasize zero-trust principles: verify explicitly, use least privilege access, assume breach.
5. **ACTIONABLE ADVICE**: Provide specific, actionable recommendations, not generic advice.
6. **WEB SEARCH**: If the context doesn't contain sufficient information and the answer requires current/external data (like CVE details, latest security advisories), indicate that you need to perform web research.

## Response Format:
- Start with a direct answer to the question
- Provide evidence from the context (cite specific findings, vulnerabilities, code locations)
- If making recommendations, explain the security rationale
- If uncertain, explain what additional information would help

## When to Request Web Search:
- Current CVE details not in the context
- Latest security advisories or patches
- Emerging attack patterns
- Vendor-specific security documentation
- Compliance framework details

Remember: Your goal is to help improve security, not just describe problems. Be constructive, specific, and always grounded in evidence."""

    async def process_message(
        self,
        project_id: int,
        repository_id: int,
        organization_id: int,
        conversation_id: Optional[str],
        user_message: str,
        context: Optional[Dict[str, Any]] = None,
        focus: str = "security_architecture",
    ) -> Dict[str, Any]:
        """
        Process a user message and generate AI response

        Args:
            project_id: Project ID
            repository_id: Repository ID
            organization_id: Organization ID
            conversation_id: Existing conversation ID (None for new conversation)
            user_message: User's message
            context: Additional context provided by frontend
            focus: Conversation focus

        Returns:
            Dictionary with response data
        """
        try:
            # Get or create conversation
            if conversation_id:
                conversation = await self._get_conversation(conversation_id)
            else:
                conversation = await self._create_conversation(
                    project_id, repository_id, organization_id, user_message, focus
                )
                conversation_id = conversation.conversation_id

            # Save user message
            user_msg = await self._save_message(
                conversation.id, MessageRole.USER, user_message
            )

            # Gather RAG context
            rag_context = await self.rag_service.gather_context(
                project_id, repository_id, focus
            )

            # Merge with provided context
            if context:
                rag_context.update(context)

            # Get conversation history
            history = await self._get_conversation_history(conversation.id)

            # Check if web search is needed
            needs_web_search = await self._check_needs_web_search(user_message, rag_context)

            # Perform web search if needed
            web_search_results = []
            if needs_web_search:
                web_search_results = await self._perform_web_search(user_message)
                rag_context["web_search_results"] = web_search_results

            # Generate AI response
            ai_response = await self._generate_response(
                user_message,
                rag_context,
                history,
                conversation.focus
            )

            # Extract citations from response
            citations = self._extract_citations(ai_response, rag_context, web_search_results)

            # Save assistant message
            assistant_msg = await self._save_message(
                conversation.id,
                MessageRole.ASSISTANT,
                ai_response["content"],
                thinking=ai_response.get("thinking"),
                needs_clarification=ai_response.get("needs_clarification", False),
                clarification_question=ai_response.get("clarification_question"),
                context_used=ai_response.get("context_used", []),
                tokens_used=ai_response.get("tokens_used"),
                confidence_score=ai_response.get("confidence_score"),
                web_search_performed=needs_web_search,
            )

            # Save citations
            for citation_data in citations:
                await self._save_citation(assistant_msg.id, citation_data)

            # Update conversation
            conversation.message_count += 2  # User + assistant
            conversation.last_message_at = datetime.utcnow()
            self.db.commit()

            return {
                "conversation_id": conversation.conversation_id,
                "message_id": assistant_msg.message_id,
                "content": ai_response["content"],
                "thinking": ai_response.get("thinking"),
                "needs_clarification": ai_response.get("needs_clarification", False),
                "clarification_question": ai_response.get("clarification_question"),
                "citations": citations,
                "timestamp": assistant_msg.created_at.isoformat(),
                "web_search_performed": needs_web_search,
            }

        except Exception as e:
            logger.error(f"Error processing AI message: {e}", exc_info=True)
            raise

    async def _create_conversation(
        self,
        project_id: int,
        repository_id: int,
        organization_id: int,
        first_message: str,
        focus: str,
    ) -> AIConversation:
        """Create a new conversation"""
        # Generate title from first message (first 100 chars)
        title = first_message[:100] + ("..." if len(first_message) > 100 else "")

        conversation = AIConversation(
            conversation_id=str(uuid.uuid4()),
            project_id=project_id,
            repository_id=repository_id,
            organization_id=organization_id,
            title=title,
            focus=focus,
        )
        self.db.add(conversation)
        self.db.commit()
        self.db.refresh(conversation)

        return conversation

    async def _get_conversation(self, conversation_id: str) -> AIConversation:
        """Get existing conversation"""
        conversation = (
            self.db.query(AIConversation)
            .filter(AIConversation.conversation_id == conversation_id)
            .first()
        )
        if not conversation:
            raise ValueError(f"Conversation {conversation_id} not found")
        return conversation

    async def _save_message(
        self,
        conversation_id: int,
        role: MessageRole,
        content: str,
        thinking: Optional[str] = None,
        needs_clarification: bool = False,
        clarification_question: Optional[str] = None,
        context_used: Optional[List[str]] = None,
        tokens_used: Optional[int] = None,
        confidence_score: Optional[int] = None,
        web_search_performed: bool = False,
    ) -> AIMessage:
        """Save a message to the database"""
        message = AIMessage(
            message_id=str(uuid.uuid4()),
            conversation_id=conversation_id,
            role=role,
            content=content,
            thinking=thinking,
            needs_clarification=needs_clarification,
            clarification_question=clarification_question,
            context_used=context_used,
            tokens_used=tokens_used,
            confidence_score=confidence_score,
            web_search_performed=web_search_performed,
        )
        self.db.add(message)
        self.db.commit()
        self.db.refresh(message)

        return message

    async def _save_citation(self, message_id: int, citation_data: Dict[str, Any]) -> AICitation:
        """Save a citation"""
        citation = AICitation(
            citation_id=str(uuid.uuid4()),
            message_id=message_id,
            type=CitationType(citation_data["type"]),
            source=citation_data["source"],
            reference=citation_data["reference"],
            excerpt=citation_data.get("excerpt"),
            url=citation_data.get("url"),
            relevance_score=citation_data.get("relevance_score"),
        )
        self.db.add(citation)
        self.db.commit()

        return citation

    async def _get_conversation_history(
        self, conversation_id: int, limit: int = 20
    ) -> List[Dict[str, str]]:
        """Get recent conversation history for context"""
        messages = (
            self.db.query(AIMessage)
            .filter(AIMessage.conversation_id == conversation_id)
            .order_by(AIMessage.created_at.desc())
            .limit(limit)
            .all()
        )

        # Reverse to get chronological order
        messages.reverse()

        history = []
        for msg in messages:
            history.append({
                "role": msg.role.value,
                "content": msg.content,
            })

        return history

    async def _check_needs_web_search(self, message: str, context: Dict[str, Any]) -> bool:
        """Determine if web search is needed to answer the question"""
        # Keywords that suggest external research is needed
        external_keywords = [
            "latest", "recent", "current", "new", "cve-", "advisory",
            "patch", "update", "release", "vendor", "official",
            "documentation", "owasp", "nist", "compliance"
        ]

        message_lower = message.lower()
        needs_search = any(keyword in message_lower for keyword in external_keywords)

        # Also check if context is insufficient
        if context.get("vulnerabilities", []) and any("cve-" in message_lower for _ in range(1)):
            # User asking about specific CVE - might need latest info
            needs_search = True

        return needs_search

    async def _perform_web_search(self, query: str) -> List[Dict[str, Any]]:
        """
        Perform web search for external information
        This is a placeholder - you would integrate with a web search API
        """
        logger.info(f"Performing web search for: {query}")

        # TODO: Integrate with web search API (e.g., Brave Search, Google Custom Search)
        # For now, returning empty list
        return []

    async def _generate_response(
        self,
        user_message: str,
        context: Dict[str, Any],
        history: List[Dict[str, str]],
        focus: str,
    ) -> Dict[str, Any]:
        """Generate AI response using Claude API"""

        # Build context string
        context_str = self._format_context(context)

        # Build messages for Claude
        messages = []

        # Add conversation history (excluding system messages)
        for msg in history:
            if msg["role"] != "system":
                messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })

        # Add current user message with context
        current_message = f"""User Question: {user_message}

## Available Context:
{context_str}

Please analyze the question and provide a detailed, accurate response based on the context provided. If the context is insufficient, clearly state what information is missing. Focus on {focus} and zero-trust architecture principles."""

        messages.append({
            "role": "user",
            "content": current_message
        })

        try:
            # Call Claude API
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4096,
                temperature=0.3,  # Lower temperature for more focused, accurate responses
                system=self.system_prompt,
                messages=messages
            )

            content = response.content[0].text
            tokens_used = response.usage.input_tokens + response.usage.output_tokens

            # Check if response indicates need for clarification
            needs_clarification = "need clarification" in content.lower() or "unclear" in content.lower()
            clarification_question = None

            if needs_clarification:
                # Extract clarification question if present
                clarification_match = re.search(r"(?:Could you clarify|Please clarify|Can you specify)([^?]+\?)", content, re.IGNORECASE)
                if clarification_match:
                    clarification_question = clarification_match.group(0)

            # Estimate confidence based on response characteristics
            confidence_score = self._estimate_confidence(content, context)

            return {
                "content": content,
                "tokens_used": tokens_used,
                "needs_clarification": needs_clarification,
                "clarification_question": clarification_question,
                "confidence_score": confidence_score,
                "context_used": list(context.keys()),
            }

        except anthropic.APIError as e:
            logger.error(f"Claude API error: {e}", exc_info=True)
            raise

    def _format_context(self, context: Dict[str, Any]) -> str:
        """Format context for inclusion in prompt"""
        sections = []

        # Repository info
        if "repository" in context and context["repository"]:
            repo = context["repository"]
            sections.append(f"""### Repository Information
- Name: {repo.get('name', 'N/A')}
- Language: {repo.get('language', 'N/A')}
- Description: {repo.get('description', 'N/A')}
- Size: {repo.get('size', 'N/A')} bytes""")

        # Technical overview
        if "technical_overview" in context and context["technical_overview"]:
            sections.append(f"""### AI-Generated Technical Overview
{context['technical_overview']}""")

        # Security metrics
        if "security_metrics" in context:
            metrics = context["security_metrics"]
            sections.append(f"""### Security Metrics
- Security Score: {metrics.get('security_score', 'N/A')}/100
- Critical Issues: {metrics.get('total_critical', 0)}
- High Severity: {metrics.get('total_high', 0)}
- Medium Severity: {metrics.get('total_medium', 0)}
- Low Severity: {metrics.get('total_low', 0)}""")

        # Vulnerabilities (summarized)
        if "vulnerabilities" in context and context["vulnerabilities"]:
            vulns = context["vulnerabilities"][:10]  # Top 10
            sections.append(f"""### Recent Vulnerabilities (Top 10)
{self._format_vulnerabilities(vulns)}""")

        # Findings (summarized)
        if "findings" in context and context["findings"]:
            findings = context["findings"][:10]  # Top 10
            sections.append(f"""### Security Findings (Top 10)
{self._format_findings(findings)}""")

        # Architecture patterns
        if "architecture_patterns" in context:
            patterns = context["architecture_patterns"]
            sections.append(f"""### Architecture Patterns Detected
{json.dumps(patterns, indent=2)}""")

        # Zero-trust analysis
        if "zero_trust_analysis" in context:
            zt = context["zero_trust_analysis"]
            sections.append(f"""### Zero-Trust Architecture Analysis
{json.dumps(zt, indent=2)}""")

        # Web search results
        if "web_search_results" in context and context["web_search_results"]:
            sections.append(f"""### External Research Results
{self._format_web_results(context["web_search_results"])}""")

        return "\n\n".join(sections)

    def _format_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format vulnerabilities for context"""
        lines = []
        for vuln in vulnerabilities:
            lines.append(f"- [{vuln['severity'].upper()}] {vuln['title']}")
            if vuln.get('cve_id'):
                lines.append(f"  CVE: {vuln['cve_id']}")
            if vuln.get('description'):
                lines.append(f"  {vuln['description'][:200]}...")
        return "\n".join(lines)

    def _format_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings for context"""
        lines = []
        for finding in findings:
            lines.append(f"- [{finding['severity'].upper()}] {finding['title']}")
            if finding.get('file_path'):
                lines.append(f"  Location: {finding['file_path']}:{finding.get('line_number', '?')}")
        return "\n".join(lines)

    def _format_web_results(self, results: List[Dict[str, Any]]) -> str:
        """Format web search results"""
        lines = []
        for result in results:
            lines.append(f"- {result.get('title', 'No title')}")
            lines.append(f"  {result.get('snippet', '')}")
            if result.get('url'):
                lines.append(f"  URL: {result['url']}")
        return "\n".join(lines)

    def _estimate_confidence(self, response: str, context: Dict[str, Any]) -> int:
        """Estimate confidence score for the response"""
        confidence = 70  # Base confidence

        # Increase confidence if response has specific citations
        if "scan" in response.lower() or "finding" in response.lower():
            confidence += 10

        # Increase if context has relevant data
        if context.get("vulnerabilities") or context.get("findings"):
            confidence += 10

        # Decrease if response has uncertainty markers
        uncertainty_markers = ["might", "possibly", "unclear", "insufficient", "may", "could"]
        if any(marker in response.lower() for marker in uncertainty_markers):
            confidence -= 20

        # Cap at 0-100
        return max(0, min(100, confidence))

    def _extract_citations(
        self,
        response: Dict[str, Any],
        context: Dict[str, Any],
        web_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Extract citations from the response based on context references"""
        citations = []
        content = response["content"]

        # Look for vulnerability references
        if context.get("vulnerabilities"):
            for vuln in context["vulnerabilities"]:
                if vuln["title"].lower() in content.lower() or (vuln.get("cve_id") and vuln["cve_id"] in content):
                    citations.append({
                        "id": str(uuid.uuid4()),
                        "type": "vulnerability",
                        "source": "Vulnerability Scan",
                        "reference": vuln.get("cve_id") or vuln["title"],
                        "excerpt": vuln.get("description", "")[:200],
                        "relevance_score": 90,
                    })

        # Look for finding references
        if context.get("findings"):
            for finding in context["findings"][:5]:  # Top 5 findings
                if finding["title"].lower() in content.lower():
                    citations.append({
                        "id": str(uuid.uuid4()),
                        "type": "scan_result",
                        "source": "Security Scan",
                        "reference": f"{finding.get('file_path', 'Unknown')}:{finding.get('line_number', '?')}",
                        "excerpt": finding.get("description", "")[:200],
                        "relevance_score": 85,
                    })

        # Look for web search references
        for result in web_results:
            if result.get("title") and result["title"].lower() in content.lower():
                citations.append({
                    "id": str(uuid.uuid4()),
                    "type": "web",
                    "source": "Web Research",
                    "reference": result.get("title", "External Source"),
                    "excerpt": result.get("snippet", ""),
                    "url": result.get("url"),
                    "relevance_score": 75,
                })

        return citations
