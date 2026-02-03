# Ask AI Security Architect - Setup Guide

## Quick Setup

### 1. Set Environment Variable

Add your Anthropic API key to your environment:

```bash
export ANTHROPIC_API_KEY="your-claude-api-key-here"
```

Or add to your `.env` file:
```
ANTHROPIC_API_KEY=your-claude-api-key-here
```

### 2. Run Database Migration

```bash
cd /path/to/auditgithub
alembic upgrade head
```

This creates the required tables:
- `ai_conversations`
- `ai_messages`
- `ai_citations`

### 3. Install Python Dependencies

```bash
pip install anthropic
```

### 4. Restart API Server

```bash
# If using Docker
docker-compose restart api

# If running locally
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

## Testing the Feature

### 1. Access the UI

1. Navigate to **Repositories** → **Projects** → Select a project
2. Go to **Architecture** tab
3. Click **"Generate Architecture"** if no report exists
4. Switch to **Report** tab
5. Click the **"Ask AI Security Architect"** button (purple/blue gradient)

### 2. Try Sample Questions

**Zero-Trust Architecture:**
- "Is this codebase following zero-trust principles?"
- "What are the gaps in our zero-trust implementation?"
- "How can we improve authentication and authorization?"

**Security Analysis:**
- "What are the most critical security issues?"
- "Are there any SQL injection vulnerabilities?"
- "Is sensitive data properly encrypted?"

**Vulnerability Assessment:**
- "Explain CVE-2024-XXXXX and how it affects us"
- "What's the remediation priority for our vulnerabilities?"
- "Which findings should we fix first?"

### 3. Check Logs

If you get errors, check the API logs:

```bash
# Docker
docker-compose logs -f api

# Local
# Check terminal where uvicorn is running
```

## Troubleshooting

### Error: "Failed to get AI response"

**Check 1: API Key**
```bash
echo $ANTHROPIC_API_KEY
# Should show your API key
```

**Check 2: API Server Running**
```bash
curl http://localhost:8000/health
# Should return: {"status": "healthy"}
```

**Check 3: Database Migration**
```bash
# Check if tables exist
psql -U postgres -d auditgithub -c "\dt ai_*"
# Should show: ai_conversations, ai_messages, ai_citations
```

**Check 4: API Endpoint**
```bash
curl -X POST http://localhost:8000/api/projects/1/repositories/1/ai-chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Test message",
    "focus": "security_architecture"
  }'
```

### Error: "Module not found"

Make sure imports are correct:
- Models should be in `models/` directory
- Services should be in `src/services/` directory

### Modal Not Scrolling

This has been fixed in commit `1a833fe`. Make sure you have the latest version:

```bash
git pull origin main
```

### Citations Not Showing

Citations are automatically extracted when the AI references:
- Specific vulnerabilities (CVE IDs)
- Security findings
- Scan results
- Web sources

If no citations appear, the AI may not have referenced specific sources in its response.

## Architecture Overview

```
Frontend (React/TypeScript)
    ↓
    AskAIModal.tsx
    ↓
    HTTP POST /api/projects/{id}/repositories/{id}/ai-chat
    ↓
Backend (FastAPI)
    ↓
    ai_chat.py (router)
    ↓
    AIChatService
    ├─→ AIRAGService (gathers context)
    │   ├─ Repository data
    │   ├─ Scan results
    │   ├─ Vulnerabilities
    │   ├─ Findings
    │   └─ Security metrics
    │
    └─→ Claude API (Anthropic)
        └─ Returns AI response with citations
    ↓
Database (PostgreSQL)
    ├─ ai_conversations
    ├─ ai_messages
    └─ ai_citations
```

## Features

### Anti-Hallucination Safeguards
- ✅ Citation required for every claim
- ✅ Explicit admission when information is missing
- ✅ Clarification requests for ambiguous questions
- ✅ Web research indicator
- ✅ Confidence scoring (0-100)

### Zero-Trust Focus
- ✅ Always verify principle analysis
- ✅ Least privilege assessment
- ✅ Assume breach posture
- ✅ Authentication coverage estimation
- ✅ Authorization gap detection

### RAG Context
- ✅ Repository metadata
- ✅ Technical architecture overview
- ✅ Scan results (SAST, DAST, SCA)
- ✅ Vulnerabilities (CVE/CWE)
- ✅ Security findings by severity
- ✅ Security metrics and scoring
- ✅ Architecture pattern analysis

## Configuration

### Adjust Token Limit

In `src/services/ai_rag_service.py`:

```python
async def gather_context(
    self,
    project_id: int,
    repository_id: int,
    focus: str = "security_architecture",
    max_tokens: int = 50000  # <-- Adjust this
) -> Dict[str, Any]:
```

### Adjust AI Temperature

In `src/services/ai_chat_service.py`:

```python
response = self.client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=4096,
    temperature=0.3,  # <-- Adjust this (0.0-1.0)
    system=self.system_prompt,
    messages=messages
)
```

Lower temperature = more focused/deterministic
Higher temperature = more creative/varied

### Change AI Model

```python
response = self.client.messages.create(
    model="claude-3-5-sonnet-20241022",  # <-- Change model here
    # Options:
    # - claude-3-5-sonnet-20241022 (recommended)
    # - claude-3-opus-20240229 (most capable, slower)
    # - claude-3-haiku-20240307 (fastest, less capable)
    ...
)
```

## API Reference

### Send Message

```http
POST /api/projects/{project_id}/repositories/{repository_id}/ai-chat
Content-Type: application/json

{
  "conversation_id": "uuid-string-or-null",
  "message": "Your question here",
  "context": {
    "technicalOverview": "...",
    "scanResults": [...],
    "vulnerabilities": [...]
  },
  "focus": "security_architecture"
}
```

**Response:**
```json
{
  "conversation_id": "uuid",
  "message_id": "uuid",
  "content": "AI response here...",
  "thinking": "Optional internal reasoning",
  "needs_clarification": false,
  "clarification_question": null,
  "citations": [
    {
      "id": "uuid",
      "type": "vulnerability",
      "source": "CVE-2024-1234",
      "reference": "SQL Injection vulnerability",
      "excerpt": "...",
      "url": "https://..."
    }
  ],
  "timestamp": "2024-02-03T12:34:56Z",
  "web_search_performed": false
}
```

### Get Conversations

```http
GET /api/projects/{project_id}/repositories/{repository_id}/ai-conversations
```

### Get Conversation Messages

```http
GET /api/projects/{project_id}/repositories/{repository_id}/ai-conversations/{conversation_id}
```

### Delete Conversation

```http
DELETE /api/projects/{project_id}/repositories/{repository_id}/ai-conversations/{conversation_id}
```

## Next Steps

1. **Integrate Authentication**: Replace mock `get_current_user()` with actual auth
2. **Add Web Search**: Integrate Brave/Google Custom Search API
3. **Add Embeddings**: Use vector search for semantic code search
4. **Export Conversations**: Add download as markdown/PDF
5. **Voice Input**: Add speech-to-text support
6. **Suggested Questions**: Pre-populate common queries

## Support

For issues or questions:
- Check API logs: `docker-compose logs -f api`
- Check browser console for frontend errors
- Verify ANTHROPIC_API_KEY is set
- Ensure database migration ran successfully
- Test with curl commands above

## License

Same as parent project (AuditGitHub)
