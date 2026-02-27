# Fix Findings Directive

## Purpose
Enable analysts to use AI-powered security analysis on findings and optionally save the analysis to the finding's description in the database for future reference.

## Current Implementation (December 2024)

### Features

| Feature | Description |
|---------|-------------|
| **Ask AI Button** | Triggers AI security analysis from Finding Details page |
| **Auto-Start Analysis** | Analysis automatically begins when dialog opens |
| **Update Description** | Save AI analysis to finding's description in database |
| **Conversation Mode** | Follow-up questions with NLP revision detection |
| **Version History** | Full versioning with restore capability |
| **Pro Tips** | Helpful guidance via lightbulb popover |

### Architecture

```
Frontend (Next.js)                    Backend (FastAPI)
─────────────────                    ─────────────────
AskAIDialog.tsx                      src/api/routers/ai.py
    │                                    │
    ├─► POST /ai/analyze-finding ───────►│ analyze_finding_endpoint()
    │                                    │
    ├─► PATCH /findings/{id} ───────────►│ update_finding() [findings.py]
    │                                    │
    └─► GET /findings/{id}/versions ────►│ get_finding_versions() [findings.py]
```

### File Locations

| Component | Path |
|-----------|------|
| **Ask AI Dialog** | `src/web-ui/components/AskAIDialog.tsx` |
| **Finding Details Page** | `src/web-ui/app/findings/[id]/page.tsx` |
| **All Findings Page** | `src/web-ui/app/findings/page.tsx` |
| **AI Router** | `src/api/routers/ai.py` |
| **Findings Router** | `src/api/routers/findings.py` |
| **Finding Model** | `src/api/models.py` → `Finding`, `FindingHistory` |

---

## API Endpoints

### POST `/ai/analyze-finding`

Triggers AI analysis of a finding.

**Request:**
```json
{
  "finding_id": "uuid-string",
  "prompt": "Optional follow-up question"
}
```

**Response:**
```json
{
  "analysis": "AI-generated security analysis markdown..."
}
```

### PATCH `/findings/{finding_id}`

Updates a finding's description (saves AI analysis).

**Request:**
```json
{
  "description": "New description with AI analysis..."
}
```

**Response:**
```json
{
  "id": "uuid",
  "message": "Finding updated successfully",
  "old_description": "...",
  "new_description": "..."
}
```

### GET `/findings/{finding_id}/versions`

Retrieves version history for a finding's description.

**Response:**
```json
[
  {
    "id": "history-uuid",
    "change_type": "description_change",
    "old_value": "previous description...",
    "new_value": "updated description...",
    "created_at": "2024-12-07T10:30:00Z"
  }
]
```

---

## Frontend Implementation

### AskAIDialog Component

Key features of the `AskAIDialog.tsx` component:

#### 1. Auto-Start Analysis
```tsx
// Analysis starts automatically when dialog opens
useEffect(() => {
  if (isOpen && !analysisStarted.current && !initialAnalysis) {
    analysisStarted.current = true
    handleAnalyze()
  }
}, [isOpen])
```

#### 2. NLP Revision Detection
Detects when follow-up questions request description updates:
```tsx
const isRevisionRequest = (text: string): boolean => {
  const revisionPatterns = [
    /update.*description/i,
    /revise.*description/i,
    /change.*description/i,
    /add.*to.*description/i,
    /include.*in.*description/i,
    /modify.*description/i,
    /rewrite.*description/i,
    /more detail/i,
    /expand.*on/i,
    /elaborate/i
  ]
  return revisionPatterns.some(pattern => pattern.test(text))
}
```

When detected, shows a toast prompting user to use "Update Description" button.

#### 3. Description Versioning
```tsx
// Save with version history
const handleUpdateDescription = async () => {
  const response = await fetch(`${API_BASE}/findings/${findingId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ description: newDescription })
  })
  // Backend automatically creates FindingHistory entry
}

// Restore previous version
const handleRestoreVersion = async (oldValue: string) => {
  // Same PATCH endpoint, restores old_value as new description
}
```

#### 4. Conversation Separation
- **Initial Analysis Card**: Gradient-styled card showing first AI analysis
- **Conversation History**: Separate scrollable area for follow-up Q&A
- **Follow-up Input**: Text input for additional questions

---

## Database Schema

### Finding Model Fields (relevant)
```python
class Finding(Base):
    description = Column(Text)  # Current description
    updated_at = Column(DateTime)  # Auto-updates on change
    # ... other fields
```

### FindingHistory for Version Tracking
```python
class FindingHistory(Base):
    finding_id = Column(UUID, ForeignKey("findings.id"))
    change_type = Column(String)  # "description_change"
    old_value = Column(Text)  # Previous description
    new_value = Column(Text)  # New description
    created_at = Column(DateTime)  # Timestamp
```

---

## UI Components

### Ask AI Button Location
Located in the **Details card** on the Finding Details page (`/findings/[id]`):
```tsx
<Card>
  <CardHeader>
    <div className="flex items-center justify-between">
      <CardTitle>Details</CardTitle>
      <AskAIDialog 
        findingId={finding.id}
        findingContext={finding}
        onDescriptionUpdated={handleDescriptionUpdated}
      />
    </div>
  </CardHeader>
  ...
</Card>
```

### Description Display with ReactMarkdown
```tsx
<div className={cn(
  "prose prose-sm max-w-none",
  hasAIAnalysis && "bg-gradient-to-br from-purple-50/50 to-blue-50/50 ... border-purple-200/50"
)}>
  <ReactMarkdown remarkPlugins={[remarkGfm]}>
    {finding.description}
  </ReactMarkdown>
</div>
```

### Pro Tips Popover
Lightbulb icon that shows helpful tips:
- Use "Update Description" to save AI insights
- Follow-up questions for deeper analysis
- Version history for tracking changes
- Keyboard shortcuts

---

## All Findings Table Columns

The `/findings` page displays these columns:

| Column | Field | Description |
|--------|-------|-------------|
| Severity | `severity` | Badge with color coding |
| Title | `title` | Link to finding details |
| Repository | `repo_name` | Link to project page |
| File | `file_path` | Mono-spaced file path |
| Last Commit | `repo_last_commit_at` | Repository's last commit date |

The **Last Commit** column helps analysts prioritize findings:
- Recent commits → Active repository, higher priority
- Old commits → Potentially dormant, may need less urgency

---

## Testing Checklist

- [ ] Navigate to `/findings` and verify Last Commit column displays
- [ ] Click a finding to open details page
- [ ] Verify "Ask AI" button is in Details card header
- [ ] Click "Ask AI" and confirm analysis auto-starts
- [ ] Verify initial analysis shows in gradient-styled card
- [ ] Send a follow-up question and verify it appears in conversation
- [ ] Type a revision request (e.g., "add more detail") and verify toast appears
- [ ] Click "Update Description" and verify save succeeds
- [ ] Click version history icon and verify previous versions show
- [ ] Restore a previous version and verify it works
- [ ] Click lightbulb icon and verify Pro Tips popover shows
- [ ] Verify Repository link navigates to correct project page

---

## Error Handling

### AI Analysis Errors
- Network failures show error toast
- Rate limit errors suggest waiting
- Invalid API key shows configuration error

### Description Update Errors
- 404: Finding not found
- 500: Database error
- Network failure: Retry option

### Version History Errors
- Empty history: Shows "No previous versions"
- Load failure: Shows error message with retry

---

## Future Enhancements

1. **File-level commit tracking**: Currently shows repository-level last commit; could add per-file commit dates
2. **AI provider selection**: Allow switching between Claude/GPT in dialog
3. **Batch AI analysis**: Analyze multiple findings at once
4. **Export analysis**: Download AI analysis as PDF/Markdown
5. **Team sharing**: Share AI insights with team members
