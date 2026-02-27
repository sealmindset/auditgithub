# AI Analysis Export Feature

## Objective

Add export functionality to the Zero Day Analysis AI Analysis pane, allowing users to download the analysis results in multiple formats: **PDF, JSON, DOCX, CSV, or Markdown**.

---

## UI Requirements

### Button Placement
- **Location:** Upper right corner of the AI Analysis pane
- **Row:** Same row as the "AI Analysis" label (CardHeader)
- **Style:** Icon-only button (no text)
- **Icon:** Download icon (`Download` from lucide-react)
- **Alt-text / Title:** "Download Report"
- **Behavior:** Opens a dropdown menu with format options

### Visual Reference

```
┌─────────────────────────────────────────────────────────┐
│  AI Analysis                                    [⬇️]   │  <- Download icon button here
├─────────────────────────────────────────────────────────┤
│                                                         │
│  [Analysis content rendered as markdown...]             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Export Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| **PDF** | `.pdf` | Professional reports, sharing with stakeholders |
| **JSON** | `.json` | Integration with other tools, programmatic access |
| **DOCX** | `.docx` | Editable documents for Microsoft Word |
| **CSV** | `.csv` | Spreadsheet analysis of affected repositories |
| **Markdown** | `.md` | Documentation, GitHub issues, wikis |

---

## Implementation

### 1. Frontend Component Updates

**File:** `src/web-ui/components/ZeroDayView.tsx`

#### Add Imports

```typescript
import { Download } from "lucide-react"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
```

#### Add Export Handler Function

```typescript
const handleExport = async (format: 'pdf' | 'json' | 'docx' | 'csv' | 'md') => {
    if (!result) return

    const exportData = {
        query,
        timestamp: new Date().toISOString(),
        scope: selectedScopes,
        analysis: result.answer,
        affected_repositories: result.affected_repositories,
        plan: result.plan,
        execution_summary: result.execution_summary
    }

    try {
        // For JSON and Markdown, handle client-side
        if (format === 'json') {
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
            downloadBlob(blob, `zda-analysis-${Date.now()}.json`)
            return
        }

        if (format === 'md') {
            const markdown = generateMarkdown(exportData)
            const blob = new Blob([markdown], { type: 'text/markdown' })
            downloadBlob(blob, `zda-analysis-${Date.now()}.md`)
            return
        }

        if (format === 'csv') {
            const csv = generateCSV(result.affected_repositories)
            const blob = new Blob([csv], { type: 'text/csv' })
            downloadBlob(blob, `zda-analysis-${Date.now()}.csv`)
            return
        }

        // For PDF and DOCX, call backend API
        const response = await fetch(`http://localhost:8000/ai/zero-day/export/${format}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(exportData)
        })

        if (!response.ok) throw new Error('Export failed')

        const blob = await response.blob()
        const extension = format === 'pdf' ? 'pdf' : 'docx'
        downloadBlob(blob, `zda-analysis-${Date.now()}.${extension}`)

    } catch (err) {
        console.error('Export failed:', err)
        // Optionally show error toast
    }
}

const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
}

const generateMarkdown = (data: any): string => {
    const lines = [
        `# Zero Day Analysis Report`,
        ``,
        `**Generated:** ${new Date(data.timestamp).toLocaleString()}`,
        `**Query:** ${data.query}`,
        `**Scope:** ${data.scope.join(', ')}`,
        ``,
        `---`,
        ``,
        `## AI Analysis`,
        ``,
        data.analysis,
        ``,
        `---`,
        ``,
        `## Affected Repositories (${data.affected_repositories.length})`,
        ``
    ]

    if (data.affected_repositories.length === 0) {
        lines.push(`No affected repositories found.`)
    } else {
        lines.push(`| Repository | Reason | Source |`)
        lines.push(`|------------|--------|--------|`)
        data.affected_repositories.forEach((repo: any) => {
            lines.push(`| ${repo.repository} | ${repo.reason || 'Context match'} | ${repo.source || '-'} |`)
        })
    }

    if (data.plan) {
        lines.push(``, `---`, ``, `## Analysis Strategy`, ``, '```json', JSON.stringify(data.plan, null, 2), '```')
    }

    return lines.join('\n')
}

const generateCSV = (repositories: any[]): string => {
    const headers = ['Repository', 'Repository ID', 'Reason', 'Source', 'Matched Sources']
    const rows = repositories.map(repo => [
        repo.repository,
        repo.repository_id,
        repo.reason || 'Context match',
        repo.source || '',
        (repo.matched_sources || []).join('; ')
    ])

    const escape = (val: string) => `"${(val || '').replace(/"/g, '""')}"`
    const csvLines = [
        headers.join(','),
        ...rows.map(row => row.map(escape).join(','))
    ]

    return csvLines.join('\n')
}
```

#### Update the AI Analysis Card Header

Replace the existing AI Analysis Card with:

```typescript
<Card className="md:col-span-2">
    <CardHeader>
        <div className="flex items-center justify-between">
            <CardTitle>AI Analysis</CardTitle>
            <DropdownMenu>
                <DropdownMenuTrigger asChild>
                    <Button
                        variant="ghost"
                        size="icon"
                        title="Download Report"
                        aria-label="Download Report"
                    >
                        <Download className="h-4 w-4" />
                    </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => handleExport('pdf')}>
                        Export as PDF
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExport('json')}>
                        Export as JSON
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExport('docx')}>
                        Export as DOCX
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExport('csv')}>
                        Export as CSV
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExport('md')}>
                        Export as Markdown
                    </DropdownMenuItem>
                </DropdownMenuContent>
            </DropdownMenu>
        </div>
    </CardHeader>
    <CardContent className="prose dark:prose-invert max-w-none">
        <ReactMarkdown>{result.answer}</ReactMarkdown>
    </CardContent>
</Card>
```

---

### 2. Backend API Endpoints

**File:** `src/api/routers/ai.py`

#### Add PDF Export Endpoint

```python
from fastapi.responses import StreamingResponse
from io import BytesIO
import json

@router.post("/zero-day/export/pdf")
async def export_zda_pdf(request: dict):
    """Export Zero Day Analysis as PDF."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.units import inch

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=12)
        story.append(Paragraph("Zero Day Analysis Report", title_style))
        story.append(Spacer(1, 12))

        # Metadata
        meta_style = styles['Normal']
        story.append(Paragraph(f"<b>Query:</b> {request.get('query', 'N/A')}", meta_style))
        story.append(Paragraph(f"<b>Generated:</b> {request.get('timestamp', 'N/A')}", meta_style))
        story.append(Paragraph(f"<b>Scope:</b> {', '.join(request.get('scope', []))}", meta_style))
        story.append(Spacer(1, 20))

        # Analysis
        story.append(Paragraph("AI Analysis", styles['Heading2']))
        story.append(Spacer(1, 8))
        analysis_text = request.get('analysis', '').replace('\n', '<br/>')
        story.append(Paragraph(analysis_text, meta_style))
        story.append(Spacer(1, 20))

        # Affected Repositories
        repos = request.get('affected_repositories', [])
        story.append(Paragraph(f"Affected Repositories ({len(repos)})", styles['Heading2']))
        story.append(Spacer(1, 8))

        if repos:
            table_data = [['Repository', 'Reason', 'Source']]
            for repo in repos:
                table_data.append([
                    repo.get('repository', ''),
                    repo.get('reason', 'Context match'),
                    repo.get('source', '-')
                ])

            table = Table(table_data, colWidths=[2.5*inch, 2.5*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No affected repositories found.", meta_style))

        doc.build(story)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=zda-analysis.pdf"}
        )

    except ImportError:
        raise HTTPException(status_code=500, detail="PDF generation requires reportlab. Install with: pip install reportlab")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
```

#### Add DOCX Export Endpoint

```python
@router.post("/zero-day/export/docx")
async def export_zda_docx(request: dict):
    """Export Zero Day Analysis as DOCX."""
    try:
        from docx import Document
        from docx.shared import Inches, Pt
        from docx.enum.text import WD_ALIGN_PARAGRAPH

        doc = Document()

        # Title
        title = doc.add_heading('Zero Day Analysis Report', 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Metadata
        doc.add_paragraph(f"Query: {request.get('query', 'N/A')}")
        doc.add_paragraph(f"Generated: {request.get('timestamp', 'N/A')}")
        doc.add_paragraph(f"Scope: {', '.join(request.get('scope', []))}")

        # Analysis
        doc.add_heading('AI Analysis', level=1)
        doc.add_paragraph(request.get('analysis', ''))

        # Affected Repositories
        repos = request.get('affected_repositories', [])
        doc.add_heading(f'Affected Repositories ({len(repos)})', level=1)

        if repos:
            table = doc.add_table(rows=1, cols=3)
            table.style = 'Table Grid'
            header_cells = table.rows[0].cells
            header_cells[0].text = 'Repository'
            header_cells[1].text = 'Reason'
            header_cells[2].text = 'Source'

            for repo in repos:
                row_cells = table.add_row().cells
                row_cells[0].text = repo.get('repository', '')
                row_cells[1].text = repo.get('reason', 'Context match')
                row_cells[2].text = repo.get('source', '-')
        else:
            doc.add_paragraph('No affected repositories found.')

        buffer = BytesIO()
        doc.save(buffer)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": "attachment; filename=zda-analysis.docx"}
        )

    except ImportError:
        raise HTTPException(status_code=500, detail="DOCX generation requires python-docx. Install with: pip install python-docx")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DOCX generation failed: {str(e)}")
```

---

### 3. Install Required Dependencies

**Backend (Python):**

```bash
pip install reportlab python-docx
```

Or add to `requirements.txt`:

```
reportlab>=4.0.0
python-docx>=0.8.11
```

---

## File Changes Summary

| File | Changes |
|------|---------|
| `src/web-ui/components/ZeroDayView.tsx` | Add Download button, export handlers, dropdown menu |
| `src/api/routers/ai.py` | Add `/zero-day/export/pdf` and `/zero-day/export/docx` endpoints |
| `requirements.txt` | Add `reportlab` and `python-docx` |

---

## Export Content Structure

### JSON Format

```json
{
  "query": "Find repositories using Log4j",
  "timestamp": "2024-12-06T10:30:00.000Z",
  "scope": ["dependencies", "findings"],
  "analysis": "Based on the analysis...",
  "affected_repositories": [
    {
      "repository": "api-service",
      "repository_id": "uuid-here",
      "reason": "Uses log4j-core 2.14.0",
      "source": "dependencies",
      "matched_sources": ["sbom", "grype"]
    }
  ],
  "plan": { ... },
  "execution_summary": ["Step 1...", "Step 2..."]
}
```

### CSV Format

```csv
"Repository","Repository ID","Reason","Source","Matched Sources"
"api-service","uuid-here","Uses log4j-core 2.14.0","dependencies","sbom; grype"
"web-app","uuid-here","Contains log4j dependency","dependencies","sbom"
```

### Markdown Format

```markdown
# Zero Day Analysis Report

**Generated:** 12/6/2024, 10:30:00 AM
**Query:** Find repositories using Log4j
**Scope:** dependencies, findings

---

## AI Analysis

Based on the analysis...

---

## Affected Repositories (2)

| Repository | Reason | Source |
|------------|--------|--------|
| api-service | Uses log4j-core 2.14.0 | dependencies |
| web-app | Contains log4j dependency | dependencies |
```

---

## Testing Checklist

- [ ] Download button appears in AI Analysis card header (right side)
- [ ] Button shows download icon with no text
- [ ] Hovering shows "Download Report" tooltip
- [ ] Clicking opens dropdown with 5 format options
- [ ] JSON export downloads valid JSON file
- [ ] Markdown export downloads valid .md file
- [ ] CSV export downloads valid CSV with all repositories
- [ ] PDF export downloads formatted PDF document
- [ ] DOCX export downloads valid Word document
- [ ] Export works when no repositories are affected
- [ ] Export includes query, timestamp, scope, and analysis
- [ ] File names include timestamp for uniqueness

---

## Accessibility

- Button has `title="Download Report"` for tooltip
- Button has `aria-label="Download Report"` for screen readers
- Dropdown menu items are keyboard navigable
- Focus states are visible

---

## Error Handling

- Display error toast if export fails
- Gracefully handle missing dependencies (reportlab, python-docx)
- Validate result exists before enabling export button
- Handle large analysis content in PDF/DOCX generation
