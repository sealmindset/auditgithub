# Affected Repositories Export Feature

## Objective

Add export functionality to the Zero Day Analysis **Affected Repositories** card, allowing users to download the list of affected repositories in multiple formats: **PDF, JSON, DOCX, CSV, or Markdown**.

---

## UI Requirements

### Button Placement
- **Location:** Upper right corner of the Affected Repositories card
- **Row:** Same row as the "Affected Repositories (##)" label (CardHeader)
- **Style:** Icon-only button (no text)
- **Icon:** Download icon (`Download` from lucide-react)
- **Alt-text / Title:** "Download List"
- **Behavior:** Opens a dropdown menu with format options

### Visual Reference

```
┌─────────────────────────────────────────────────────────┐
│  Affected Repositories (5)                      [⬇️]   │  <- Download icon button here
│  Projects identified based on your query.               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  [Repository cards list...]                             │
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
| **CSV** | `.csv` | Spreadsheet analysis, import to Excel/Sheets |
| **Markdown** | `.md` | Documentation, GitHub issues, wikis |

---

## Implementation

### 1. Frontend Component Updates

**File:** `src/web-ui/components/ZeroDayView.tsx`

#### Add Export Handler for Repository List

Add this function alongside the existing `handleExport` function:

```typescript
const handleExportRepoList = async (format: 'pdf' | 'json' | 'docx' | 'csv' | 'md') => {
    if (!result || !result.affected_repositories) return

    const exportData = {
        query,
        timestamp: new Date().toISOString(),
        scope: selectedScopes,
        total_repositories: result.affected_repositories.length,
        repositories: result.affected_repositories
    }

    try {
        // For JSON, handle client-side
        if (format === 'json') {
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
            downloadBlob(blob, `affected-repos-${Date.now()}.json`)
            return
        }

        // For Markdown, handle client-side
        if (format === 'md') {
            const markdown = generateRepoListMarkdown(exportData)
            const blob = new Blob([markdown], { type: 'text/markdown' })
            downloadBlob(blob, `affected-repos-${Date.now()}.md`)
            return
        }

        // For CSV, handle client-side
        if (format === 'csv') {
            const csv = generateCSV(result.affected_repositories)
            const blob = new Blob([csv], { type: 'text/csv' })
            downloadBlob(blob, `affected-repos-${Date.now()}.csv`)
            return
        }

        // For PDF and DOCX, call backend API
        const response = await fetch(`http://localhost:8000/ai/zero-day/export/repos/${format}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(exportData)
        })

        if (!response.ok) throw new Error('Export failed')

        const blob = await response.blob()
        const extension = format === 'pdf' ? 'pdf' : 'docx'
        downloadBlob(blob, `affected-repos-${Date.now()}.${extension}`)

    } catch (err) {
        console.error('Export failed:', err)
        setError('Export failed. Please try again.')
    }
}

const generateRepoListMarkdown = (data: any): string => {
    const lines = [
        `# Affected Repositories Report`,
        ``,
        `**Generated:** ${new Date(data.timestamp).toLocaleString()}`,
        `**Query:** ${data.query}`,
        `**Scope:** ${data.scope.join(', ')}`,
        `**Total Repositories:** ${data.total_repositories}`,
        ``,
        `---`,
        ``,
        `## Repository List`,
        ``
    ]

    if (data.repositories.length === 0) {
        lines.push(`No affected repositories found.`)
    } else {
        lines.push(`| # | Repository | Reason | Source | Matched Sources |`)
        lines.push(`|---|------------|--------|--------|-----------------|`)
        data.repositories.forEach((repo: any, idx: number) => {
            const matchedSources = (repo.matched_sources || []).join(', ') || '-'
            lines.push(`| ${idx + 1} | ${repo.repository} | ${repo.reason || 'Context match'} | ${repo.source || '-'} | ${matchedSources} |`)
        })
    }

    lines.push(``, `---`, ``, `*Report generated from Zero Day Analysis*`)

    return lines.join('\n')
}
```

#### Update the Affected Repositories Card Header

Replace the existing Affected Repositories Card with:

```typescript
<Card>
    <CardHeader>
        <div className="flex items-center justify-between">
            <div>
                <CardTitle>Affected Repositories ({result.affected_repositories.length})</CardTitle>
                <CardDescription>
                    Projects identified based on your query.
                </CardDescription>
            </div>
            <DropdownMenu>
                <DropdownMenuTrigger asChild>
                    <Button
                        variant="ghost"
                        size="icon"
                        title="Download List"
                        aria-label="Download List"
                    >
                        <Download className="h-4 w-4" />
                    </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => handleExportRepoList('pdf')}>
                        Export as PDF
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExportRepoList('json')}>
                        Export as JSON
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExportRepoList('docx')}>
                        Export as DOCX
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExportRepoList('csv')}>
                        Export as CSV
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExportRepoList('md')}>
                        Export as Markdown
                    </DropdownMenuItem>
                </DropdownMenuContent>
            </DropdownMenu>
        </div>
    </CardHeader>
    <CardContent>
        {result.affected_repositories.length === 0 ? (
            <div className="flex items-center gap-2 text-muted-foreground">
                <CheckCircle2 className="h-4 w-4 text-green-500" />
                <span>No affected repositories found locally.</span>
            </div>
        ) : (
            <div className="grid gap-4 mt-2">
                {result.affected_repositories.map((repo, idx) => (
                    <div key={idx} className="flex items-start justify-between p-4 border rounded-lg bg-card hover:bg-accent/50 transition-colors">
                        <div>
                            <h4 className="font-semibold text-lg">
                                <a href={`/projects/${repo.repository_id}`} className="hover:underline text-primary">
                                    {repo.repository}
                                </a>
                            </h4>
                            <p className="text-sm text-muted-foreground mt-1">
                                match reason: {repo.reason || "Context match"}
                            </p>
                        </div>
                        <div className="flex gap-2">
                            <Button variant="outline" size="sm" asChild>
                                <a href={`/projects/${repo.repository_id}`}>View Project</a>
                            </Button>
                        </div>
                    </div>
                ))}
            </div>
        )}
    </CardContent>
</Card>
```

---

### 2. Backend API Endpoints

**File:** `src/api/routers/ai.py`

#### Add PDF Export Endpoint for Repository List

```python
@router.post("/zero-day/export/repos/pdf")
async def export_zda_repos_pdf(request: dict):
    """Export Zero Day Analysis affected repositories as PDF."""
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
        story.append(Paragraph("Affected Repositories Report", title_style))
        story.append(Spacer(1, 12))

        # Metadata
        meta_style = styles['Normal']
        story.append(Paragraph(f"<b>Query:</b> {request.get('query', 'N/A')}", meta_style))
        story.append(Paragraph(f"<b>Generated:</b> {request.get('timestamp', 'N/A')}", meta_style))
        scope_list = request.get('scope', [])
        scope_str = ', '.join(scope_list) if isinstance(scope_list, list) else str(scope_list)
        story.append(Paragraph(f"<b>Scope:</b> {scope_str}", meta_style))
        story.append(Paragraph(f"<b>Total Repositories:</b> {request.get('total_repositories', 0)}", meta_style))
        story.append(Spacer(1, 20))

        # Repository Table
        repos = request.get('repositories', [])
        story.append(Paragraph("Repository List", styles['Heading2']))
        story.append(Spacer(1, 8))

        if repos:
            table_data = [['#', 'Repository', 'Reason', 'Source']]
            for idx, repo in enumerate(repos, 1):
                table_data.append([
                    str(idx),
                    repo.get('repository', '')[:25],
                    repo.get('reason', 'Context match')[:35],
                    repo.get('source', '-')[:15]
                ])

            table = Table(table_data, colWidths=[0.4*inch, 2.0*inch, 2.8*inch, 1.3*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (1, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No affected repositories found.", meta_style))

        # Footer
        story.append(Spacer(1, 30))
        footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
        story.append(Paragraph("Report generated from Zero Day Analysis", footer_style))

        doc.build(story)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=affected-repos.pdf"}
        )

    except ImportError:
        raise HTTPException(status_code=500, detail="PDF generation requires reportlab. Install with: pip install reportlab")
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@router.post("/zero-day/export/repos/docx")
async def export_zda_repos_docx(request: dict):
    """Export Zero Day Analysis affected repositories as DOCX."""
    try:
        from docx import Document
        from docx.shared import Inches, Pt, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_TABLE_ALIGNMENT

        doc = Document()

        # Title
        title = doc.add_heading('Affected Repositories Report', 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Metadata
        doc.add_paragraph(f"Query: {request.get('query', 'N/A')}")
        doc.add_paragraph(f"Generated: {request.get('timestamp', 'N/A')}")
        scope_list = request.get('scope', [])
        scope_str = ', '.join(scope_list) if isinstance(scope_list, list) else str(scope_list)
        doc.add_paragraph(f"Scope: {scope_str}")
        doc.add_paragraph(f"Total Repositories: {request.get('total_repositories', 0)}")

        doc.add_paragraph()  # Spacer

        # Repository List
        doc.add_heading('Repository List', level=1)
        repos = request.get('repositories', [])

        if repos:
            table = doc.add_table(rows=1, cols=4)
            table.style = 'Table Grid'
            table.alignment = WD_TABLE_ALIGNMENT.CENTER

            # Header row
            header_cells = table.rows[0].cells
            headers = ['#', 'Repository', 'Reason', 'Source']
            for i, header in enumerate(headers):
                header_cells[i].text = header
                # Bold header
                for paragraph in header_cells[i].paragraphs:
                    for run in paragraph.runs:
                        run.bold = True

            # Data rows
            for idx, repo in enumerate(repos, 1):
                row_cells = table.add_row().cells
                row_cells[0].text = str(idx)
                row_cells[1].text = repo.get('repository', '')
                row_cells[2].text = repo.get('reason', 'Context match')
                row_cells[3].text = repo.get('source', '-')
        else:
            doc.add_paragraph('No affected repositories found.')

        # Footer
        doc.add_paragraph()
        footer = doc.add_paragraph('Report generated from Zero Day Analysis')
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER

        buffer = BytesIO()
        doc.save(buffer)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": "attachment; filename=affected-repos.docx"}
        )

    except ImportError:
        raise HTTPException(status_code=500, detail="DOCX generation requires python-docx. Install with: pip install python-docx")
    except Exception as e:
        logger.error(f"DOCX generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"DOCX generation failed: {str(e)}")
```

---

## File Changes Summary

| File | Changes |
|------|---------|
| `src/web-ui/components/ZeroDayView.tsx` | Add `handleExportRepoList`, `generateRepoListMarkdown`, update Affected Repositories Card |
| `src/api/routers/ai.py` | Add `/zero-day/export/repos/pdf` and `/zero-day/export/repos/docx` endpoints |

---

## Export Content Structure

The **Reason** column contains detailed findings explaining why each repository was flagged, including:
- Vulnerability identifiers (CVE, GHSA)
- Affected components and versions
- Types of issues found (RCE, secrets exposure, etc.)

### JSON Format

```json
{
  "query": "Find repositories with critical vulnerabilities or exposed secrets",
  "timestamp": "2024-12-06T10:30:00.000Z",
  "scope": ["dependencies", "findings", "secrets"],
  "total_repositories": 5,
  "repositories": [
    {
      "repository": "product-exchange-frontend",
      "repository_id": "uuid-here",
      "reason": "Contains critical RCE vulnerabilities (GHSA-f2jv-r9rf-7988, GHSA-ghhp-997w-qr28) and exposed secrets (GitHub tokens, URIs)",
      "source": "findings",
      "matched_sources": ["grype", "gitleaks", "semgrep"]
    },
    {
      "repository": "api-service",
      "repository_id": "uuid-here",
      "reason": "Uses vulnerable log4j-core 2.14.0 (CVE-2021-44228 - Log4Shell RCE)",
      "source": "dependencies",
      "matched_sources": ["sbom", "grype"]
    },
    {
      "repository": "payment-gateway",
      "repository_id": "uuid-here",
      "reason": "Exposed AWS credentials in config files and hardcoded API keys",
      "source": "secrets",
      "matched_sources": ["gitleaks"]
    },
    {
      "repository": "user-auth-service",
      "repository_id": "uuid-here",
      "reason": "SQL injection vulnerability in login handler (CWE-89) and weak password hashing",
      "source": "findings",
      "matched_sources": ["semgrep"]
    }
  ]
}
```

### CSV Format

```csv
"Repository","Repository ID","Reason","Source","Matched Sources"
"product-exchange-frontend","uuid-here","Contains critical RCE vulnerabilities (GHSA-f2jv-r9rf-7988, GHSA-ghhp-997w-qr28) and exposed secrets (GitHub tokens, URIs)","findings","grype; gitleaks; semgrep"
"api-service","uuid-here","Uses vulnerable log4j-core 2.14.0 (CVE-2021-44228 - Log4Shell RCE)","dependencies","sbom; grype"
"payment-gateway","uuid-here","Exposed AWS credentials in config files and hardcoded API keys","secrets","gitleaks"
"user-auth-service","uuid-here","SQL injection vulnerability in login handler (CWE-89) and weak password hashing","findings","semgrep"
```

### Markdown Format

```markdown
# Affected Repositories Report

**Generated:** 12/6/2024, 10:30:00 AM
**Query:** Find repositories with critical vulnerabilities or exposed secrets
**Scope:** dependencies, findings, secrets
**Total Repositories:** 5

---

## Repository List

| # | Repository | Reason | Source | Matched Sources |
|---|------------|--------|--------|-----------------|
| 1 | product-exchange-frontend | Contains critical RCE vulnerabilities (GHSA-f2jv-r9rf-7988, GHSA-ghhp-997w-qr28) and exposed secrets (GitHub tokens, URIs) | findings | grype, gitleaks, semgrep |
| 2 | api-service | Uses vulnerable log4j-core 2.14.0 (CVE-2021-44228 - Log4Shell RCE) | dependencies | sbom, grype |
| 3 | payment-gateway | Exposed AWS credentials in config files and hardcoded API keys | secrets | gitleaks |
| 4 | user-auth-service | SQL injection vulnerability in login handler (CWE-89) and weak password hashing | findings | semgrep |

---

*Report generated from Zero Day Analysis*
```

---

## Testing Checklist

- [ ] Download button appears in Affected Repositories card header (right side)
- [ ] Button shows download icon with no text
- [ ] Hovering shows "Download List" tooltip
- [ ] Clicking opens dropdown with 5 format options
- [ ] JSON export downloads valid JSON file with repository data
- [ ] Markdown export downloads valid .md file with table
- [ ] CSV export downloads valid CSV with all repository columns
- [ ] PDF export downloads formatted PDF with styled table
- [ ] DOCX export downloads valid Word document with table
- [ ] Export works when repository count is 0 (shows "No affected repositories")
- [ ] Export includes query, timestamp, scope, and total count
- [ ] File names include timestamp for uniqueness
- [ ] Table includes row numbers (#) column
- [ ] **Reason column contains detailed findings** (vulnerability IDs, CVE/GHSA references, secrets types, etc.)

---

## Accessibility

- Button has `title="Download List"` for tooltip
- Button has `aria-label="Download List"` for screen readers
- Dropdown menu items are keyboard navigable
- Focus states are visible

---

## Differences from AI Analysis Export

| Feature | AI Analysis Export | Repository List Export |
|---------|-------------------|----------------------|
| **Button alt-text** | "Download Report" | "Download List" |
| **API endpoint** | `/ai/zero-day/export/{format}` | `/ai/zero-day/export/repos/{format}` |
| **Content** | Full analysis + repos | Repositories only |
| **Includes AI text** | Yes | No |
| **Row numbers** | No | Yes |
| **File prefix** | `zda-analysis-` | `affected-repos-` |

---

## Error Handling

- Display error toast if export fails
- Gracefully handle missing dependencies (reportlab, python-docx)
- Validate result and repositories exist before enabling export button
- Handle empty repository list gracefully

---

## To Deploy

### 1. Install Python Dependencies

```bash
pip install reportlab python-docx
```

Or if using requirements.txt (already added):

```bash
pip install -r requirements.txt
```

### 2. Restart Services

```bash
# If using Docker Compose
docker-compose restart api web-ui

# Or restart individual services
docker-compose restart api
docker-compose restart web-ui
```

### 3. Verify Installation

```bash
# Check that dependencies are installed
python -c "import reportlab; print('reportlab:', reportlab.Version)"
python -c "import docx; print('python-docx: installed')"
```

### 4. Test the Feature

1. Navigate to Zero Day Analysis in the web UI
2. Run a query to generate affected repositories
3. Click the download icon in the Affected Repositories card header
4. Test each export format (PDF, JSON, DOCX, CSV, Markdown)
5. Verify downloaded files open correctly in their respective applications
