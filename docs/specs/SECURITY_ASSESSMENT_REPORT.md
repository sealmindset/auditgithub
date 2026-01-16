# AI-Powered Security Assessment Report - Implementation Spec

## Overview

A comprehensive, AI-powered security assessment report that aggregates all security findings, architecture analysis, and project insights into a beautiful, actionable document. The report is accessible via a report icon on the project detail page and can be exported in multiple formats.

## User Interface

### Report Icon Location
- **Position**: Upper right side of the project detail page header
- **Alignment**: In line with the row of tabs (Overview, Secrets, SAST, etc.)
- **Icon**: `FileText` or `ClipboardList` from Lucide icons
- **Alt-text**: "Report"
- **Tooltip**: "Generate Security Assessment Report"

### Report Modal
- **Size**: 75% of root browser viewport (width and height)
- **Scrollable**: Yes, vertical scrolling for content
- **Header**: Fixed position with title and export buttons
- **Export Buttons**: PDF, DOCX, JSON, Markdown, CSV (upper right)
- **Close Button**: X icon in upper right corner

## Report Structure

### 1. Executive Summary
- Project name, description, and repository URL
- Overall risk score (calculated from findings)
- Date of assessment
- AI-generated executive summary highlighting key concerns

### 2. System Architecture Overview
- **Source**: Architecture tab > System Architecture > Report
- Project type and technology stack
- Cloud provider and infrastructure overview
- Architecture diagram (if available)
- AI-generated insights about the system design

### 3. Project Insights
- **Development Evaluation**:
  - Code quality indicators
  - Development patterns observed
  - Technical debt assessment
- **Contributor Analysis**:
  - Number of contributors
  - Contribution patterns
  - Key maintainers
- **Language Breakdown**:
  - Primary languages
  - Framework detection
  - Dependency ecosystem
- **Additional Context**:
  - Repository age and activity
  - Frequency of commits
  - CI/CD pipeline status

### 4. Critical Findings Highlight Reel
**NOT a list of all findings** - Instead, AI-curated "highlight reel" of the most impactful risks:

- **Secrets & Credentials**:
  - Focus on credentials that could grant access (not just detected patterns)
  - Highlight embedded API keys, tokens with actual access potential
  - Example: "AWS key found in config.py grants S3 bucket access"

- **SAST Vulnerabilities**:
  - Cherry-pick exploitable vulnerabilities
  - Focus on injection points, auth bypasses
  - Highlight attack chains, not just individual issues

- **Infrastructure Risks**:
  - Public entry points
  - Misconfigured security groups
  - Exposed services

- **Dependency Vulnerabilities**:
  - Known exploited vulnerabilities (KEV)
  - Critical CVEs with public exploits
  - Supply chain risks

- **CI/CD Security**:
  - Pipeline injection risks
  - Secret exposure in logs
  - Insecure deployment patterns

- **API Security**:
  - Unauthenticated endpoints
  - Credential-URL correlations
  - Information disclosure

### 5. Comprehensive Findings
All findings organized by category with full details:

- **Secrets** (full table)
- **SAST** (full table)
- **Infrastructure** (full table)
- **Dependencies** (full table)
- **CI/CD** (full table)
- **Contributors** (full table)
- **Languages** (breakdown)
- **SBOM** (full component list)
- **API Audit** (full results)

## API Endpoint

### `POST /projects/{project_id}/security-report`

Generates the AI-powered security assessment report.

**Request Body**:
```json
{
  "include_architecture": true,
  "include_diagram": true,
  "highlight_count": 10
}
```

**Response**:
```json
{
  "report_id": "uuid",
  "generated_at": "ISO timestamp",
  "project": { ... },
  "executive_summary": "AI-generated summary...",
  "architecture": {
    "report": "markdown content",
    "diagram_base64": "...",
    "insights": "AI insights..."
  },
  "project_insights": {
    "development_evaluation": "...",
    "contributor_count": 15,
    "contributor_analysis": "...",
    "language_breakdown": { ... },
    "additional_context": { ... }
  },
  "highlight_reel": [
    {
      "category": "secrets",
      "title": "AWS Access Key with S3 Permissions",
      "severity": "critical",
      "impact": "Full read/write access to production S3 buckets",
      "finding_id": "uuid",
      "ai_analysis": "This credential was found in..."
    }
  ],
  "findings": {
    "secrets": [ ... ],
    "sast": [ ... ],
    "infrastructure": [ ... ],
    "dependencies": [ ... ],
    "cicd": [ ... ],
    "contributors": [ ... ],
    "languages": { ... },
    "sbom": [ ... ],
    "api_audit": [ ... ]
  },
  "risk_score": {
    "overall": 78,
    "secrets": 85,
    "sast": 65,
    "infrastructure": 70,
    "dependencies": 80
  }
}
```

## Export Formats

### PDF
- Professional formatting with company branding area
- Table of contents with page numbers
- Charts and diagrams embedded
- Syntax highlighting for code snippets

### DOCX
- Editable Word document
- Proper heading styles for TOC generation
- Tables for findings
- Embedded images

### JSON
- Full structured data
- Machine-readable for integration
- Includes all metadata

### Markdown
- GitHub-flavored markdown
- Suitable for documentation systems
- Includes mermaid diagrams where applicable

### CSV
- Flattened findings data
- One row per finding
- Suitable for spreadsheet analysis

## Component Structure

```
src/web-ui/components/
├── SecurityReportModal.tsx      # Main modal component
├── report/
│   ├── ExecutiveSummary.tsx     # Executive summary section
│   ├── ArchitectureSection.tsx  # Architecture overview
│   ├── ProjectInsights.tsx      # Project insights section
│   ├── HighlightReel.tsx        # Critical findings highlights
│   ├── FindingsSection.tsx      # Comprehensive findings
│   ├── RiskScoreCard.tsx        # Risk score visualization
│   └── ExportButtons.tsx        # Export functionality
```

## AI Integration

The report generation uses the existing AI agent infrastructure to:

1. **Analyze findings** - Identify the most impactful issues
2. **Generate insights** - Provide context and recommendations
3. **Create executive summary** - Summarize for leadership
4. **Correlate data** - Connect findings across categories

## Implementation Order

1. Create `SecurityReportModal.tsx` component
2. Add API endpoint for report generation
3. Implement AI analysis for highlight reel
4. Add export functionality (start with JSON/Markdown)
5. Add PDF export (using html2pdf or similar)
6. Add DOCX export (using docx library)
7. Add CSV export
8. Add report icon to project page
9. Test and refine

## Dependencies

### Frontend
- `html2pdf.js` - PDF generation
- `docx` - DOCX generation
- `file-saver` - File download handling
- `recharts` - Risk score visualization (already installed)

### Backend
- Existing AI agent infrastructure
- Existing database models and endpoints
