# Report Section Checkboxes Implementation Guide

## Overview

This guide documents the implementation of checkbox controls for the Security Report Modal, allowing users to selectively include/exclude sections when exporting reports.

## Changes Made

### 1. State Management (Lines 131-164)

Added state for tracking which sections are selected for export:

```typescript
// Section selection state for export (all enabled by default)
const [selectedSections, setSelectedSections] = useState({
    executiveSummary: true,
    riskScore: true,
    projectDetails: true,
    projectInsights: true,
    criticalInsights: true,
    highlightReel: true,
    apiCompromises: true,
    comprehensiveFindings: true,
    secrets: true,
    sast: true,
    infrastructure: true,
    dependencies: true,
    cicd: true,
    contributors: true,
    languages: true,
    sbom: true,
    apiAudit: true
})

// Toggle individual section
const toggleSection = (section: keyof typeof selectedSections) => {
    setSelectedSections(prev => ({ ...prev, [section]: !prev[section] }))
}

// Select/Deselect all sections
const toggleAllSections = (selected: boolean) => {
    const newState = Object.keys(selectedSections).reduce((acc, key) => ({
        ...acc,
        [key]: selected
    }), {} as typeof selectedSections)
    setSelectedSections(newState)
}
```

### 2. UI Controls Added (Lines 753-770)

Added Select All / Deselect All buttons in the header:

```tsx
<Button
    variant="outline"
    size="sm"
    onClick={() => toggleAllSections(true)}
    disabled={!reportData || generating}
>
    <CheckCircle className="h-4 w-4 mr-2" />
    Select All
</Button>
<Button
    variant="outline"
    size="sm"
    onClick={() => toggleAllSections(false)}
    disabled={!reportData || generating}
>
    <X className="h-4 w-4 mr-2" />
    Deselect All
</Button>
```

### 3. Section Checkboxes

Added checkbox to Executive Summary section (example pattern):

```tsx
<CardHeader>
    <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
            <Checkbox
                id="exec-summary-checkbox"
                checked={selectedSections.executiveSummary}
                onCheckedChange={() => toggleSection('executiveSummary')}
            />
            <CardTitle>Executive Summary</CardTitle>
        </div>
    </div>
    <CardDescription>
        Comprehensive overview of security posture
    </CardDescription>
</CardHeader>
```

## Sections That Need Checkboxes

Apply the same checkbox pattern to these sections:

### Major Sections (Cards with CardHeader)

1. **Risk Score Overview** (Line ~810)
   - Key: `riskScore`
   - Already has header with title

2. **Project Details** (Line ~888)
   - Key: `projectDetails`
   - Metrics card

3. **Project Insights** (Line ~930)
   - Key: `projectInsights`
   - Contributors, Languages, Development info

4. **Critical Security Insights** (Line ~960)
   - Key: `criticalInsights`
   - Red-highlighted RCE/critical vuln card

5. **Critical Findings Highlight Reel** (Line ~1014)
   - Key: `highlightReel`
   - Curated high-impact risks

6. **Successful API Compromises** (Line ~1091)
   - Key: `apiCompromises`
   - API endpoint test results

7. **Comprehensive Findings** (Line ~1300)
   - Key: `comprehensiveFindings`
   - Parent section for tabbed findings

### Finding Category Tabs (Inside Comprehensive Findings)

Each tab should have a checkbox in the TabsTrigger:

8. **Secrets** - Key: `secrets`
9. **SAST** - Key: `sast`
10. **Infrastructure** - Key: `infrastructure`
11. **Dependencies** - Key: `dependencies`
12. **CI/CD** - Key: `cicd`
13. **Contributors** - Key: `contributors`
14. **Languages** - Key: `languages`
15. **SBOM** - Key: `sbom`
16. **API Audit** - Key: `apiAudit`

## Export Functions to Update

The following export functions need to check `selectedSections` before including content:

### 1. generateMarkdown() (Line ~300)

```typescript
const generateMarkdown = (data: ReportData): string => {
    let md = `# Security Assessment Report\n\n`
    md += `**Project:** ${projectName}\n`
    md += `**Generated:** ${new Date(data.generated_at).toLocaleString()}\n\n`
    md += `---\n\n`

    // Executive Summary (conditional)
    if (selectedSections.executiveSummary) {
        md += `## Executive Summary\n\n${data.executive_summary || 'No summary available.'}\n\n`
    }

    // Architecture (conditional)
    if (selectedSections.projectInsights && data.architecture?.report) {
        md += `## System Architecture\n\n${data.architecture.report}\n\n`
        if (data.architecture.insights) {
            md += `### Architecture Insights\n\n${data.architecture.insights}\n\n`
        }
    }

    // Project Insights (conditional)
    if (selectedSections.projectInsights && data.project_insights) {
        md += `## Project Insights\n\n`
        md += `### Development Evaluation\n\n${data.project_insights.development_evaluation || 'No evaluation available.'}\n\n`

        // ... rest of project insights
    }

    // Highlight Reel (conditional)
    if (selectedSections.highlightReel) {
        md += `## Critical Findings Highlight Reel\n\n`
        // ... highlight reel content
    }

    // Findings Summary (conditional per category)
    md += `## Findings Summary\n\n`
    const categories = [
        { key: 'secrets', label: 'Secrets', enabled: selectedSections.secrets },
        { key: 'sast', label: 'SAST', enabled: selectedSections.sast },
        { key: 'infrastructure', label: 'Infrastructure', enabled: selectedSections.infrastructure },
        { key: 'dependencies', label: 'Dependencies', enabled: selectedSections.dependencies },
        { key: 'cicd', label: 'CI/CD', enabled: selectedSections.cicd },
    ]

    categories.forEach(({ key, label, enabled }) => {
        if (enabled && data.findings?.[key]?.length > 0) {
            md += `### ${label}\n\n`
            md += `Found ${data.findings[key].length} ${label.toLowerCase()} findings.\n\n`
        }
    })

    return md
}
```

### 2. generateCSV() (Line ~360)

```typescript
const generateCSV = (data: ReportData): string => {
    let csv = "Category,Severity,Title,File,Line,Description\n"

    const categories = [
        { key: 'secrets', name: 'Secrets', enabled: selectedSections.secrets },
        { key: 'sast', name: 'SAST', enabled: selectedSections.sast },
        { key: 'infrastructure', name: 'Infrastructure', enabled: selectedSections.infrastructure },
        { key: 'dependencies', name: 'Dependencies', enabled: selectedSections.dependencies },
        { key: 'cicd', name: 'CI/CD', enabled: selectedSections.cicd },
    ]

    categories.forEach(({ key, name, enabled }) => {
        if (enabled) {
            const findings = data.findings?.[key] || []
            findings.forEach((f: any) => {
                csv += `"${name}","${f.severity || ''}","${f.title || ''}","${f.file_path || ''}","${f.line_start || ''}","${(f.description || '').replace(/"/g, '""')}"\n`
            })
        }
    })

    return csv
}
```

### 3. buildPDFHtml() (Line ~386)

```typescript
const buildPDFHtml = (data: ReportData): string => {
    let html = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            /* ... PDF styles ... */
        </style>
    </head>
    <body>
        <div style="max-width: 800px; margin: 0 auto; padding: 20px;">`

    // Executive Summary (conditional)
    if (selectedSections.executiveSummary) {
        html += `
        <div style="margin-bottom: 25px; page-break-inside: avoid;">
            <h2 style="color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 20px;">Executive Summary</h2>
            <div style="background: #f9fafb; padding: 15px; border-radius: 8px; border-left: 4px solid #3b82f6;">
                ${data.executive_summary?.replace(/\n/g, '<br>') || 'No executive summary available.'}
            </div>
        </div>`
    }

    // Risk Score (conditional)
    if (selectedSections.riskScore && data.risk_score) {
        html += `
        <div style="margin-bottom: 25px;">
            <h2 style="color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 20px;">Risk Assessment</h2>
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 48px; font-weight: bold; color: ${data.risk_score.overall >= 80 ? '#ef4444' : data.risk_score.overall >= 60 ? '#f97316' : '#84cc16'};">
                    ${data.risk_score.overall}
                </div>
                <p style="margin-top: 8px; color: #6b7280;">Overall Risk Score</p>
            </div>
        </div>`
    }

    // Project Insights (conditional)
    if (selectedSections.projectInsights && data.project_insights) {
        // ... project insights HTML
    }

    // Highlight Reel (conditional)
    if (selectedSections.highlightReel && data.highlight_reel && data.highlight_reel.length > 0) {
        html += `
        <div style="margin-bottom: 25px;">
            <h2 style="color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 20px;">Critical Findings</h2>`

        data.highlight_reel.forEach((highlight, idx) => {
            // ... highlight HTML
        })

        html += `</div>`
    }

    // Findings (conditional per category)
    const categories = [
        { key: 'secrets', label: 'Secrets', enabled: selectedSections.secrets },
        { key: 'sast', label: 'SAST', enabled: selectedSections.sast },
        { key: 'infrastructure', label: 'Infrastructure', enabled: selectedSections.infrastructure },
        { key: 'dependencies', label: 'Dependencies', enabled: selectedSections.dependencies },
        { key: 'cicd', label: 'CI/CD', enabled: selectedSections.cicd },
    ]

    categories.forEach(({ key, label, enabled }) => {
        if (enabled) {
            const findings = data.findings?.[key] || []
            if (findings.length > 0) {
                html += `
                <div style="margin-bottom: 20px;">
                    <h3 style="color: #374151; font-size: 16px;">${label} (${findings.length})</h3>
                    <!-- findings list -->
                </div>`
            }
        }
    })

    html += `
        </div>
    </body>
    </html>`

    return html
}
```

### 4. JSON Export

```typescript
const handleExportClick = (format: string) => {
    if (!reportData) return

    if (format === "json") {
        // Filter reportData based on selectedSections
        const filteredData = {
            ...reportData,
            executive_summary: selectedSections.executiveSummary ? reportData.executive_summary : undefined,
            critical_insights: selectedSections.criticalInsights ? reportData.critical_insights : undefined,
            architecture: selectedSections.projectInsights ? reportData.architecture : undefined,
            project_insights: selectedSections.projectInsights ? reportData.project_insights : undefined,
            highlight_reel: selectedSections.highlightReel ? reportData.highlight_reel : undefined,
            risk_score: selectedSections.riskScore ? reportData.risk_score : undefined,
            findings: {
                secrets: selectedSections.secrets ? reportData.findings?.secrets : [],
                sast: selectedSections.sast ? reportData.findings?.sast : [],
                infrastructure: selectedSections.infrastructure ? reportData.findings?.infrastructure : [],
                dependencies: selectedSections.dependencies ? reportData.findings?.dependencies : [],
                cicd: selectedSections.cicd ? reportData.findings?.cicd : [],
                contributors: selectedSections.contributors ? reportData.findings?.contributors : [],
                languages: selectedSections.languages ? reportData.findings?.languages : [],
                sbom: selectedSections.sbom ? reportData.findings?.sbom : [],
                api_audit: selectedSections.apiAudit ? reportData.findings?.api_audit : [],
            }
        }

        const blob = new Blob([JSON.stringify(filteredData, null, 2)], { type: "application/json" })
        const url = URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = url
        a.download = `${projectName}-security-report.json`
        a.click()
        URL.revokeObjectURL(url)
        return
    }

    // ... other formats
}
```

## Pattern for Tab Checkboxes

For the tabbed findings section, add checkboxes to TabsTrigger:

```tsx
<TabsList className="grid grid-cols-9 w-full">
    <TabsTrigger value="secrets" className="relative">
        <div className="flex items-center gap-2">
            <Checkbox
                checked={selectedSections.secrets}
                onCheckedChange={(e) => { e?.stopPropagation(); toggleSection('secrets'); }}
                onClick={(e) => e.stopPropagation()}
            />
            <Lock className="h-4 w-4" />
            <span className="hidden sm:inline">Secrets</span>
            {reportData?.findings?.secrets && reportData.findings.secrets.length > 0 && (
                <Badge variant="destructive" className="ml-1">
                    {reportData.findings.secrets.length}
                </Badge>
            )}
        </div>
    </TabsTrigger>
    {/* Repeat for other tabs */}
</TabsList>
```

## Testing Checklist

- [ ] All major sections have checkboxes
- [ ] Select All button enables all checkboxes
- [ ] Deselect All button disables all checkboxes
- [ ] Individual checkboxes can be toggled
- [ ] PDF export respects selected sections
- [ ] Markdown export respects selected sections
- [ ] CSV export respects selected sections
- [ ] JSON export respects selected sections
- [ ] DOCX export respects selected sections
- [ ] Tab checkboxes work independently
- [ ] Checkbox state persists during report session
- [ ] Disabled sections don't appear in exports

## User Experience Notes

1. **Default State**: All sections enabled by default (users opt-out rather than opt-in)
2. **Visual Feedback**: Checkboxes provide clear visual indication of what will be included
3. **Convenience**: Select All / Deselect All for quick bulk operations
4. **Granular Control**: Individual checkboxes for fine-tuned control
5. **Export Preview**: Users can see exactly what's checked before exporting

## Next Steps

1. Add checkboxes to remaining sections (follow the pattern established)
2. Update all export functions to respect `selectedSections` state
3. Test all export formats with various checkbox combinations
4. Consider adding a "Preview" button to show what will be exported
5. Add tooltip/help text explaining the checkbox functionality
