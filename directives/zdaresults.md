# ZDA Reports Page Feature

## Objective

Move the **Recent Analyses** card from the Zero Day Analysis page to its own dedicated page called **ZDA Reports**. This new page will be accessible through a submenu under "Zero Day Analysis" in the left navigation sidebar.

---

## Current State

- **Zero Day Analysis** page (`/zero-day`) contains:
  - Query input and scope selector
  - AI Analysis results card
  - Affected Repositories card
  - Recent Analyses card (history)
  - Analysis Strategy (debug) card

- **Navigation** has a single "Zero Day Analysis" menu item pointing to `/zero-day`

---

## Target State

### Navigation Structure

```
Platform
├── Dashboard
├── Findings
├── Repositories
└── Zero Day Analysis        <- Parent with submenu
    ├── Analysis             <- /zero-day (current functionality minus history)
    └── ZDA Reports          <- /zero-day/reports (new page with history)
```

### Visual Reference

```
┌─────────────────────────────────────────────┐
│  Platform                                   │
├─────────────────────────────────────────────┤
│  📊 Dashboard                               │
│  ⚠️  Findings                               │
│  🔀 Repositories                            │
│  🛡️ Zero Day Analysis              ▼        │  <- Expandable
│      ├── 🔍 Analysis                        │  <- /zero-day
│      └── 📋 ZDA Reports                     │  <- /zero-day/reports
├─────────────────────────────────────────────┤
│  Settings                                   │
│  ⚙️  Configuration                          │
└─────────────────────────────────────────────┘
```

---

## Implementation

### 1. Update Navigation Sidebar

**File:** `src/web-ui/components/app-sidebar.tsx`

#### Update Imports

```typescript
import {
    ShieldCheck,
    LayoutDashboard,
    FileText,
    Settings,
    Users,
    AlertTriangle,
    GitBranch,
    Search,
    ClipboardList,
    ChevronDown,
} from "lucide-react"

import {
    Sidebar,
    SidebarContent,
    SidebarGroup,
    SidebarGroupContent,
    SidebarGroupLabel,
    SidebarHeader,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    SidebarMenuSub,
    SidebarMenuSubButton,
    SidebarMenuSubItem,
    SidebarRail,
} from "@/components/ui/sidebar"

import {
    Collapsible,
    CollapsibleContent,
    CollapsibleTrigger,
} from "@/components/ui/collapsible"
```

#### Update Navigation Data Structure

```typescript
const data = {
    navMain: [
        {
            title: "Platform",
            url: "#",
            items: [
                {
                    title: "Dashboard",
                    url: "/",
                    icon: LayoutDashboard,
                },
                {
                    title: "Findings",
                    url: "/findings",
                    icon: AlertTriangle,
                },
                {
                    title: "Repositories",
                    url: "/repositories",
                    icon: GitBranch,
                },
                {
                    title: "Zero Day Analysis",
                    icon: ShieldCheck,
                    isExpandable: true,
                    items: [
                        {
                            title: "Analysis",
                            url: "/zero-day",
                            icon: Search,
                        },
                        {
                            title: "ZDA Reports",
                            url: "/zero-day/reports",
                            icon: ClipboardList,
                        },
                    ],
                },
            ],
        },
        {
            title: "Settings",
            url: "#",
            items: [
                {
                    title: "Configuration",
                    url: "/settings",
                    icon: Settings,
                },
            ],
        },
    ],
}
```

#### Update Sidebar Component to Support Submenus

```typescript
export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
    const [zdaOpen, setZdaOpen] = React.useState(true)

    return (
        <Sidebar {...props}>
            <SidebarHeader>
                <div className="flex items-center gap-2 px-4 py-2">
                    <ShieldCheck className="h-6 w-6 text-primary" />
                    <span className="font-bold text-lg">AuditGitHub</span>
                </div>
            </SidebarHeader>
            <SidebarContent>
                {data.navMain.map((group) => (
                    <SidebarGroup key={group.title}>
                        <SidebarGroupLabel>{group.title}</SidebarGroupLabel>
                        <SidebarGroupContent>
                            <SidebarMenu>
                                {group.items.map((item) => (
                                    item.isExpandable ? (
                                        <Collapsible
                                            key={item.title}
                                            open={zdaOpen}
                                            onOpenChange={setZdaOpen}
                                            className="group/collapsible"
                                        >
                                            <SidebarMenuItem>
                                                <CollapsibleTrigger asChild>
                                                    <SidebarMenuButton>
                                                        <item.icon className="h-4 w-4" />
                                                        <span>{item.title}</span>
                                                        <ChevronDown className="ml-auto h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                                                    </SidebarMenuButton>
                                                </CollapsibleTrigger>
                                                <CollapsibleContent>
                                                    <SidebarMenuSub>
                                                        {item.items?.map((subItem) => (
                                                            <SidebarMenuSubItem key={subItem.title}>
                                                                <SidebarMenuSubButton asChild>
                                                                    <a href={subItem.url}>
                                                                        <subItem.icon className="h-4 w-4" />
                                                                        <span>{subItem.title}</span>
                                                                    </a>
                                                                </SidebarMenuSubButton>
                                                            </SidebarMenuSubItem>
                                                        ))}
                                                    </SidebarMenuSub>
                                                </CollapsibleContent>
                                            </SidebarMenuItem>
                                        </Collapsible>
                                    ) : (
                                        <SidebarMenuItem key={item.title}>
                                            <SidebarMenuButton asChild>
                                                <a href={item.url}>
                                                    <item.icon className="h-4 w-4" />
                                                    <span>{item.title}</span>
                                                </a>
                                            </SidebarMenuButton>
                                        </SidebarMenuItem>
                                    )
                                ))}
                            </SidebarMenu>
                        </SidebarGroupContent>
                    </SidebarGroup>
                ))}
            </SidebarContent>
            <SidebarRail />
        </Sidebar>
    )
}
```

---

### 2. Create Collapsible UI Component (if not exists)

**File:** `src/web-ui/components/ui/collapsible.tsx`

```typescript
"use client"

import * as React from "react"
import * as CollapsiblePrimitive from "@radix-ui/react-collapsible"

const Collapsible = CollapsiblePrimitive.Root

const CollapsibleTrigger = CollapsiblePrimitive.CollapsibleTrigger

const CollapsibleContent = CollapsiblePrimitive.CollapsibleContent

export { Collapsible, CollapsibleTrigger, CollapsibleContent }
```

**Install dependency if needed:**

```bash
npm install @radix-ui/react-collapsible
```

---

### 3. Create ZDA Reports Page

**File:** `src/web-ui/app/zero-day/reports/page.tsx`

```typescript
import { ZDAReportsView } from "@/components/ZDAReportsView"

export default function ZDAReportsPage() {
    return (
        <div className="container mx-auto py-6">
            <h1 className="text-3xl font-bold mb-6">ZDA Reports</h1>
            <p className="text-muted-foreground mb-6">
                View and manage your saved Zero Day Analysis reports.
            </p>
            <ZDAReportsView />
        </div>
    )
}
```

---

### 4. Create ZDA Reports View Component

**File:** `src/web-ui/components/ZDAReportsView.tsx`

```typescript
"use client"

import * as React from "react"
import { useState, useEffect } from "react"
import { Trash2, Clock, ChevronRight, Search, Download, Eye, AlertTriangle } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import ReactMarkdown from "react-markdown"

interface RepositoryResult {
    repository: string
    repository_id: string
    reason?: string
    source?: string
    matched_sources?: string[]
}

interface AnalysisResult {
    answer: string
    affected_repositories: RepositoryResult[]
    plan?: any
    execution_summary?: string[]
}

interface QueryHistory {
    id: string
    timestamp: string
    query: string
    scope: string[]
    result: AnalysisResult
    repoCount: number
}

export function ZDAReportsView() {
    const [queryHistory, setQueryHistory] = useState<QueryHistory[]>([])
    const [searchTerm, setSearchTerm] = useState("")
    const [selectedReport, setSelectedReport] = useState<QueryHistory | null>(null)
    const [viewDialogOpen, setViewDialogOpen] = useState(false)

    // Load history from localStorage on mount
    useEffect(() => {
        try {
            const saved = localStorage.getItem('zda-history')
            if (saved) {
                setQueryHistory(JSON.parse(saved))
            }
        } catch (err) {
            console.error('Failed to load history:', err)
        }
    }, [])

    // Delete single report
    const deleteReport = (id: string) => {
        const updated = queryHistory.filter(entry => entry.id !== id)
        setQueryHistory(updated)
        try {
            localStorage.setItem('zda-history', JSON.stringify(updated))
        } catch (err) {
            console.error('Failed to save history:', err)
        }
    }

    // Clear all history
    const clearAllHistory = () => {
        setQueryHistory([])
        try {
            localStorage.removeItem('zda-history')
        } catch (err) {
            console.error('Failed to clear history:', err)
        }
    }

    // View report details
    const viewReport = (entry: QueryHistory) => {
        setSelectedReport(entry)
        setViewDialogOpen(true)
    }

    // Export functionality
    const handleExport = async (entry: QueryHistory, format: 'pdf' | 'json' | 'docx' | 'csv' | 'md') => {
        const exportData = {
            query: entry.query,
            timestamp: entry.timestamp,
            scope: entry.scope,
            analysis: entry.result.answer,
            affected_repositories: entry.result.affected_repositories,
            plan: entry.result.plan,
            execution_summary: entry.result.execution_summary
        }

        try {
            if (format === 'json') {
                const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
                downloadBlob(blob, `zda-report-${entry.id}.json`)
                return
            }

            if (format === 'md') {
                const markdown = generateMarkdown(exportData)
                const blob = new Blob([markdown], { type: 'text/markdown' })
                downloadBlob(blob, `zda-report-${entry.id}.md`)
                return
            }

            if (format === 'csv') {
                const csv = generateCSV(entry.result.affected_repositories)
                const blob = new Blob([csv], { type: 'text/csv' })
                downloadBlob(blob, `zda-report-${entry.id}.csv`)
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
            downloadBlob(blob, `zda-report-${entry.id}.${extension}`)

        } catch (err) {
            console.error('Export failed:', err)
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

    // Filter reports by search term
    const filteredHistory = queryHistory.filter(entry =>
        entry.query.toLowerCase().includes(searchTerm.toLowerCase()) ||
        entry.scope.some(s => s.toLowerCase().includes(searchTerm.toLowerCase()))
    )

    return (
        <div className="space-y-6">
            {/* Search and Actions Bar */}
            <Card>
                <CardHeader>
                    <div className="flex justify-between items-center">
                        <div>
                            <CardTitle className="flex items-center gap-2">
                                <Clock className="h-5 w-5" />
                                Saved Analysis Reports
                            </CardTitle>
                            <CardDescription>
                                {queryHistory.length} report{queryHistory.length !== 1 ? 's' : ''} saved
                            </CardDescription>
                        </div>
                        {queryHistory.length > 0 && (
                            <Button variant="destructive" size="sm" onClick={clearAllHistory}>
                                <Trash2 className="h-4 w-4 mr-2" />
                                Clear All
                            </Button>
                        )}
                    </div>
                </CardHeader>
                <CardContent>
                    <div className="flex gap-4">
                        <div className="relative flex-1">
                            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                                placeholder="Search reports by query or scope..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="pl-10"
                            />
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Reports List */}
            {filteredHistory.length === 0 ? (
                <Card>
                    <CardContent className="flex flex-col items-center justify-center py-12">
                        <AlertTriangle className="h-12 w-12 text-muted-foreground mb-4" />
                        <h3 className="text-lg font-semibold mb-2">No Reports Found</h3>
                        <p className="text-muted-foreground text-center max-w-md">
                            {queryHistory.length === 0
                                ? "You haven't run any Zero Day analyses yet. Go to the Analysis page to get started."
                                : "No reports match your search criteria."}
                        </p>
                        {queryHistory.length === 0 && (
                            <Button className="mt-4" asChild>
                                <a href="/zero-day">Run Analysis</a>
                            </Button>
                        )}
                    </CardContent>
                </Card>
            ) : (
                <div className="space-y-4">
                    {filteredHistory.map((entry) => (
                        <Card key={entry.id} className="hover:bg-accent/50 transition-colors">
                            <CardContent className="py-4">
                                <div className="flex justify-between items-start">
                                    <div className="flex-1 min-w-0 cursor-pointer" onClick={() => viewReport(entry)}>
                                        <h3 className="font-semibold text-lg truncate pr-4">
                                            {entry.query}
                                        </h3>
                                        <div className="flex items-center gap-3 mt-2 text-sm text-muted-foreground">
                                            <span className="flex items-center gap-1">
                                                <Clock className="h-3 w-3" />
                                                {new Date(entry.timestamp).toLocaleString()}
                                            </span>
                                            <Badge variant={entry.repoCount > 0 ? "destructive" : "secondary"}>
                                                {entry.repoCount} repo{entry.repoCount !== 1 ? 's' : ''} affected
                                            </Badge>
                                            {entry.scope && entry.scope.length > 0 && !entry.scope.includes("all") && (
                                                <span className="text-blue-600 dark:text-blue-400">
                                                    Scope: {entry.scope.join(', ')}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={() => viewReport(entry)}
                                        >
                                            <Eye className="h-4 w-4 mr-1" />
                                            View
                                        </Button>
                                        <DropdownMenu>
                                            <DropdownMenuTrigger asChild>
                                                <Button variant="outline" size="sm">
                                                    <Download className="h-4 w-4 mr-1" />
                                                    Export
                                                </Button>
                                            </DropdownMenuTrigger>
                                            <DropdownMenuContent align="end">
                                                <DropdownMenuItem onClick={() => handleExport(entry, 'pdf')}>
                                                    Export as PDF
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExport(entry, 'json')}>
                                                    Export as JSON
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExport(entry, 'docx')}>
                                                    Export as DOCX
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExport(entry, 'csv')}>
                                                    Export as CSV
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExport(entry, 'md')}>
                                                    Export as Markdown
                                                </DropdownMenuItem>
                                            </DropdownMenuContent>
                                        </DropdownMenu>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => deleteReport(entry.id)}
                                            className="text-destructive hover:text-destructive"
                                        >
                                            <Trash2 className="h-4 w-4" />
                                        </Button>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    ))}
                </div>
            )}

            {/* View Report Dialog - 75% of browser screen size */}
            <Dialog open={viewDialogOpen} onOpenChange={setViewDialogOpen}>
                <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
                    <DialogHeader className="flex-shrink-0">
                        <div className="flex items-center justify-between">
                            <div>
                                <DialogTitle>Analysis Report</DialogTitle>
                                <DialogDescription>
                                    {selectedReport && new Date(selectedReport.timestamp).toLocaleString()}
                                </DialogDescription>
                            </div>
                            {selectedReport && (
                                <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                        <Button variant="outline" size="sm">
                                            <Download className="h-4 w-4 mr-1" />
                                            Export
                                        </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end">
                                        <DropdownMenuItem onClick={() => handleExport(selectedReport, 'pdf')}>
                                            Export as PDF
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={() => handleExport(selectedReport, 'json')}>
                                            Export as JSON
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={() => handleExport(selectedReport, 'docx')}>
                                            Export as DOCX
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={() => handleExport(selectedReport, 'csv')}>
                                            Export as CSV
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={() => handleExport(selectedReport, 'md')}>
                                            Export as Markdown
                                        </DropdownMenuItem>
                                    </DropdownMenuContent>
                                </DropdownMenu>
                            )}
                        </div>
                    </DialogHeader>
                    {selectedReport && (
                        <div className="flex-1 overflow-y-auto space-y-6 pr-2">
                            {/* Query and Scope */}
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <h4 className="font-semibold mb-2">Query</h4>
                                    <p className="text-muted-foreground bg-muted p-3 rounded text-sm">
                                        {selectedReport.query}
                                    </p>
                                </div>
                                <div>
                                    <h4 className="font-semibold mb-2">Scope</h4>
                                    <div className="flex gap-2 flex-wrap">
                                        {selectedReport.scope.map(s => (
                                            <Badge key={s} variant="outline">{s}</Badge>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            {/* AI Analysis Card */}
                            <Card>
                                <CardHeader className="pb-2">
                                    <div className="flex items-center justify-between">
                                        <CardTitle className="text-lg">AI Analysis</CardTitle>
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
                                                <DropdownMenuItem onClick={() => handleExport(selectedReport, 'pdf')}>
                                                    Export as PDF
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExport(selectedReport, 'json')}>
                                                    Export as JSON
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExport(selectedReport, 'docx')}>
                                                    Export as DOCX
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExport(selectedReport, 'csv')}>
                                                    Export as CSV
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExport(selectedReport, 'md')}>
                                                    Export as Markdown
                                                </DropdownMenuItem>
                                            </DropdownMenuContent>
                                        </DropdownMenu>
                                    </div>
                                </CardHeader>
                                <CardContent>
                                    <div className="prose dark:prose-invert max-w-none">
                                        <ReactMarkdown>{selectedReport.result.answer}</ReactMarkdown>
                                    </div>
                                </CardContent>
                            </Card>

                            {/* Affected Repositories Card */}
                            <Card>
                                <CardHeader className="pb-2">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <CardTitle className="text-lg">
                                                Affected Repositories ({selectedReport.result.affected_repositories.length})
                                            </CardTitle>
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
                                                <DropdownMenuItem onClick={() => handleExportRepoList(selectedReport, 'pdf')}>
                                                    Export as PDF
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExportRepoList(selectedReport, 'json')}>
                                                    Export as JSON
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExportRepoList(selectedReport, 'docx')}>
                                                    Export as DOCX
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExportRepoList(selectedReport, 'csv')}>
                                                    Export as CSV
                                                </DropdownMenuItem>
                                                <DropdownMenuItem onClick={() => handleExportRepoList(selectedReport, 'md')}>
                                                    Export as Markdown
                                                </DropdownMenuItem>
                                            </DropdownMenuContent>
                                        </DropdownMenu>
                                    </div>
                                </CardHeader>
                                <CardContent>
                                    {selectedReport.result.affected_repositories.length === 0 ? (
                                        <p className="text-muted-foreground">No affected repositories found.</p>
                                    ) : (
                                        <div className="space-y-2">
                                            {selectedReport.result.affected_repositories.map((repo, idx) => (
                                                <div key={idx} className="flex justify-between items-center p-3 border rounded bg-card hover:bg-accent/50 transition-colors">
                                                    <div>
                                                        <a
                                                            href={`/projects/${repo.repository_id}`}
                                                            className="font-medium text-primary hover:underline"
                                                        >
                                                            {repo.repository}
                                                        </a>
                                                        <p className="text-sm text-muted-foreground">
                                                            {repo.reason || 'Context match'}
                                                        </p>
                                                    </div>
                                                    <Badge variant="outline">{repo.source || '-'}</Badge>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </CardContent>
                            </Card>
                        </div>
                    )}
                </DialogContent>
            </Dialog>
        </div>
    )
}
```

---

### 5. Update ZeroDayView Component

**File:** `src/web-ui/components/ZeroDayView.tsx`

#### Remove the Recent Analyses Card

Remove the following section from `ZeroDayView.tsx` (approximately lines 455-505):

```typescript
// REMOVE THIS ENTIRE BLOCK:
{/* Recent Analyses */}
{queryHistory.length > 0 && !result && (
    <Card>
        <CardHeader>
            <div className="flex justify-between items-center">
                <div>
                    <CardTitle className="flex items-center gap-2">
                        <Clock className="h-5 w-5" />
                        Recent Analyses
                    </CardTitle>
                    <CardDescription>Click to restore previous results</CardDescription>
                </div>
                <Button variant="ghost" size="sm" onClick={clearHistory}>
                    <Trash2 className="h-4 w-4 mr-2" />
                    Clear History
                </Button>
            </div>
        </CardHeader>
        <CardContent>
            {/* ... history list ... */}
        </CardContent>
    </Card>
)}
```

#### Remove Unused State and Functions (Optional Cleanup)

The following can be removed if only needed for the Recent Analyses card:
- `restoreQuery` function
- `clearHistory` function

However, keep:
- `queryHistory` state (still used for saving new analyses)
- `saveToHistory` function (still used to save results)

#### Add Link to ZDA Reports

Add a small info section or link below the query input:

```typescript
{/* Add after the CardContent with query input */}
<div className="text-sm text-muted-foreground flex items-center gap-2 px-6 pb-4">
    <Clock className="h-4 w-4" />
    <span>View your saved analyses in</span>
    <a href="/zero-day/reports" className="text-primary hover:underline font-medium">
        ZDA Reports
    </a>
</div>
```

---

## File Changes Summary

| File | Changes |
|------|---------|
| `src/web-ui/components/app-sidebar.tsx` | Add submenu structure for Zero Day Analysis with Analysis and ZDA Reports items |
| `src/web-ui/components/ui/collapsible.tsx` | Create new collapsible UI component (if not exists) |
| `src/web-ui/app/zero-day/reports/page.tsx` | Create new page for ZDA Reports |
| `src/web-ui/components/ZDAReportsView.tsx` | Create new component for displaying saved reports |
| `src/web-ui/components/ZeroDayView.tsx` | Remove Recent Analyses card, add link to ZDA Reports |

---

## Data Flow

### Shared State (localStorage)

Both components share the same localStorage key `'zda-history'`:

- **ZeroDayView** writes to localStorage when a new analysis completes
- **ZDAReportsView** reads from localStorage to display saved reports

```
┌─────────────────────┐     localStorage      ┌─────────────────────┐
│   ZeroDayView       │ ───── writes ──────▶  │   'zda-history'     │
│   (Analysis page)   │                       │                     │
└─────────────────────┘                       └─────────────────────┘
                                                       │
                                                       │ reads
                                                       ▼
                                              ┌─────────────────────┐
                                              │   ZDAReportsView    │
                                              │   (Reports page)    │
                                              └─────────────────────┘
```

---

## Testing Checklist

- [ ] Navigation shows "Zero Day Analysis" as expandable menu
- [ ] Submenu shows "Analysis" and "ZDA Reports" items
- [ ] Clicking "Analysis" navigates to `/zero-day`
- [ ] Clicking "ZDA Reports" navigates to `/zero-day/reports`
- [ ] Zero Day Analysis page no longer shows Recent Analyses card
- [ ] Zero Day Analysis page shows link to ZDA Reports
- [ ] ZDA Reports page displays all saved analyses
- [ ] Search filter works on ZDA Reports page
- [ ] View button opens report details dialog
- [ ] **View Report dialog is 75% of browser screen size (width and height)**
- [ ] **Export button appears in View Report dialog header**
- [ ] **Export as PDF works from within the dialog**
- [ ] Export dropdown works for each saved report in the list
- [ ] Delete button removes individual report
- [ ] Clear All button removes all reports
- [ ] New analyses from Analysis page appear in ZDA Reports
- [ ] Empty state shows when no reports exist
- [ ] Submenu remains expanded when on either Zero Day page

---

## Accessibility

- Collapsible menu is keyboard navigable
- Submenu items have proper focus states
- Dialog has proper ARIA labels
- Icons have appropriate alt text via lucide-react
- Color contrast meets WCAG standards

---

## To Deploy

### 1. Restart the Web UI Service

```bash
docker-compose restart web-ui
```

The `web-ui` container will automatically install dependencies (including `@radix-ui/react-collapsible`) on startup via the `npm install` command in its entrypoint.

### 2. Verify the Service is Running

```bash
docker-compose logs -f web-ui
```

Wait for the Next.js development server to show "Ready" before testing.

### 3. Test the Feature

1. Navigate to the sidebar and verify submenu appears under "Zero Day Analysis"
2. Click "Analysis" and verify the analysis page works at `/zero-day`
3. Run an analysis to generate data
4. Click "ZDA Reports" and verify reports appear at `/zero-day/reports`
5. Test view, export, and delete functionality
