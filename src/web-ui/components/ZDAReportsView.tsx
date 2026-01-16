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

    // Export functionality for Repository List only
    const handleExportRepoList = async (entry: QueryHistory, format: 'pdf' | 'json' | 'docx' | 'csv' | 'md') => {
        const exportData = {
            query: entry.query,
            timestamp: entry.timestamp,
            scope: entry.scope,
            total_repositories: entry.result.affected_repositories.length,
            repositories: entry.result.affected_repositories
        }

        try {
            if (format === 'json') {
                const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
                downloadBlob(blob, `affected-repos-${entry.id}.json`)
                return
            }

            if (format === 'md') {
                const markdown = generateRepoListMarkdown(exportData)
                const blob = new Blob([markdown], { type: 'text/markdown' })
                downloadBlob(blob, `affected-repos-${entry.id}.md`)
                return
            }

            if (format === 'csv') {
                const csv = generateCSV(entry.result.affected_repositories)
                const blob = new Blob([csv], { type: 'text/csv' })
                downloadBlob(blob, `affected-repos-${entry.id}.csv`)
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
            downloadBlob(blob, `affected-repos-${entry.id}.${extension}`)

        } catch (err) {
            console.error('Export failed:', err)
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

            {/* View Report Dialog */}
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
