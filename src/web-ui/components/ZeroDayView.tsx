"use client"

import * as React from "react"
import { useState, useEffect } from "react"
import { Send, Loader2, ShieldAlert, CheckCircle2, Search, Clock, FileEdit, Download, ClipboardList } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { PromptEditorDialog } from "@/components/PromptEditorDialog"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import ReactMarkdown from "react-markdown"
import { API_BASE, apiFetch } from "@/lib/api"

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
    // Threat-hunting output. coverage_notes lists surfaces the run could not examine;
    // hunt_enabled is false when the account lacks hunt:execute, in which case no
    // external evidence was gathered at all.
    hunt_evidence?: Record<string, any>
    coverage_notes?: string[]
    hunt_enabled?: boolean
    organizations_in_scope?: string[]
    // Parts 1 and 2 of the exported report -- the plain-language summary and the ordered
    // plan -- written once when the analysis ran so every export of this result matches.
    briefing?: Record<string, any>
}

interface QueryHistory {
    id: string
    timestamp: string
    query: string
    scope: string[]
    result: AnalysisResult
    repoCount: number
}

export function ZeroDayView() {
    const [query, setQuery] = useState("")
    const [isLoading, setIsLoading] = useState(false)
    const [result, setResult] = useState<AnalysisResult | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [queryHistory, setQueryHistory] = useState<QueryHistory[]>([])
    const [promptEditorOpen, setPromptEditorOpen] = useState(false)

    // Scope selection state
    const [selectedScopes, setSelectedScopes] = useState<string[]>(["all"])
    const availableScopes = [
        { id: "all", label: "All Sources", description: "Search everywhere" },
        { id: "dependencies", label: "Dependencies (SBOM)", description: "Package libraries and modules" },
        { id: "findings", label: "Security Findings", description: "CVEs, CWEs, vulnerabilities" },
        { id: "languages", label: "Languages & Tech Stack", description: "Programming languages used" },
    ]

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

    // Save to localStorage after history changes
    const saveToHistory = (query: string, scope: string[], result: AnalysisResult) => {
        const entry: QueryHistory = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            query,
            scope,
            result,
            repoCount: result.affected_repositories.length
        }
        const updated = [entry, ...queryHistory].slice(0, 10) // Keep last 10
        setQueryHistory(updated)
        try {
            localStorage.setItem('zda-history', JSON.stringify(updated))
        } catch (err) {
            console.error('Failed to save history:', err)
        }
    }

    const handleScopeToggle = (scopeId: string) => {
        if (scopeId === "all") {
            setSelectedScopes(["all"])
        } else {
            const newScopes = selectedScopes.filter(s => s !== "all")
            if (newScopes.includes(scopeId)) {
                const filtered = newScopes.filter(s => s !== scopeId)
                setSelectedScopes(filtered.length === 0 ? ["all"] : filtered)
            } else {
                setSelectedScopes([...newScopes, scopeId])
            }
        }
    }

    const handleAnalyze = async () => {
        if (!query.trim()) return

        setIsLoading(true)
        setError(null)
        setResult(null)

        try {
            const scopeToSend = selectedScopes.includes("all") ? null : selectedScopes

            const response = await apiFetch(`${API_BASE}/ai/zero-day`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    query,
                    scope: scopeToSend
                }),
            })

            if (!response.ok) {
                const errorData = await response.json()
                throw new Error(errorData.detail || "Analysis failed")
            }

            const data = await response.json()
            setResult(data)

            // Save to history
            saveToHistory(query, selectedScopes, data)
        } catch (err) {
            console.error(err)
            setError(err instanceof Error ? err.message : "An unexpected error occurred")
        } finally {
            setIsLoading(false)
        }
    }

    // Export functionality
    const handleExport = async (format: 'pdf' | 'json' | 'docx' | 'csv' | 'md') => {
        if (!result) return

        const exportData = {
            query,
            timestamp: new Date().toISOString(),
            scope: selectedScopes,
            analysis: result.answer,
            affected_repositories: result.affected_repositories,
            plan: result.plan,
            execution_summary: result.execution_summary,
            // Forwarded so the exported report carries the evidence and the blind spots.
            // Omitting these produces a document that reads as a complete hunt while
            // silently dropping every caveat that qualifies its conclusions.
            hunt_evidence: result.hunt_evidence,
            coverage_notes: result.coverage_notes,
            hunt_enabled: result.hunt_enabled,
            organizations_in_scope: result.organizations_in_scope,
            // The written summary and priority plan that open the report. Authored once
            // when the analysis ran and echoed back here, so exporting the same result
            // twice produces the same document. Dropping it does not break the export --
            // it silently downgrades it to the rule-written wording, which is exactly the
            // kind of difference nobody notices until two copies of one report disagree.
            briefing: result.briefing
        }

        try {
            // For JSON and Markdown, handle client-side
            if (format === 'json') {
                const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
                downloadBlob(blob, `zda-analysis-${Date.now()}.json`)
                return
            }

            if (format === 'csv') {
                const csv = generateCSV(result.affected_repositories)
                const blob = new Blob([csv], { type: 'text/csv' })
                downloadBlob(blob, `zda-analysis-${Date.now()}.csv`)
                return
            }

            // PDF, DOCX and Markdown are all rendered server-side from one builder.
            // The Markdown export used to be assembled here and omitted the coverage
            // and blind-spot sections the PDF carried, so the two documents disagreed
            // about how complete the hunt was.
            const response = await apiFetch(`${API_BASE}/ai/zero-day/export/${format}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(exportData)
            })

            if (!response.ok) {
                const body = await response.json().catch(() => null)
                throw new Error(body?.detail || `Export failed (${response.status})`)
            }

            const blob = await response.blob()
            downloadBlob(blob, `zda-analysis-${Date.now()}.${format}`)

        } catch (err) {
            const message = err instanceof Error ? err.message : 'Export failed'
            console.error('Export failed:', message)
            setError(message)
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

    // Export functionality for Repository List
    const handleExportRepoList = async (format: 'pdf' | 'json' | 'docx' | 'csv' | 'md') => {
        if (!result || !result.affected_repositories) return

        const exportData = {
            query,
            timestamp: new Date().toISOString(),
            scope: selectedScopes,
            total_repositories: result.affected_repositories.length,
            repositories: result.affected_repositories,
            // A repository list is the artifact most likely to be forwarded alone, and a
            // short or empty list is exactly where the reader needs to know what could
            // not be seen. The backend renders these as a coverage section.
            coverage_notes: result.coverage_notes,
            hunt_enabled: result.hunt_enabled,
            organizations_in_scope: result.organizations_in_scope
        }

        try {
            // For JSON, handle client-side
            if (format === 'json') {
                const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
                downloadBlob(blob, `affected-repos-${Date.now()}.json`)
                return
            }

            // For CSV, handle client-side
            if (format === 'csv') {
                const csv = generateCSV(result.affected_repositories)
                const blob = new Blob([csv], { type: 'text/csv' })
                downloadBlob(blob, `affected-repos-${Date.now()}.csv`)
                return
            }

            // PDF, DOCX and Markdown are rendered server-side from the same builder, so
            // the coverage section travels with every format of this list.
            const response = await apiFetch(`${API_BASE}/ai/zero-day/export/repos/${format}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(exportData)
            })

            if (!response.ok) {
                const body = await response.json().catch(() => null)
                throw new Error(body?.detail || `Export failed (${response.status})`)
            }

            const blob = await response.blob()
            downloadBlob(blob, `affected-repos-${Date.now()}.${format}`)

        } catch (err) {
            const message = err instanceof Error ? err.message : 'Export failed'
            console.error('Export failed:', message)
            setError(message)
        }
    }

    return (
        <div className="space-y-6">
            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <div>
                            <CardTitle>Zero Day & Vulnerability Analysis</CardTitle>
                            <CardDescription>
                                Ask our AI agent to identify repositories susceptible to specific zero-day vulnerabilities or security conditions.
                            </CardDescription>
                        </div>
                        <Button
                            variant="outline"
                            size="icon"
                            onClick={() => setPromptEditorOpen(true)}
                            title="Edit AI Prompt"
                        >
                            <FileEdit className="h-4 w-4" />
                        </Button>
                    </div>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex gap-4">
                        <Input
                            placeholder="e.g., 'Identify all repositories using React' or 'Find projects affected by CVE-2024-12345'"
                            value={query}
                            onChange={(e) => setQuery(e.target.value)}
                            onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
                            className="flex-1"
                        />
                        <Button onClick={handleAnalyze} disabled={isLoading || !query.trim()}>
                            {isLoading ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Analyzing...
                                </>
                            ) : (
                                <>
                                    <Search className="mr-2 h-4 w-4" />
                                    Analyze
                                </>
                            )}
                        </Button>
                    </div>

                    {/* Scope Selector */}
                    <div className="space-y-2">
                        <Label className="text-sm font-medium">Search Scope</Label>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            {availableScopes.map((scope) => (
                                <div key={scope.id} className="flex items-start space-x-2">
                                    <Checkbox
                                        id={scope.id}
                                        checked={selectedScopes.includes(scope.id)}
                                        onCheckedChange={() => handleScopeToggle(scope.id)}
                                    />
                                    <div className="grid gap-0.5 leading-none">
                                        <label
                                            htmlFor={scope.id}
                                            className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                                        >
                                            {scope.label}
                                        </label>
                                        <p className="text-xs text-muted-foreground">
                                            {scope.description}
                                        </p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Link to ZDA Reports */}
                    <div className="flex items-center gap-2 text-sm text-muted-foreground pt-2 border-t">
                        <ClipboardList className="h-4 w-4" />
                        <span>View your saved analyses in</span>
                        <a href="/zero-day/reports" className="text-primary hover:underline font-medium">
                            ZDA Reports
                        </a>
                    </div>
                </CardContent>
            </Card>

            {error && (
                <Alert variant="destructive">
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Error</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                </Alert>
            )}

            {result && (
                <div className="space-y-6">
                    <div className="grid gap-6 md:grid-cols-2">
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

                        {/* Coverage limits, shown next to the analysis rather than only in
                            the exported file. A reader who sees the conclusions on screen
                            needs to see, in the same place, which surfaces went unexamined —
                            otherwise an empty result reads as an all-clear. */}
                        {(result.hunt_enabled === false || (result.coverage_notes?.length ?? 0) > 0) && (
                            <Card className="mt-4 border-amber-500/60">
                                <CardHeader>
                                    <CardTitle className="text-base">Coverage and Blind Spots</CardTitle>
                                    <CardDescription>
                                        {result.hunt_enabled === false
                                            ? "External evidence was not gathered: this account lacks the hunt:execute permission. Registry ground truth, CI/CD activity, endpoint telemetry and alerts were not consulted."
                                            : "Surfaces this run could not examine. An absence of findings on these is not a finding of absence."}
                                        {result.organizations_in_scope?.length
                                            ? ` Organizations in scope: ${result.organizations_in_scope.join(', ')}.`
                                            : ''}
                                    </CardDescription>
                                </CardHeader>
                                {(result.coverage_notes?.length ?? 0) > 0 && (
                                    <CardContent>
                                        <ul className="list-disc pl-5 space-y-1 text-sm">
                                            {result.coverage_notes!.map((note, i) => (
                                                <li key={i}>{note}</li>
                                            ))}
                                        </ul>
                                    </CardContent>
                                )}
                            </Card>
                        )}
                    </div>

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

                    {result.plan && (
                        <Card className="opacity-80">
                            <CardHeader>
                                <CardTitle className="text-sm text-muted-foreground">Analysis Strategy (Debug)</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <pre className="bg-muted p-4 rounded text-xs overflow-auto max-h-40">
                                    {JSON.stringify(result.plan, null, 2)}
                                </pre>
                            </CardContent>
                        </Card>
                    )}
                </div>
            )}

            <PromptEditorDialog
                projectId="zero-day-analysis"
                isOpen={promptEditorOpen}
                onOpenChange={setPromptEditorOpen}
                promptEndpoint="/ai/zero-day/prompt"
                validateEndpoint="/ai/zero-day/prompt/validate"
            />
        </div>
    )
}
