"use client"

import * as React from "react"
import { useState, useEffect } from "react"
import { Send, Loader2, ShieldAlert, CheckCircle2, Search, ChevronRight, Trash2, Clock, FileEdit } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { PromptEditorDialog } from "@/components/PromptEditorDialog"
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

    // Restore previous query
    const restoreQuery = (entry: QueryHistory) => {
        setQuery(entry.query)
        setSelectedScopes(entry.scope)
        setResult(entry.result)
        setError(null)
    }

    // Clear history
    const clearHistory = () => {
        setQueryHistory([])
        try {
            localStorage.removeItem('zda-history')
        } catch (err) {
            console.error('Failed to clear history:', err)
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

            const response = await fetch("http://localhost:8000/ai/zero-day", {
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
                </CardContent>
            </Card>

            {error && (
                <Alert variant="destructive">
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Error</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                </Alert>
            )}

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
                        <div className="space-y-2">
                            {queryHistory.map((entry) => (
                                <div
                                    key={entry.id}
                                    className="flex justify-between items-center p-3 border rounded-lg cursor-pointer hover:bg-accent transition-colors"
                                    onClick={() => restoreQuery(entry)}
                                >
                                    <div className="flex-1 min-w-0">
                                        <p className="font-medium text-sm truncate">{entry.query}</p>
                                        <div className="flex items-center gap-2 text-xs text-muted-foreground mt-1">
                                            <span>{new Date(entry.timestamp).toLocaleString()}</span>
                                            <span>•</span>
                                            <span className={entry.repoCount > 0 ? "text-orange-600 dark:text-orange-400" : "text-green-600 dark:text-green-400"}>
                                                {entry.repoCount} repo{entry.repoCount !== 1 ? 's' : ''} found
                                            </span>
                                            {entry.scope && entry.scope.length > 0 && !entry.scope.includes("all") && (
                                                <>
                                                    <span>•</span>
                                                    <span className="text-blue-600 dark:text-blue-400">
                                                        {entry.scope.join(', ')}
                                                    </span>
                                                </>
                                            )}
                                        </div>
                                    </div>
                                    <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0 ml-2" />
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}

            {result && (
                <div className="space-y-6">
                    <div className="grid gap-6 md:grid-cols-2">
                        <Card className="md:col-span-2">
                            <CardHeader>
                                <CardTitle>AI Analysis</CardTitle>
                            </CardHeader>
                            <CardContent className="prose dark:prose-invert max-w-none">
                                <ReactMarkdown>{result.answer}</ReactMarkdown>
                            </CardContent>
                        </Card>
                    </div>

                    <Card>
                        <CardHeader>
                            <CardTitle>Affected Repositories ({result.affected_repositories.length})</CardTitle>
                            <CardDescription>
                                Projects identified based on your query.
                            </CardDescription>
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
