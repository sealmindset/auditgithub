"use client"

import { useEffect, useState } from "react"
import { useParams, useRouter } from "next/navigation"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { AiRemediationCard } from "@/components/ai-remediation-card"
import { ExceptionDialog } from "@/components/ExceptionDialog"
import { AskAIDialog } from "@/components/AskAIDialog"
import { JournalModal } from "@/components/JournalModal"
import { SeverityEditor } from "@/components/SeverityEditor"
import { RiskScoreBadge } from "@/components/RiskScoreBadge"
import { Loader2, ArrowLeft, Sparkles, GitCommit, User, Calendar, Clock, FileCode, Archive, BookOpen, AlertTriangle, Shield, CheckCircle2, FileText } from "lucide-react"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"

const API_BASE = "http://localhost:8000"

export default function FindingDetailsPage() {
    const params = useParams()
    const router = useRouter()
    const id = params.id as string
    const [finding, setFinding] = useState<any>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    const [journalOpen, setJournalOpen] = useState(false)
    const [includeInReport, setIncludeInReport] = useState(false)
    const [isTogglingReport, setIsTogglingReport] = useState(false)

    const fetchFinding = async () => {
        try {
            const res = await fetch(`${API_BASE}/findings/${id}`)
            if (!res.ok) throw new Error("Finding not found")
            const data = await res.json()
            setFinding(data)
            setIncludeInReport(data.include_in_report || false)
        } catch (err) {
            setError("Failed to load finding details")
        } finally {
            setLoading(false)
        }
    }

    const handleToggleIncludeInReport = async (checked: boolean) => {
        setIsTogglingReport(true)
        try {
            const res = await fetch(`${API_BASE}/findings/${id}/include-in-report`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ include_in_report: checked }),
            })
            if (res.ok) {
                setIncludeInReport(checked)
                setFinding({ ...finding, include_in_report: checked })
            }
        } catch (err) {
            console.error("Failed to toggle include in report:", err)
        } finally {
            setIsTogglingReport(false)
        }
    }

    useEffect(() => {
        if (id) fetchFinding()
    }, [id])

    const getInvestigationStatusBadge = (status: string | null) => {
        switch (status) {
            case "triage":
                return (
                    <Badge className="bg-yellow-500 hover:bg-yellow-600 text-white flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        Triage
                    </Badge>
                )
            case "incident_response":
                return (
                    <Badge className="bg-red-500 hover:bg-red-600 text-white flex items-center gap-1">
                        <Shield className="h-3 w-3" />
                        IR
                    </Badge>
                )
            case "resolved":
                return (
                    <Badge className="bg-green-500 hover:bg-green-600 text-white flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" />
                        Resolved
                    </Badge>
                )
            default:
                return null
        }
    }

    if (loading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    if (error || !finding) {
        return (
            <div className="flex h-screen flex-col items-center justify-center gap-4">
                <p className="text-red-500">{error || "Finding not found"}</p>
                <Button variant="outline" onClick={() => router.back()}>Go Back</Button>
            </div>
        )
    }

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => router.back()}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-2xl font-bold tracking-tight">{finding.title}</h1>
                    <div className="flex items-center gap-2 text-muted-foreground">
                        {finding.repository_id ? (
                            <Link href={`/projects/${finding.repository_id}`} className="text-blue-600 hover:underline">
                                {finding.repo_name}
                            </Link>
                        ) : (
                            <span>{finding.repo_name}</span>
                        )}
                        <span>•</span>
                        <span>{finding.id.substring(0, 8)}</span>
                        {/* Investigation Status Badge */}
                        {finding.investigation_status && (
                            <>
                                <span>•</span>
                                {getInvestigationStatusBadge(finding.investigation_status)}
                            </>
                        )}
                    </div>
                </div>
                <div className="ml-auto flex items-center gap-2">
                    {/* Include in Report Checkbox */}
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-md border bg-card hover:bg-accent/50 transition-colors">
                        <Checkbox
                            id="include-in-report"
                            checked={includeInReport}
                            onCheckedChange={(checked) => handleToggleIncludeInReport(checked as boolean)}
                            disabled={isTogglingReport}
                            className="data-[state=checked]:bg-red-600 data-[state=checked]:border-red-600"
                        />
                        <Label 
                            htmlFor="include-in-report" 
                            className="text-sm font-medium cursor-pointer flex items-center gap-1.5"
                        >
                            <FileText className="h-4 w-4 text-muted-foreground" />
                            Include in Report
                        </Label>
                    </div>
                    {/* Journal Button */}
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setJournalOpen(true)}
                        className="flex items-center gap-2"
                    >
                        <BookOpen className="h-4 w-4" />
                        Journal
                    </Button>
                    <ExceptionDialog finding={finding} onDeleted={() => router.push("/findings")} />
                    <SeverityEditor
                        findingId={finding.id}
                        currentSeverity={finding.severity}
                        onUpdate={fetchFinding}
                    />
                    <RiskScoreBadge
                        score={finding.risk_score}
                        level={finding.risk_level}
                        factors={finding.risk_factors}
                        size="md"
                    />
                </div>
            </div>

            <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-6">
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0">
                            <CardTitle>Details</CardTitle>
                            <AskAIDialog findingId={finding.id} onDescriptionUpdated={() => {
                                // Refresh finding data after description update
                                fetch(`${API_BASE}/findings/${id}`)
                                    .then(res => res.json())
                                    .then(data => setFinding(data))
                            }} />
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div>
                                <h3 className="font-semibold mb-2">Description</h3>
                                {finding.description?.startsWith('**AI Security Analysis') ? (
                                    <div className="rounded-lg border bg-gradient-to-br from-purple-50 to-blue-50 dark:from-purple-950/20 dark:to-blue-950/20 p-4">
                                        <div className="flex items-center gap-2 mb-3 text-purple-600 dark:text-purple-400">
                                            <Sparkles className="h-4 w-4" />
                                            <span className="text-xs font-medium uppercase tracking-wide">AI-Enhanced Description</span>
                                        </div>
                                        <div className="prose prose-sm dark:prose-invert max-w-none prose-headings:text-base prose-headings:font-semibold prose-p:text-muted-foreground prose-ul:text-muted-foreground prose-li:text-muted-foreground">
                                            <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.description}</ReactMarkdown>
                                        </div>
                                    </div>
                                ) : (
                                    <p className="text-sm text-muted-foreground bg-muted p-3 rounded-md">
                                        {finding.description || 'No description available.'}
                                    </p>
                                )}
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <h3 className="font-semibold">Scanner</h3>
                                    <p className="text-sm">{finding.scanner_name}</p>
                                </div>
                                <div>
                                    <h3 className="font-semibold">Status</h3>
                                    <p className="text-sm capitalize">{finding.status}</p>
                                </div>
                            </div>
                            {finding.file_path && (
                                <div>
                                    <h3 className="font-semibold">Location</h3>
                                    <p className="text-sm font-mono bg-muted p-2 rounded">
                                        {finding.file_path}:{finding.line_start}
                                    </p>
                                </div>
                            )}

                            {/* File Commit History - from GitHub API */}
                            {(finding.file_last_commit_at || finding.repo_pushed_at) && (
                                <div className="border-t pt-4">
                                    <h3 className="font-semibold flex items-center gap-2 mb-3">
                                        <GitCommit className="h-4 w-4 text-muted-foreground" />
                                        File History
                                    </h3>
                                    <div className="bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 rounded-lg p-4 space-y-3">
                                        {finding.file_last_commit_at ? (
                                            <>
                                                <div className="flex items-center justify-between">
                                                    <div className="flex items-center gap-2 text-sm">
                                                        <Calendar className="h-4 w-4 text-blue-500" />
                                                        <span className="text-muted-foreground">Last File Commit</span>
                                                    </div>
                                                    <div className="text-sm font-medium">
                                                        {new Date(finding.file_last_commit_at).toLocaleDateString("en-US", {
                                                            year: "numeric",
                                                            month: "short",
                                                            day: "numeric",
                                                            hour: "2-digit",
                                                            minute: "2-digit"
                                                        })}
                                                    </div>
                                                </div>
                                                {finding.file_last_commit_author && (
                                                    <div className="flex items-center justify-between">
                                                        <div className="flex items-center gap-2 text-sm">
                                                            <User className="h-4 w-4 text-green-500" />
                                                            <span className="text-muted-foreground">Last Author</span>
                                                        </div>
                                                        <div className="text-sm font-medium">
                                                            {finding.file_last_commit_author}
                                                        </div>
                                                    </div>
                                                )}
                                                <div className="flex items-center justify-between text-xs text-muted-foreground pt-2 border-t border-slate-200 dark:border-slate-700">
                                                    <div className="flex items-center gap-1">
                                                        <FileCode className="h-3 w-3" />
                                                        <span>File-level commit data from GitHub</span>
                                                    </div>
                                                    {(() => {
                                                        const days = Math.floor((new Date().getTime() - new Date(finding.file_last_commit_at).getTime()) / (1000 * 60 * 60 * 24))
                                                        const years = Math.floor(days / 365)
                                                        if (years > 0) {
                                                            return (
                                                                <Badge variant={years > 2 ? "destructive" : "secondary"} className="text-xs">
                                                                    <Clock className="h-3 w-3 mr-1" />
                                                                    {years}y old
                                                                </Badge>
                                                            )
                                                        }
                                                        return (
                                                            <Badge variant="secondary" className="text-xs">
                                                                <Clock className="h-3 w-3 mr-1" />
                                                                {days}d old
                                                            </Badge>
                                                        )
                                                    })()}
                                                </div>
                                            </>
                                        ) : finding.repo_pushed_at && (
                                            <>
                                                <div className="flex items-center justify-between">
                                                    <div className="flex items-center gap-2 text-sm">
                                                        <Calendar className="h-4 w-4 text-amber-500" />
                                                        <span className="text-muted-foreground">Last Repo Push</span>
                                                    </div>
                                                    <div className="text-sm font-medium">
                                                        {new Date(finding.repo_pushed_at).toLocaleDateString("en-US", {
                                                            year: "numeric",
                                                            month: "short",
                                                            day: "numeric"
                                                        })}
                                                    </div>
                                                </div>
                                                <div className="text-xs text-muted-foreground">
                                                    Repository-level data (file-specific commit not yet synced)
                                                </div>
                                            </>
                                        )}
                                        {finding.is_archived && (
                                            <div className="flex items-center gap-2 pt-2 border-t border-slate-200 dark:border-slate-700">
                                                <Badge variant="secondary" className="text-xs">
                                                    <Archive className="h-3 w-3 mr-1" />
                                                    Archived Repository
                                                </Badge>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {finding.code_snippet && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Code Context</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <pre className="overflow-x-auto rounded-md bg-slate-950 p-4 text-xs text-slate-50">
                                    <code>{finding.code_snippet}</code>
                                </pre>
                            </CardContent>
                        </Card>
                    )}
                </div>

                <div className="space-y-6">
                    <AiRemediationCard
                        findingId={finding.id}
                        vulnType={finding.title}
                        description={finding.description || ""}
                        context={finding.code_snippet || ""}
                        language="python" // TODO: Detect language dynamically
                        existingRemediations={finding.remediations}
                    />
                </div>
            </div>

            {/* Journal Modal */}
            <JournalModal
                findingId={finding.id}
                isOpen={journalOpen}
                onClose={() => setJournalOpen(false)}
                onStatusChange={(newStatus) => {
                    setFinding({ ...finding, investigation_status: newStatus })
                }}
            />
        </div>
    )
}
