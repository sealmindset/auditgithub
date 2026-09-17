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
import { API_BASE, apiFetch } from "@/lib/api"
import { BackButton, PageHeader, PageShell } from "@/components/ui/page-header"
import { JiraIssueDialog } from "@/components/JiraIssueDialog"
import { AuditBoardIssueDialog } from "@/components/AuditBoardIssueDialog"
import { AuditBoardFiledBadge } from "@/components/AuditBoardFiledBadge"

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
    // Bumped after an AuditBoard filing so the badge re-reads without a reload.
    const [filedRefresh, setFiledRefresh] = useState(0)

    const fetchFinding = async () => {
        try {
            const res = await apiFetch(`${API_BASE}/findings/${id}`)
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
            const res = await apiFetch(`${API_BASE}/findings/${id}/include-in-report`, {
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
                    <Badge className="bg-warning hover:bg-warning text-warning-foreground flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        Triage
                    </Badge>
                )
            case "incident_response":
                return (
                    <Badge className="bg-danger hover:bg-danger text-danger-foreground flex items-center gap-1">
                        <Shield className="h-3 w-3" />
                        IR
                    </Badge>
                )
            case "resolved":
                return (
                    <Badge className="bg-success hover:bg-success text-success-foreground flex items-center gap-1">
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
                <p className="text-danger-text">{error || "Finding not found"}</p>
                <Button variant="outline" onClick={() => router.back()}>Go Back</Button>
            </div>
        )
    }

    return (
        <PageShell>
            <PageHeader
                back={<BackButton onClick={() => router.back()} label="Back to findings" />}
                eyebrow="Finding"
                title={finding.title}
                description={
                    <span className="flex flex-wrap items-center gap-2">
                        {finding.repository_id ? (
                            <Link href={`/projects/${finding.repository_id}`} className="font-medium text-primary-text hover:underline">
                                {finding.repo_name}
                            </Link>
                        ) : (
                            <span>{finding.repo_name}</span>
                        )}
                        <span aria-hidden>•</span>
                        <span className="font-mono text-xs">{finding.id.substring(0, 8)}</span>
                        {finding.investigation_status && (
                            <>
                                <span aria-hidden>•</span>
                                {getInvestigationStatusBadge(finding.investigation_status)}
                            </>
                        )}
                    </span>
                }
                actions={
                <>
                    {/* Include in Report Checkbox */}
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-md border bg-card hover:bg-accent/50 transition-colors">
                        <Checkbox
                            id="include-in-report"
                            checked={includeInReport}
                            onCheckedChange={(checked) => handleToggleIncludeInReport(checked as boolean)}
                            disabled={isTogglingReport}
                            className="data-[state=checked]:bg-danger data-[state=checked]:border-danger"
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
                    <JiraIssueDialog finding={finding} />
                    <AuditBoardIssueDialog
                        finding={finding}
                        onFiled={() => setFiledRefresh((n) => n + 1)}
                    />
                    <AuditBoardFiledBadge findingId={finding.id} refreshKey={filedRefresh} />
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
                </>
                }
            />

            <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-6">
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0">
                            <CardTitle>Details</CardTitle>
                            <AskAIDialog findingId={finding.id} onDescriptionUpdated={() => {
                                // Refresh finding data after description update
                                apiFetch(`${API_BASE}/findings/${id}`)
                                    .then(res => res.json())
                                    .then(data => setFinding(data))
                            }} />
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div>
                                <h3 className="font-semibold mb-2">Description</h3>
                                {finding.description?.startsWith('**AI Security Analysis') ? (
                                    <div className="rounded-lg border bg-gradient-to-br from-ai-soft to-info-soft dark:from-ai/20 dark:to-info/20 p-4">
                                        <div className="flex items-center gap-2 mb-3 text-ai-text">
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
                                    <div className="bg-gradient-to-br from-muted to-muted rounded-lg p-4 space-y-3">
                                        {finding.file_last_commit_at ? (
                                            <>
                                                <div className="flex items-center justify-between">
                                                    <div className="flex items-center gap-2 text-sm">
                                                        <Calendar className="h-4 w-4 text-info-text" />
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
                                                            <User className="h-4 w-4 text-success-text" />
                                                            <span className="text-muted-foreground">Last Author</span>
                                                        </div>
                                                        <div className="text-sm font-medium">
                                                            {finding.file_last_commit_author}
                                                        </div>
                                                    </div>
                                                )}
                                                <div className="flex items-center justify-between text-xs text-muted-foreground pt-2 border-t border-border">
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
                                                        <Calendar className="h-4 w-4 text-warning-text" />
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
                                            <div className="flex items-center gap-2 pt-2 border-t border-border">
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
                                <pre className="overflow-x-auto rounded-md bg-muted p-4 text-xs text-muted-foreground">
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
        </PageShell>
    )
}
