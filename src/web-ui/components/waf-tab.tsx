"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet"
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import {
    ShieldAlert,
    Code,
    GitCompare,
    Info,
    Search,
    ChevronDown,
    ChevronRight,
    Sparkles,
    Copy,
    Check,
    CheckCircle2,
    Loader2,
    FileCode2,
    Send,
    Bot,
    User,
    AlertTriangle,
    Shield,
    Eye,
    Clock,
    Filter,
    X,
    ArrowLeftRight,
    MessageSquare,
    Lightbulb,
    ExternalLink,
    FileText,
} from "lucide-react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import { API_BASE, apiFetch } from "@/lib/api"
import { useToast } from "@/components/ui/use-toast"

// =============================================================================
// WAF Severity Model
// =============================================================================

const WAF_SEVERITIES = {
    active_risk: {
        label: "Active Risk",
        color: "#dc2626",
        bgColor: "bg-red-100 dark:bg-red-950",
        borderColor: "border-red-500",
        icon: ShieldAlert,
        description: "Live misconfiguration, exploitable now",
    },
    code_risk: {
        label: "Code Risk",
        color: "#ea580c",
        bgColor: "bg-orange-100 dark:bg-orange-950",
        borderColor: "border-orange-500",
        icon: Code,
        description: "Deployable misconfiguration in Terraform",
    },
    drift_risk: {
        label: "Drift Risk",
        color: "#d97706",
        bgColor: "bg-amber-100 dark:bg-amber-950",
        borderColor: "border-amber-500",
        icon: GitCompare,
        description: "Code and live AWS config diverge",
    },
    informational: {
        label: "Informational",
        color: "#2563eb",
        bgColor: "bg-blue-100 dark:bg-blue-950",
        borderColor: "border-blue-500",
        icon: Info,
        description: "Best practice recommendation",
    },
} as const

type WAFSeverity = keyof typeof WAF_SEVERITIES

const SOURCE_BADGES = {
    static: { label: "Static", className: "bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border-purple-300 dark:border-purple-700" },
    live: { label: "Live", className: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300 border-green-300 dark:border-green-700" },
    drift: { label: "Drift", className: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border-amber-300 dark:border-amber-700" },
} as const

type FindingSource = keyof typeof SOURCE_BADGES

// =============================================================================
// Types
// =============================================================================

interface WAFTabProps {
    projectId: string
    projectName: string
}

interface WAFSummary {
    severity_counts: Record<WAFSeverity, number>
    source_counts: Record<FindingSource, number>
    total: number
    last_static_scan: string | null
    last_live_scan: string | null
    web_acls: string[]
    rule_types: string[]
}

interface WAFFinding {
    id: string
    severity: WAFSeverity
    source: FindingSource
    title: string
    description: string
    web_acl_name: string
    rule_name: string
    rule_type: string
    file_path: string | null
    line: number | null
    code_snippet: string | null
    recommendation: string | null
    remediation_code: string | null
    raw_data: Record<string, unknown>
    reviewed: boolean
    associated_path: string | null
}

interface WAFDriftWebACL {
    web_acl_name: string
    in_code: boolean
    in_aws: boolean
    drift_items: WAFDriftItem[]
}

interface WAFDriftItem {
    rule_name: string
    attribute: string
    code_value: string | null
    live_value: string | null
    status: "match" | "drift" | "code_only" | "live_only"
    code_detail: string | null
    live_detail: string | null
}

interface ChatMessage {
    role: "user" | "assistant"
    content: string
    timestamp: Date
}

// =============================================================================
// Utility Functions
// =============================================================================

function formatTimestamp(ts: string | null): string {
    if (!ts) return "Never"
    const d = new Date(ts)
    return d.toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" })
}

function formatRelativeTime(ts: string | null): string | null {
    if (!ts) return null
    const d = new Date(ts)
    const now = new Date()
    const diffMs = now.getTime() - d.getTime()
    const diffMin = Math.floor(diffMs / 60000)
    if (diffMin < 1) return "just now"
    if (diffMin < 60) return `${diffMin}m ago`
    const diffHr = Math.floor(diffMin / 60)
    if (diffHr < 24) return `${diffHr}h ago`
    const diffDay = Math.floor(diffHr / 24)
    if (diffDay < 7) return `${diffDay}d ago`
    return null
}

// =============================================================================
// Sub-components
// =============================================================================

function CopyButton({ text }: { text: string }) {
    const [copied, setCopied] = useState(false)

    const handleCopy = useCallback(async () => {
        try {
            await navigator.clipboard.writeText(text)
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
        } catch {
            // Fallback for older browsers
            const textarea = document.createElement("textarea")
            textarea.value = text
            document.body.appendChild(textarea)
            textarea.select()
            document.execCommand("copy")
            document.body.removeChild(textarea)
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
        }
    }, [text])

    return (
        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={handleCopy}>
            {copied ? (
                <Check className="h-3.5 w-3.5 text-green-500" />
            ) : (
                <Copy className="h-3.5 w-3.5 text-muted-foreground" />
            )}
        </Button>
    )
}

function CodeBlock({ code, language }: { code: string; language?: string }) {
    return (
        <div className="relative group rounded-md border bg-muted/50">
            <div className="flex items-center justify-between px-3 py-1.5 border-b bg-muted/30">
                <span className="text-xs font-mono text-muted-foreground">
                    {language || "code"}
                </span>
                <CopyButton text={code} />
            </div>
            <pre className="p-3 overflow-x-auto text-sm">
                <code className="font-mono text-xs leading-relaxed whitespace-pre">
                    {code}
                </code>
            </pre>
        </div>
    )
}

function SeverityBadge({ severity }: { severity: WAFSeverity }) {
    const config = WAF_SEVERITIES[severity]
    if (!config) return <Badge variant="outline">{severity}</Badge>
    const Icon = config.icon
    return (
        <Tooltip>
            <TooltipTrigger asChild>
                <Badge
                    variant="outline"
                    className={`${config.bgColor} border ${config.borderColor} gap-1`}
                    style={{ color: config.color }}
                >
                    <Icon className="h-3 w-3" />
                    {config.label}
                </Badge>
            </TooltipTrigger>
            <TooltipContent>{config.description}</TooltipContent>
        </Tooltip>
    )
}

function SourceBadge({ source }: { source: FindingSource }) {
    const config = SOURCE_BADGES[source]
    if (!config) return <Badge variant="outline">{source}</Badge>
    return (
        <Badge variant="outline" className={config.className}>
            {config.label}
        </Badge>
    )
}

function RuleTypeBadge({ ruleType }: { ruleType: string }) {
    return (
        <Badge variant="secondary" className="text-xs font-normal">
            {ruleType}
        </Badge>
    )
}

function DriftStatusBadge({ status }: { status: WAFDriftItem["status"] }) {
    const styles: Record<WAFDriftItem["status"], string> = {
        match: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300 border-green-300 dark:border-green-700",
        drift: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border-amber-300 dark:border-amber-700",
        code_only: "bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border-purple-300 dark:border-purple-700",
        live_only: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300 border-orange-300 dark:border-orange-700",
    }
    const labels: Record<WAFDriftItem["status"], string> = {
        match: "Match",
        drift: "Drift",
        code_only: "Code Only",
        live_only: "Live Only",
    }
    return (
        <Badge variant="outline" className={styles[status]}>
            {labels[status]}
        </Badge>
    )
}

// =============================================================================
// Loading Skeletons
// =============================================================================

function FindingsLoadingSkeleton() {
    return (
        <div className="space-y-6">
            {/* Summary cards skeleton */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {Array.from({ length: 4 }).map((_, i) => (
                    <Card key={i}>
                        <CardContent className="p-4">
                            <div className="flex items-center justify-between">
                                <Skeleton className="h-4 w-20" />
                                <Skeleton className="h-8 w-8 rounded-full" />
                            </div>
                            <Skeleton className="h-8 w-12 mt-2" />
                            <Skeleton className="h-3 w-32 mt-1" />
                        </CardContent>
                    </Card>
                ))}
            </div>
            {/* Source bar skeleton */}
            <Skeleton className="h-10 w-full rounded-md" />
            {/* Filter bar skeleton */}
            <div className="flex gap-3">
                {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-10 w-36" />
                ))}
            </div>
            {/* Finding cards skeleton */}
            {Array.from({ length: 3 }).map((_, i) => (
                <Card key={i} className="border-l-4">
                    <CardContent className="p-4 space-y-3">
                        <div className="flex items-center gap-2">
                            <Skeleton className="h-5 w-16" />
                            <Skeleton className="h-5 w-20" />
                            <Skeleton className="h-5 w-24" />
                        </div>
                        <Skeleton className="h-5 w-3/4" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-2/3" />
                    </CardContent>
                </Card>
            ))}
        </div>
    )
}

function DriftLoadingSkeleton() {
    return (
        <div className="space-y-4">
            {Array.from({ length: 2 }).map((_, i) => (
                <Card key={i}>
                    <CardHeader>
                        <div className="flex items-center gap-3">
                            <Skeleton className="h-6 w-48" />
                            <Skeleton className="h-5 w-20" />
                            <Skeleton className="h-5 w-20" />
                        </div>
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-2">
                            {Array.from({ length: 4 }).map((_, j) => (
                                <Skeleton key={j} className="h-10 w-full" />
                            ))}
                        </div>
                    </CardContent>
                </Card>
            ))}
        </div>
    )
}

// =============================================================================
// Findings Sub-tab
// =============================================================================

function FindingsView({
    projectId,
    onSendToAI,
}: {
    projectId: string
    onSendToAI: (finding: WAFFinding) => void
}) {
    const { toast } = useToast()
    const [summary, setSummary] = useState<WAFSummary | null>(null)
    const [findings, setFindings] = useState<WAFFinding[]>([])
    const [loading, setLoading] = useState(true)
    const [findingsLoading, setFindingsLoading] = useState(false)
    const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
    const [rawSheetFinding, setRawSheetFinding] = useState<WAFFinding | null>(null)
    const [page, setPage] = useState(1)
    const [hasMore, setHasMore] = useState(false)

    // Filters
    const [severityFilter, setSeverityFilter] = useState<string>("all")
    const [sourceFilter, setSourceFilter] = useState<string>("all")
    const [ruleTypeFilter, setRuleTypeFilter] = useState<string>("all")
    const [webAclFilter, setWebAclFilter] = useState<string>("all")
    const [searchText, setSearchText] = useState("")
    const [activeSeverityCard, setActiveSeverityCard] = useState<string | null>(null)

    const fetchSummary = useCallback(async () => {
        try {
            const res = await apiFetch(`${API_BASE}/projects/${projectId}/waf/summary`)
            if (res.ok) {
                const data = await res.json()
                setSummary(data)
            }
        } catch (err) {
            console.error("Failed to fetch WAF summary:", err)
        }
    }, [projectId])

    const fetchFindings = useCallback(async (pageNum: number, append = false) => {
        setFindingsLoading(true)
        try {
            const params = new URLSearchParams()
            const effectiveSeverity = activeSeverityCard || severityFilter
            if (effectiveSeverity && effectiveSeverity !== "all") params.set("severity", effectiveSeverity)
            if (sourceFilter && sourceFilter !== "all") params.set("source", sourceFilter)
            if (ruleTypeFilter && ruleTypeFilter !== "all") params.set("rule_type", ruleTypeFilter)
            if (webAclFilter && webAclFilter !== "all") params.set("web_acl", webAclFilter)
            if (searchText.trim()) params.set("search", searchText.trim())
            params.set("page", String(pageNum))
            params.set("per_page", "25")

            const res = await apiFetch(`${API_BASE}/projects/${projectId}/waf/findings?${params}`)
            if (res.ok) {
                const data = await res.json()
                const items: WAFFinding[] = data.findings || data.items || data || []
                if (append) {
                    setFindings(prev => [...prev, ...items])
                } else {
                    setFindings(items)
                }
                setHasMore(data.has_more ?? items.length === 25)
            }
        } catch (err) {
            console.error("Failed to fetch WAF findings:", err)
        } finally {
            setFindingsLoading(false)
        }
    }, [projectId, severityFilter, sourceFilter, ruleTypeFilter, webAclFilter, searchText, activeSeverityCard])

    useEffect(() => {
        const init = async () => {
            setLoading(true)
            await fetchSummary()
            await fetchFindings(1)
            setLoading(false)
        }
        init()
    }, [fetchSummary, fetchFindings])

    // Refetch findings when filters change
    useEffect(() => {
        if (!loading) {
            setPage(1)
            fetchFindings(1)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [severityFilter, sourceFilter, ruleTypeFilter, webAclFilter, searchText, activeSeverityCard])

    const handleLoadMore = () => {
        const nextPage = page + 1
        setPage(nextPage)
        fetchFindings(nextPage, true)
    }

    const toggleExpanded = (id: string) => {
        setExpandedIds(prev => {
            const next = new Set(prev)
            if (next.has(id)) next.delete(id)
            else next.add(id)
            return next
        })
    }

    const handleSeverityCardClick = (severity: string) => {
        if (activeSeverityCard === severity) {
            setActiveSeverityCard(null)
            setSeverityFilter("all")
        } else {
            setActiveSeverityCard(severity)
            setSeverityFilter("all")
        }
    }

    const handleMarkReviewed = async (findingId: string) => {
        try {
            const res = await apiFetch(`${API_BASE}/projects/${projectId}/waf/findings/${findingId}/review`, {
                method: "POST",
            })
            if (res.ok) {
                setFindings(prev => prev.map(f => f.id === findingId ? { ...f, reviewed: true } : f))
                toast({ title: "Finding Reviewed", description: "Finding has been marked as reviewed." })
            }
        } catch {
            toast({ title: "Error", description: "Failed to mark finding as reviewed.", variant: "destructive" })
        }
    }

    const clearFilters = () => {
        setSeverityFilter("all")
        setSourceFilter("all")
        setRuleTypeFilter("all")
        setWebAclFilter("all")
        setSearchText("")
        setActiveSeverityCard(null)
    }

    const hasActiveFilters = severityFilter !== "all" || sourceFilter !== "all" || ruleTypeFilter !== "all" || webAclFilter !== "all" || searchText.trim() !== "" || activeSeverityCard !== null

    if (loading) return <FindingsLoadingSkeleton />

    // Empty state - no WAF resources at all
    if (summary && summary.total === 0 && !summary.last_static_scan && !summary.last_live_scan) {
        return (
            <Card className="border-dashed">
                <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                    <Shield className="h-12 w-12 text-muted-foreground/50 mb-4" />
                    <h3 className="text-lg font-semibold mb-2">No WAF Resources Detected</h3>
                    <p className="text-muted-foreground max-w-md">
                        No WAF resources were detected in this repository&apos;s Terraform files.
                        If this project uses AWS WAF, ensure the Terraform configurations are present
                        and run a new scan.
                    </p>
                </CardContent>
            </Card>
        )
    }

    const severityEntries = Object.entries(WAF_SEVERITIES) as [WAFSeverity, typeof WAF_SEVERITIES[WAFSeverity]][]

    return (
        <div className="space-y-6">
            {/* Summary Dashboard */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {severityEntries.map(([key, config]) => {
                    const count = summary?.severity_counts?.[key] ?? 0
                    const Icon = config.icon
                    const isActive = activeSeverityCard === key
                    return (
                        <Card
                            key={key}
                            className={`cursor-pointer transition-all hover:shadow-md ${
                                isActive
                                    ? `ring-2 ${config.borderColor} shadow-md`
                                    : "hover:border-muted-foreground/30"
                            }`}
                            onClick={() => handleSeverityCardClick(key)}
                        >
                            <CardContent className="p-4">
                                <div className="flex items-center justify-between">
                                    <span
                                        className="text-sm font-medium"
                                        style={{ color: config.color }}
                                    >
                                        {config.label}
                                    </span>
                                    <div
                                        className={`h-9 w-9 rounded-full flex items-center justify-center ${config.bgColor}`}
                                    >
                                        <Icon className="h-4.5 w-4.5" style={{ color: config.color }} />
                                    </div>
                                </div>
                                <div className="mt-1">
                                    <span className="text-3xl font-bold" style={{ color: config.color }}>
                                        {count}
                                    </span>
                                </div>
                                <p className="text-xs text-muted-foreground mt-0.5">
                                    {config.description}
                                </p>
                            </CardContent>
                        </Card>
                    )
                })}
            </div>

            {/* Source breakdown bar + timestamps */}
            <Card>
                <CardContent className="p-4">
                    <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                        {/* Source breakdown */}
                        <div className="flex items-center gap-4">
                            <span className="text-sm font-medium text-muted-foreground">Source:</span>
                            <div className="flex items-center gap-3">
                                {(["static", "live", "drift"] as FindingSource[]).map(src => {
                                    const count = summary?.source_counts?.[src] ?? 0
                                    const config = SOURCE_BADGES[src]
                                    return (
                                        <div key={src} className="flex items-center gap-1.5">
                                            <div
                                                className={`h-3 w-3 rounded-sm ${
                                                    src === "static" ? "bg-purple-500" :
                                                    src === "live" ? "bg-green-500" : "bg-amber-500"
                                                }`}
                                            />
                                            <span className="text-sm">
                                                {config.label}: <strong>{count}</strong>
                                            </span>
                                        </div>
                                    )
                                })}
                            </div>
                            {/* Visual bar */}
                            {summary && summary.total > 0 && (
                                <div className="hidden xl:flex items-center gap-0 h-2.5 w-48 rounded-full overflow-hidden bg-muted">
                                    {(["static", "live", "drift"] as FindingSource[]).map(src => {
                                        const count = summary.source_counts?.[src] ?? 0
                                        const pct = (count / summary.total) * 100
                                        if (pct === 0) return null
                                        const colors = { static: "bg-purple-500", live: "bg-green-500", drift: "bg-amber-500" }
                                        return (
                                            <div
                                                key={src}
                                                className={`h-full ${colors[src]}`}
                                                style={{ width: `${pct}%` }}
                                            />
                                        )
                                    })}
                                </div>
                            )}
                        </div>
                        {/* Timestamps */}
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <div className="flex items-center gap-1.5">
                                <Clock className="h-3.5 w-3.5" />
                                <span>Static: {formatTimestamp(summary?.last_static_scan ?? null)}</span>
                                {summary?.last_static_scan && formatRelativeTime(summary.last_static_scan) && (
                                    <span className="text-muted-foreground/70">
                                        ({formatRelativeTime(summary.last_static_scan)})
                                    </span>
                                )}
                            </div>
                            <Separator orientation="vertical" className="h-4" />
                            <div className="flex items-center gap-1.5">
                                <Clock className="h-3.5 w-3.5" />
                                <span>Live: {formatTimestamp(summary?.last_live_scan ?? null)}</span>
                                {summary?.last_live_scan && formatRelativeTime(summary.last_live_scan) && (
                                    <span className="text-muted-foreground/70">
                                        ({formatRelativeTime(summary.last_live_scan)})
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Filter bar */}
            <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
                    <Filter className="h-4 w-4" />
                    <span>Filter:</span>
                </div>
                <Select value={severityFilter} onValueChange={(v) => { setSeverityFilter(v); setActiveSeverityCard(null) }}>
                    <SelectTrigger className="w-[160px] h-9">
                        <SelectValue placeholder="Severity" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Severities</SelectItem>
                        {severityEntries.map(([key, config]) => (
                            <SelectItem key={key} value={key}>
                                <span className="flex items-center gap-2">
                                    <span className="h-2 w-2 rounded-full" style={{ backgroundColor: config.color }} />
                                    {config.label}
                                </span>
                            </SelectItem>
                        ))}
                    </SelectContent>
                </Select>

                <Select value={sourceFilter} onValueChange={setSourceFilter}>
                    <SelectTrigger className="w-[140px] h-9">
                        <SelectValue placeholder="Source" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Sources</SelectItem>
                        <SelectItem value="static">Static</SelectItem>
                        <SelectItem value="live">Live</SelectItem>
                        <SelectItem value="drift">Drift</SelectItem>
                    </SelectContent>
                </Select>

                <Select value={ruleTypeFilter} onValueChange={setRuleTypeFilter}>
                    <SelectTrigger className="w-[170px] h-9">
                        <SelectValue placeholder="Rule Type" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Rule Types</SelectItem>
                        {(summary?.rule_types || []).map(rt => (
                            <SelectItem key={rt} value={rt}>{rt}</SelectItem>
                        ))}
                    </SelectContent>
                </Select>

                <Select value={webAclFilter} onValueChange={setWebAclFilter}>
                    <SelectTrigger className="w-[180px] h-9">
                        <SelectValue placeholder="WebACL" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All WebACLs</SelectItem>
                        {(summary?.web_acls || []).map(acl => (
                            <SelectItem key={acl} value={acl}>{acl}</SelectItem>
                        ))}
                    </SelectContent>
                </Select>

                <div className="relative flex-1 min-w-[200px] max-w-[320px]">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                        placeholder="Search findings..."
                        className="pl-8 h-9"
                        value={searchText}
                        onChange={e => setSearchText(e.target.value)}
                    />
                </div>

                {hasActiveFilters && (
                    <Button variant="ghost" size="sm" onClick={clearFilters} className="h-9 gap-1.5 text-muted-foreground">
                        <X className="h-3.5 w-3.5" />
                        Clear
                    </Button>
                )}
            </div>

            {/* Findings list */}
            {findingsLoading && findings.length === 0 ? (
                <div className="flex items-center justify-center py-12">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
            ) : findings.length === 0 ? (
                <Card className="border-dashed">
                    <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                        <CheckCircle2 className="h-10 w-10 text-green-500 mb-3" />
                        <h3 className="font-semibold mb-1">No Findings Match</h3>
                        <p className="text-sm text-muted-foreground">
                            {hasActiveFilters
                                ? "No findings match the current filters. Try adjusting your criteria."
                                : "No WAF findings to display."}
                        </p>
                    </CardContent>
                </Card>
            ) : (
                <div className="space-y-3">
                    {findings.map(finding => {
                        const config = WAF_SEVERITIES[finding.severity]
                        const isExpanded = expandedIds.has(finding.id)

                        return (
                            <Collapsible key={finding.id} open={isExpanded} onOpenChange={() => toggleExpanded(finding.id)}>
                                <Card className={`border-l-4 ${config?.borderColor ?? "border-gray-300"} transition-shadow hover:shadow-sm`}>
                                    <CardContent className="p-0">
                                        {/* Collapsed header */}
                                        <CollapsibleTrigger asChild>
                                            <div className="flex items-start gap-3 p-4 cursor-pointer select-none">
                                                <div className="mt-0.5">
                                                    {isExpanded ? (
                                                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                                    ) : (
                                                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                                                    )}
                                                </div>
                                                <div className="flex-1 min-w-0 space-y-2">
                                                    {/* Badge row */}
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <SourceBadge source={finding.source} />
                                                        <SeverityBadge severity={finding.severity} />
                                                        <RuleTypeBadge ruleType={finding.rule_type} />
                                                        {finding.reviewed && (
                                                            <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300 border-green-300 dark:border-green-700 gap-1">
                                                                <Check className="h-3 w-3" />
                                                                Reviewed
                                                            </Badge>
                                                        )}
                                                    </div>
                                                    {/* Title */}
                                                    <h4 className="font-semibold text-sm leading-tight">
                                                        {finding.title}
                                                    </h4>
                                                    {/* Meta row */}
                                                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                                                        <span className="flex items-center gap-1">
                                                            <Shield className="h-3 w-3" />
                                                            {finding.web_acl_name}
                                                        </span>
                                                        <span className="flex items-center gap-1">
                                                            <FileText className="h-3 w-3" />
                                                            {finding.rule_name}
                                                        </span>
                                                        {finding.file_path && (
                                                            <span className="flex items-center gap-1 font-mono">
                                                                <FileCode2 className="h-3 w-3" />
                                                                {finding.file_path}
                                                                {finding.line != null && `:${finding.line}`}
                                                            </span>
                                                        )}
                                                    </div>
                                                    {/* Truncated description */}
                                                    {!isExpanded && finding.description && (
                                                        <p className="text-sm text-muted-foreground line-clamp-2">
                                                            {finding.description}
                                                        </p>
                                                    )}
                                                </div>
                                                {/* Quick actions (prevent collapse toggle) */}
                                                <div className="flex items-center gap-1 shrink-0" onClick={e => e.stopPropagation()}>
                                                    <Tooltip>
                                                        <TooltipTrigger asChild>
                                                            <Button
                                                                variant="ghost"
                                                                size="icon"
                                                                className="h-8 w-8"
                                                                onClick={() => onSendToAI(finding)}
                                                            >
                                                                <Sparkles className="h-4 w-4 text-purple-500" />
                                                            </Button>
                                                        </TooltipTrigger>
                                                        <TooltipContent>Ask AI about this finding</TooltipContent>
                                                    </Tooltip>
                                                </div>
                                            </div>
                                        </CollapsibleTrigger>

                                        {/* Expanded details */}
                                        <CollapsibleContent>
                                            <Separator />
                                            <div className="p-4 space-y-5">
                                                {/* Full description */}
                                                {finding.description && (
                                                    <div>
                                                        <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                                                            Description
                                                        </h5>
                                                        <p className="text-sm leading-relaxed">
                                                            {finding.description}
                                                        </p>
                                                    </div>
                                                )}

                                                {/* Code snippet */}
                                                {finding.code_snippet && (
                                                    <div>
                                                        <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                                                            {finding.source === "live" ? "Rule JSON" : "Code Snippet"}
                                                        </h5>
                                                        <CodeBlock
                                                            code={finding.code_snippet}
                                                            language={finding.source === "live" ? "json" : "hcl"}
                                                        />
                                                    </div>
                                                )}

                                                {/* Recommendation */}
                                                {finding.recommendation && (
                                                    <div>
                                                        <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                                                            Recommendation
                                                        </h5>
                                                        <div className="rounded-md border bg-blue-50/50 dark:bg-blue-950/30 p-3">
                                                            <p className="text-sm leading-relaxed">
                                                                {finding.recommendation}
                                                            </p>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Remediation code */}
                                                {finding.remediation_code && (
                                                    <div>
                                                        <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                                                            Remediation Code
                                                        </h5>
                                                        <CodeBlock code={finding.remediation_code} language="hcl" />
                                                    </div>
                                                )}

                                                {/* Associated With */}
                                                <div>
                                                    <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                                                        Associated With
                                                    </h5>
                                                    <div className="rounded-md border p-3 space-y-2">
                                                        <div className="flex items-center gap-2 text-sm">
                                                            <span className="text-muted-foreground font-medium min-w-[80px]">Path:</span>
                                                            <span className="font-mono text-xs">
                                                                {finding.associated_path || `${finding.web_acl_name} > ${finding.rule_name}`}
                                                            </span>
                                                        </div>
                                                        {finding.file_path && (
                                                            <div className="flex items-center gap-2 text-sm">
                                                                <span className="text-muted-foreground font-medium min-w-[80px]">File:</span>
                                                                <span className="font-mono text-xs">
                                                                    {finding.file_path}{finding.line != null && `:${finding.line}`}
                                                                </span>
                                                            </div>
                                                        )}
                                                        <div className="flex items-center gap-2 text-sm">
                                                            <span className="text-muted-foreground font-medium min-w-[80px]">Source:</span>
                                                            <SourceBadge source={finding.source} />
                                                        </div>
                                                    </div>
                                                </div>

                                                {/* Actions */}
                                                <div className="flex items-center gap-2 pt-2">
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        className="gap-1.5"
                                                        onClick={() => onSendToAI(finding)}
                                                    >
                                                        <Sparkles className="h-3.5 w-3.5 text-purple-500" />
                                                        Ask AI
                                                    </Button>
                                                    {!finding.reviewed && (
                                                        <Button
                                                            variant="outline"
                                                            size="sm"
                                                            className="gap-1.5"
                                                            onClick={() => handleMarkReviewed(finding.id)}
                                                        >
                                                            <Check className="h-3.5 w-3.5" />
                                                            Mark as Reviewed
                                                        </Button>
                                                    )}
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        className="gap-1.5"
                                                        onClick={() => setRawSheetFinding(finding)}
                                                    >
                                                        <Eye className="h-3.5 w-3.5" />
                                                        View Raw
                                                    </Button>
                                                </div>
                                            </div>
                                        </CollapsibleContent>
                                    </CardContent>
                                </Card>
                            </Collapsible>
                        )
                    })}

                    {/* Load more */}
                    {hasMore && (
                        <div className="flex justify-center pt-2">
                            <Button
                                variant="outline"
                                onClick={handleLoadMore}
                                disabled={findingsLoading}
                                className="gap-2"
                            >
                                {findingsLoading ? (
                                    <Loader2 className="h-4 w-4 animate-spin" />
                                ) : (
                                    <ChevronDown className="h-4 w-4" />
                                )}
                                Load More
                            </Button>
                        </div>
                    )}
                </div>
            )}

            {/* Raw data Sheet */}
            <Sheet open={!!rawSheetFinding} onOpenChange={() => setRawSheetFinding(null)}>
                <SheetContent side="right" className="w-full sm:max-w-xl">
                    <SheetHeader>
                        <SheetTitle className="flex items-center gap-2">
                            <Code className="h-4 w-4" />
                            Raw Finding Data
                        </SheetTitle>
                        <SheetDescription>
                            {rawSheetFinding?.title}
                        </SheetDescription>
                    </SheetHeader>
                    <ScrollArea className="flex-1 mt-4 h-[calc(100vh-120px)]">
                        {rawSheetFinding && (
                            <div className="space-y-4 pr-4">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                        <SourceBadge source={rawSheetFinding.source} />
                                        <SeverityBadge severity={rawSheetFinding.severity} />
                                    </div>
                                    <CopyButton text={JSON.stringify(rawSheetFinding.raw_data, null, 2)} />
                                </div>
                                <CodeBlock
                                    code={JSON.stringify(rawSheetFinding.raw_data, null, 2)}
                                    language="json"
                                />
                            </div>
                        )}
                    </ScrollArea>
                </SheetContent>
            </Sheet>
        </div>
    )
}

// =============================================================================
// Drift Comparison Sub-tab
// =============================================================================

function DriftComparisonView({ projectId }: { projectId: string }) {
    const [driftData, setDriftData] = useState<WAFDriftWebACL[]>([])
    const [loading, setLoading] = useState(true)
    const [hasLiveData, setHasLiveData] = useState<boolean | null>(null)
    const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

    useEffect(() => {
        const fetchDrift = async () => {
            setLoading(true)
            try {
                const res = await apiFetch(`${API_BASE}/projects/${projectId}/waf/drift`)
                if (res.ok) {
                    const data = await res.json()
                    setDriftData(data.web_acls || data || [])
                    setHasLiveData(data.has_live_data ?? true)
                } else if (res.status === 404) {
                    setHasLiveData(false)
                }
            } catch (err) {
                console.error("Failed to fetch WAF drift:", err)
                setHasLiveData(false)
            } finally {
                setLoading(false)
            }
        }
        fetchDrift()
    }, [projectId])

    const toggleRow = (key: string) => {
        setExpandedRows(prev => {
            const next = new Set(prev)
            if (next.has(key)) next.delete(key)
            else next.add(key)
            return next
        })
    }

    if (loading) return <DriftLoadingSkeleton />

    // No live audit data available
    if (hasLiveData === false || (driftData.length === 0 && hasLiveData !== true)) {
        return (
            <Card className="border-dashed border-amber-300 dark:border-amber-700">
                <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                    <AlertTriangle className="h-12 w-12 text-amber-500 mb-4" />
                    <h3 className="text-lg font-semibold mb-2">Live Audit Data Unavailable</h3>
                    <p className="text-muted-foreground max-w-lg mb-4">
                        Drift comparison requires both static analysis (from Terraform code) and live audit data
                        (from AWS). Configure AWS credentials and run a WAF audit to enable drift detection.
                    </p>
                    <div className="rounded-md border bg-muted/50 p-4 max-w-md">
                        <p className="text-sm font-mono text-muted-foreground">
                            Required: <code className="text-foreground">AWS_ACCESS_KEY_ID</code>,{" "}
                            <code className="text-foreground">AWS_SECRET_ACCESS_KEY</code>, and{" "}
                            <code className="text-foreground">AWS_REGION</code>
                        </p>
                    </div>
                </CardContent>
            </Card>
        )
    }

    if (driftData.length === 0) {
        return (
            <Card className="border-dashed border-green-300 dark:border-green-700">
                <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                    <CheckCircle2 className="h-12 w-12 text-green-500 mb-4" />
                    <h3 className="text-lg font-semibold mb-2">No Drift Detected</h3>
                    <p className="text-muted-foreground max-w-md">
                        All WAF configurations in Terraform match the live AWS environment.
                        Code and cloud are in sync.
                    </p>
                </CardContent>
            </Card>
        )
    }

    const statusRowColors: Record<WAFDriftItem["status"], string> = {
        match: "bg-green-50/50 dark:bg-green-950/20",
        drift: "bg-amber-50/50 dark:bg-amber-950/20",
        code_only: "bg-purple-50/50 dark:bg-purple-950/20",
        live_only: "bg-orange-50/50 dark:bg-orange-950/20",
    }

    return (
        <div className="space-y-4">
            {/* Summary stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                    { label: "WebACLs Compared", value: driftData.length, icon: Shield },
                    { label: "Drifted Rules", value: driftData.reduce((acc, w) => acc + w.drift_items.filter(d => d.status === "drift").length, 0), icon: GitCompare },
                    { label: "Code Only", value: driftData.reduce((acc, w) => acc + w.drift_items.filter(d => d.status === "code_only").length, 0), icon: Code },
                    { label: "Live Only", value: driftData.reduce((acc, w) => acc + w.drift_items.filter(d => d.status === "live_only").length, 0), icon: AlertTriangle },
                ].map(stat => (
                    <Card key={stat.label}>
                        <CardContent className="p-4 flex items-center gap-3">
                            <stat.icon className="h-5 w-5 text-muted-foreground" />
                            <div>
                                <div className="text-xl font-bold">{stat.value}</div>
                                <div className="text-xs text-muted-foreground">{stat.label}</div>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* Per-WebACL drift cards */}
            {driftData.map(webAcl => {
                const driftCount = webAcl.drift_items.filter(d => d.status !== "match").length
                return (
                    <Card key={webAcl.web_acl_name}>
                        <CardHeader className="pb-3">
                            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                                <div className="flex items-center gap-3">
                                    <CardTitle className="text-base">{webAcl.web_acl_name}</CardTitle>
                                    {webAcl.in_code && (
                                        <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300 border-green-300 dark:border-green-700 gap-1">
                                            <CheckCircle2 className="h-3 w-3" />
                                            In Code
                                        </Badge>
                                    )}
                                    {webAcl.in_aws && (
                                        <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300 border-green-300 dark:border-green-700 gap-1">
                                            <CheckCircle2 className="h-3 w-3" />
                                            In AWS
                                        </Badge>
                                    )}
                                </div>
                                {driftCount > 0 && (
                                    <Badge variant="outline" className="bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-700">
                                        {driftCount} {driftCount === 1 ? "difference" : "differences"}
                                    </Badge>
                                )}
                            </div>
                        </CardHeader>
                        <CardContent>
                            <div className="rounded-md border overflow-hidden">
                                {/* Table header */}
                                <div className="grid grid-cols-12 gap-2 px-4 py-2.5 bg-muted/50 border-b text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                                    <div className="col-span-1" />
                                    <div className="col-span-2">Rule Name</div>
                                    <div className="col-span-2">Attribute</div>
                                    <div className="col-span-3">Code Value</div>
                                    <div className="col-span-3">Live Value</div>
                                    <div className="col-span-1">Status</div>
                                </div>
                                {/* Table rows */}
                                {webAcl.drift_items.length === 0 ? (
                                    <div className="px-4 py-8 text-center text-sm text-muted-foreground">
                                        No rules to compare for this WebACL.
                                    </div>
                                ) : (
                                    webAcl.drift_items.map((item, idx) => {
                                        const rowKey = `${webAcl.web_acl_name}-${item.rule_name}-${item.attribute}-${idx}`
                                        const isRowExpanded = expandedRows.has(rowKey)
                                        const hasDetail = item.code_detail || item.live_detail
                                        return (
                                            <div key={rowKey}>
                                                <div
                                                    className={`grid grid-cols-12 gap-2 px-4 py-2.5 items-center text-sm border-b last:border-b-0 ${statusRowColors[item.status]} ${hasDetail ? "cursor-pointer hover:bg-muted/30" : ""}`}
                                                    onClick={() => hasDetail && toggleRow(rowKey)}
                                                >
                                                    <div className="col-span-1">
                                                        {hasDetail && (
                                                            isRowExpanded ? (
                                                                <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                                                            ) : (
                                                                <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                                                            )
                                                        )}
                                                    </div>
                                                    <div className="col-span-2 font-medium truncate" title={item.rule_name}>
                                                        {item.rule_name}
                                                    </div>
                                                    <div className="col-span-2 text-muted-foreground truncate" title={item.attribute}>
                                                        {item.attribute}
                                                    </div>
                                                    <div className="col-span-3 font-mono text-xs truncate" title={item.code_value || "---"}>
                                                        {item.code_value || <span className="text-muted-foreground italic">---</span>}
                                                    </div>
                                                    <div className="col-span-3 font-mono text-xs truncate" title={item.live_value || "---"}>
                                                        {item.live_value || <span className="text-muted-foreground italic">---</span>}
                                                    </div>
                                                    <div className="col-span-1">
                                                        <DriftStatusBadge status={item.status} />
                                                    </div>
                                                </div>
                                                {/* Expanded detail row */}
                                                {isRowExpanded && hasDetail && (
                                                    <div className="border-b px-4 py-3 bg-muted/20">
                                                        <div className="grid grid-cols-2 gap-4">
                                                            <div>
                                                                <h6 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                                                                    <Code className="h-3 w-3" />
                                                                    Code (Terraform)
                                                                </h6>
                                                                {item.code_detail ? (
                                                                    <CodeBlock code={item.code_detail} language="hcl" />
                                                                ) : (
                                                                    <div className="rounded-md border border-dashed p-4 text-center text-sm text-muted-foreground">
                                                                        Not defined in code
                                                                    </div>
                                                                )}
                                                            </div>
                                                            <div>
                                                                <h6 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                                                                    <ExternalLink className="h-3 w-3" />
                                                                    Live (AWS)
                                                                </h6>
                                                                {item.live_detail ? (
                                                                    <CodeBlock code={item.live_detail} language="json" />
                                                                ) : (
                                                                    <div className="rounded-md border border-dashed p-4 text-center text-sm text-muted-foreground">
                                                                        Not found in AWS
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        )
                                    })
                                )}
                            </div>
                        </CardContent>
                    </Card>
                )
            })}
        </div>
    )
}

// =============================================================================
// Ask AI Sub-tab
// =============================================================================

function AskAIView({
    projectId,
    projectName,
    initialFinding,
    onClearFinding,
}: {
    projectId: string
    projectName: string
    initialFinding: WAFFinding | null
    onClearFinding: () => void
}) {
    const [messages, setMessages] = useState<ChatMessage[]>([])
    const [input, setInput] = useState("")
    const [isLoading, setIsLoading] = useState(false)
    const scrollRef = useRef<HTMLDivElement>(null)

    const suggestedPrompts = [
        "Analyze my WAF security posture",
        "Generate an adaptive blocking strategy",
        "Review my rate limiting configuration",
        "Suggest missing WAF rules for a web application",
        "Explain the risks of my current WAF setup",
        "Compare my WAF rules against OWASP Top 10",
    ]

    // Auto-scroll on new messages
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight
        }
    }, [messages, isLoading])

    // Handle initial finding sent from Findings tab
    useEffect(() => {
        if (initialFinding) {
            const contextMessage = `Analyze this WAF finding:\n\n**${initialFinding.title}**\n- Severity: ${WAF_SEVERITIES[initialFinding.severity]?.label}\n- Source: ${initialFinding.source}\n- WebACL: ${initialFinding.web_acl_name}\n- Rule: ${initialFinding.rule_name}\n- Type: ${initialFinding.rule_type}\n${initialFinding.file_path ? `- File: ${initialFinding.file_path}${initialFinding.line != null ? `:${initialFinding.line}` : ""}` : ""}\n\n${initialFinding.description}`
            sendMessage(contextMessage)
            onClearFinding()
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [initialFinding])

    const sendMessage = async (text: string) => {
        const userMsg: ChatMessage = { role: "user", content: text, timestamp: new Date() }
        setMessages(prev => [...prev, userMsg])
        setInput("")
        setIsLoading(true)

        try {
            const res = await apiFetch(`${API_BASE}/projects/${projectId}/waf/ask-ai`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    question: text,
                    finding_id: initialFinding?.id || undefined,
                }),
            })

            if (!res.ok) {
                const err = await res.json().catch(() => ({}))
                throw new Error(err.detail || `HTTP ${res.status}`)
            }

            const data = await res.json()
            const assistantMsg: ChatMessage = {
                role: "assistant",
                content: data.response || data.analysis || data.answer || "No response received.",
                timestamp: new Date(),
            }
            setMessages(prev => [...prev, assistantMsg])
        } catch (err) {
            const errorMsg: ChatMessage = {
                role: "assistant",
                content: `Failed to get AI response: ${err instanceof Error ? err.message : "Unknown error"}. Please try again.`,
                timestamp: new Date(),
            }
            setMessages(prev => [...prev, errorMsg])
        } finally {
            setIsLoading(false)
        }
    }

    const handleSubmit = () => {
        if (!input.trim() || isLoading) return
        sendMessage(input.trim())
    }

    return (
        <div className="flex flex-col h-[calc(100vh-320px)] min-h-[500px]">
            {/* Chat messages area */}
            <Card className="flex-1 flex flex-col overflow-hidden">
                <CardHeader className="pb-3 border-b shrink-0">
                    <div className="flex items-center justify-between">
                        <CardTitle className="text-base flex items-center gap-2">
                            <Sparkles className="h-4.5 w-4.5 text-purple-500" />
                            WAF Security Assistant
                        </CardTitle>
                        <span className="text-xs text-muted-foreground">
                            Context: {projectName} WAF Configuration
                        </span>
                    </div>
                </CardHeader>
                <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-4">
                    {messages.length === 0 && !isLoading ? (
                        /* Empty state with suggested prompts */
                        <div className="flex flex-col items-center justify-center h-full gap-6">
                            <div className="text-center space-y-2">
                                <div className="h-16 w-16 rounded-full bg-purple-100 dark:bg-purple-950 flex items-center justify-center mx-auto mb-4">
                                    <MessageSquare className="h-8 w-8 text-purple-500" />
                                </div>
                                <h3 className="text-lg font-semibold">WAF Security Assistant</h3>
                                <p className="text-sm text-muted-foreground max-w-md">
                                    Ask questions about your WAF configuration, get security recommendations,
                                    or generate Terraform code for new rules.
                                </p>
                            </div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-w-lg w-full">
                                {suggestedPrompts.map(prompt => (
                                    <Button
                                        key={prompt}
                                        variant="outline"
                                        className="justify-start text-left h-auto py-3 px-4"
                                        onClick={() => sendMessage(prompt)}
                                    >
                                        <Lightbulb className="h-4 w-4 text-amber-500 mr-2 shrink-0" />
                                        <span className="text-sm">{prompt}</span>
                                    </Button>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <>
                            {messages.map((msg, idx) => (
                                <div key={idx} className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                                    {msg.role === "assistant" && (
                                        <div className="flex-shrink-0 w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900 flex items-center justify-center">
                                            <Bot className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                                        </div>
                                    )}
                                    <div
                                        className={`max-w-[75%] rounded-lg p-3 ${
                                            msg.role === "user"
                                                ? "bg-blue-500 text-white"
                                                : "bg-muted"
                                        }`}
                                    >
                                        {msg.role === "user" ? (
                                            <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
                                        ) : (
                                            <div className="prose prose-sm dark:prose-invert max-w-none [&_pre]:relative [&_pre]:group">
                                                <ReactMarkdown
                                                    remarkPlugins={[remarkGfm]}
                                                    components={{
                                                        pre: ({ children, ...props }) => (
                                                            <div className="relative group my-2">
                                                                <pre className="font-mono text-xs p-3 rounded-md bg-background border overflow-x-auto" {...props}>
                                                                    {children}
                                                                </pre>
                                                                <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                                                    <CopyButton text={extractCodeText(children)} />
                                                                </div>
                                                            </div>
                                                        ),
                                                        code: ({ className, children, ...props }) => {
                                                            const isInline = !className
                                                            if (isInline) {
                                                                return (
                                                                    <code className="bg-muted px-1 py-0.5 rounded text-xs font-mono" {...props}>
                                                                        {children}
                                                                    </code>
                                                                )
                                                            }
                                                            return (
                                                                <code className={`${className} font-mono`} {...props}>
                                                                    {children}
                                                                </code>
                                                            )
                                                        },
                                                    }}
                                                >
                                                    {msg.content}
                                                </ReactMarkdown>
                                            </div>
                                        )}
                                        <p className={`text-xs mt-2 ${msg.role === "user" ? "text-blue-100" : "text-muted-foreground"}`}>
                                            {msg.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                        </p>
                                    </div>
                                    {msg.role === "user" && (
                                        <div className="flex-shrink-0 w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                                            <User className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                                        </div>
                                    )}
                                </div>
                            ))}
                            {/* Loading indicator */}
                            {isLoading && (
                                <div className="flex gap-3 justify-start">
                                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900 flex items-center justify-center">
                                        <Bot className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                                    </div>
                                    <div className="bg-muted rounded-lg p-3 flex items-center gap-2">
                                        <Loader2 className="h-4 w-4 animate-spin" />
                                        <span className="text-sm text-muted-foreground">Analyzing...</span>
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                </div>
            </Card>

            {/* Input area */}
            <div className="pt-4 flex gap-2">
                <Textarea
                    placeholder="Ask about your WAF configuration, request rule generation, or analyze security posture..."
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    className="resize-none flex-1"
                    rows={2}
                    onKeyDown={e => {
                        if (e.key === "Enter" && !e.shiftKey && input.trim()) {
                            e.preventDefault()
                            handleSubmit()
                        }
                    }}
                />
                <Button
                    onClick={handleSubmit}
                    disabled={isLoading || !input.trim()}
                    className="h-auto px-4"
                >
                    {isLoading ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                        <Send className="h-4 w-4" />
                    )}
                </Button>
            </div>
        </div>
    )
}

/** Extract text content from pre > code children for the copy button. */
function extractCodeText(children: React.ReactNode): string {
    if (typeof children === "string") return children
    if (Array.isArray(children)) return children.map(extractCodeText).join("")
    if (children && typeof children === "object" && "props" in (children as React.ReactElement)) {
        const el = children as React.ReactElement<{ children?: React.ReactNode }>
        return extractCodeText(el.props.children)
    }
    return String(children ?? "")
}

// =============================================================================
// Main WAF Tab Component
// =============================================================================

export function WAFTab({ projectId, projectName }: WAFTabProps) {
    const [activeTab, setActiveTab] = useState("findings")
    const [aiPendingFinding, setAiPendingFinding] = useState<WAFFinding | null>(null)

    const handleSendToAI = useCallback((finding: WAFFinding) => {
        setAiPendingFinding(finding)
        setActiveTab("ask-ai")
    }, [])

    const handleClearFinding = useCallback(() => {
        setAiPendingFinding(null)
    }, [])

    return (
        <div className="space-y-4">
            <Tabs value={activeTab} onValueChange={setActiveTab}>
                <div className="flex items-center justify-between">
                    <TabsList>
                        <TabsTrigger value="findings" className="gap-1.5">
                            <ShieldAlert className="h-4 w-4" />
                            Findings
                        </TabsTrigger>
                        <TabsTrigger value="drift" className="gap-1.5">
                            <ArrowLeftRight className="h-4 w-4" />
                            Drift Comparison
                        </TabsTrigger>
                        <TabsTrigger value="ask-ai" className="gap-1.5">
                            <Sparkles className="h-4 w-4" />
                            Ask AI
                        </TabsTrigger>
                    </TabsList>
                </div>

                <TabsContent value="findings" className="mt-4">
                    <FindingsView projectId={projectId} onSendToAI={handleSendToAI} />
                </TabsContent>

                <TabsContent value="drift" className="mt-4">
                    <DriftComparisonView projectId={projectId} />
                </TabsContent>

                <TabsContent value="ask-ai" className="mt-4">
                    <AskAIView
                        projectId={projectId}
                        projectName={projectName}
                        initialFinding={aiPendingFinding}
                        onClearFinding={handleClearFinding}
                    />
                </TabsContent>
            </Tabs>
        </div>
    )
}
