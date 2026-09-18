"use client"

import { useEffect, useMemo, useState } from "react"
import { DataTable } from "@/components/data-table"
import { ColumnDef } from "@tanstack/react-table"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Loader2, LayoutGrid, List, Clock, FileCode, Archive, ShieldAlert, ShieldCheck, Users } from "lucide-react"
import Link from "next/link"
import { ProjectScorecard } from "@/components/project-scorecard"
import { FindingsSelectionToolbar } from "@/components/findings-selection-toolbar"
import { API_BASE, apiFetch } from "@/lib/api"
import { PageHeader, PageShell } from "@/components/ui/page-header"
import {
    buildFilingIndex,
    lookupFiling,
    type AuditBoardFiling,
    type FilingIndex,
} from "@/lib/auditboard"

interface Finding {
    id: string
    title: string
    description: string | null
    severity: string
    status: string
    scanner_name: string | null
    // With scanner_name this identifies the defect, which is what an
    // AuditBoard filing is matched on. Without it the AuditBoard ID column
    // would only ever match pre-2026-09-16 'global' filings.
    rule_id: string | null
    repo_name: string
    repository_id: string | null
    file_path: string | null
    line_start: number | null
    repo_pushed_at: string | null
    file_last_commit_at: string | null
    file_last_commit_author: string | null
    is_archived: boolean | null
    created_at: string
    risk_score: number | null
    risk_level: string | null
    snoozed_until: string | null
    snooze_reason: string | null
    investigation_status: string | null
}

interface PaginatedResponse {
    items: Finding[]
    total: number
    page: number
    page_size: number
    total_pages: number
    has_next: boolean
    has_prev: boolean
}

// Severity order for sorting
const SEVERITY_ORDER: Record<string, number> = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    info: 5,
    warning: 6,
}

function getDaysSince(date: string | null): number | null {
    if (!date) return null
    const now = new Date()
    const pastDate = new Date(date)
    const diffTime = Math.abs(now.getTime() - pastDate.getTime())
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    return diffDays
}

function getSeverityBadge(severity: string) {
    const severityLower = severity?.toLowerCase() || "unknown"
    const colorMap: Record<string, string> = {
        critical: "bg-danger hover:bg-danger",
        high: "bg-warning hover:bg-warning",
        medium: "bg-warning hover:bg-warning",
        low: "bg-info hover:bg-info",
        info: "bg-muted-foreground hover:bg-muted-foreground",
        warning: "bg-warning hover:bg-warning",
    }
    return (
        <Badge className={colorMap[severityLower] || "bg-muted-foreground"}>
            {severity}
        </Badge>
    )
}

function getCommitAgeBadge(days: number | null, hasFileCommit: boolean, isArchived: boolean | null) {
    if (days === null) {
        return (
            <Badge variant="secondary">
                <Clock className="h-3 w-3 mr-1" />
                No data
            </Badge>
        )
    }

    const icons = []
    if (hasFileCommit) {
        icons.push(
            <span key="file" title="File-level commit date">
                <FileCode className="h-3 w-3 text-info-text" />
            </span>
        )
    }
    if (isArchived) {
        icons.push(
            <span key="archived" title="Archived repository">
                <Archive className="h-3 w-3 text-warning-text" />
            </span>
        )
    }

    let badge
    if (days < 31) {
        badge = (
            <Badge className="bg-success hover:bg-success">
                <Clock className="h-3 w-3 mr-1" />
                {days}d ago
            </Badge>
        )
    } else if (days < 365) {
        badge = (
            <Badge className="bg-warning hover:bg-warning">
                <Clock className="h-3 w-3 mr-1" />
                {days}d ago
            </Badge>
        )
    } else {
        const years = Math.floor(days / 365)
        badge = (
            <Badge variant="destructive">
                <Clock className="h-3 w-3 mr-1" />
                {years}y ago
            </Badge>
        )
    }

    if (icons.length > 0) {
        return (
            <div className="flex items-center gap-1">
                {badge}
                {icons}
            </div>
        )
    }

    return badge
}

function getRiskBadge(riskScore: number | null, riskLevel: string | null) {
    if (riskScore === null) {
        return <span className="text-muted-foreground">—</span>
    }

    const colorMap: Record<string, string> = {
        critical: "bg-danger hover:bg-danger",
        high: "bg-warning hover:bg-warning",
        medium: "bg-warning hover:bg-warning",
        low: "bg-info hover:bg-info",
    }

    return (
        <Badge className={colorMap[riskLevel?.toLowerCase() || ""] || "bg-muted-foreground"}>
            <ShieldAlert className="h-3 w-3 mr-1" />
            {riskScore}
        </Badge>
    )
}

/**
 * AuditBoard column.
 *
 * Built from a filing index rather than a field on the finding, because a
 * filing is not a property of a finding — a global filing covers every
 * finding sharing its scanner and file path, so one issue annotates many
 * rows that know nothing about it.
 *
 * Two states are shown differently on purpose: a shield for "this finding was
 * filed" and people for "a group filing covers this one". Both link to the
 * same issue; only the first means somebody looked at this row.
 *
 * The status shown in the tooltip is the status at filing time. Nothing here
 * calls AuditBoard, so an issue closed over there still reads as it was
 * created.
 */
function auditBoardColumn(index: FilingIndex | null): ColumnDef<Finding> {
    return {
        id: "auditboard",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="AuditBoard" />
        ),
        // Sortable and searchable on the label people actually quote.
        accessorFn: (row) => lookupFiling(index, row)?.filing.issue_uid ?? "",
        cell: ({ row }) => {
            const match = lookupFiling(index, row.original)
            if (!match) return <span className="text-muted-foreground">—</span>
            const { filing, direct } = match
            const label = filing.issue_uid || `I#${filing.issue_id}`
            const Icon = direct ? ShieldCheck : Users
            const title = [
                direct
                    ? "Filed to AuditBoard from this finding"
                    : "Covered by a global filing from the same scanner and file",
                filing.deficiency_level_name ? `Level: ${filing.deficiency_level_name}` : null,
                `Spoke for ${filing.occurrence_count} finding${filing.occurrence_count === 1 ? "" : "s"} when filed`,
                filing.filed_by ? `By ${filing.filed_by}` : null,
                filing.issue_status
                    ? `Status at filing: ${filing.issue_status} (not kept in sync)`
                    : null,
            ]
                .filter(Boolean)
                .join("\n")

            const badge = (
                <Badge
                    variant={direct ? "default" : "secondary"}
                    className="gap-1 font-mono text-xs"
                >
                    <Icon className="h-3 w-3" />
                    {label}
                </Badge>
            )

            return filing.issue_url ? (
                <a
                    href={filing.issue_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={title}
                    aria-label={`Open AuditBoard issue ${label}`}
                >
                    {badge}
                </a>
            ) : (
                <span title={title}>{badge}</span>
            )
        },
        filterFn: (row, id, value) => {
            if (!value || !Array.isArray(value) || value.length === 0) return true
            const uid = row.getValue(id) as string
            return value.includes(uid ? "Filed" : "Not filed")
        },
    }
}

// Column definitions
const baseColumns: ColumnDef<Finding>[] = [
    {
        accessorKey: "severity",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Severity" />
        ),
        cell: ({ row }) => getSeverityBadge(row.getValue("severity")),
        sortingFn: (rowA, rowB) => {
            const sevA = SEVERITY_ORDER[rowA.original.severity?.toLowerCase()] || 99
            const sevB = SEVERITY_ORDER[rowB.original.severity?.toLowerCase()] || 99
            return sevA - sevB
        },
        filterFn: (row, id, value) => {
            if (!value || !Array.isArray(value) || value.length === 0) return true
            return value.includes(row.getValue(id))
        },
    },
    {
        accessorKey: "title",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Title" />
        ),
        cell: ({ row }) => (
            <Link
                href={`/findings/${row.original.id}`}
                className="font-medium text-info-text hover:underline max-w-md truncate block"
                title={row.getValue("title")}
            >
                {row.getValue("title")}
            </Link>
        ),
    },
    {
        accessorKey: "repo_name",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Repository" />
        ),
        cell: ({ row }) => {
            const finding = row.original
            if (finding.repository_id) {
                return (
                    <Link
                        href={`/projects/${finding.repository_id}`}
                        className="font-medium text-info-text hover:underline"
                    >
                        {finding.repo_name}
                    </Link>
                )
            }
            return <span className="font-medium">{finding.repo_name}</span>
        },
        filterFn: (row, id, value) => {
            if (!value || !Array.isArray(value) || value.length === 0) return true
            return value.includes(row.getValue(id))
        },
    },
    {
        accessorKey: "scanner_name",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Scanner" />
        ),
        cell: ({ row }) => {
            const scanner = row.getValue("scanner_name") as string | null
            return scanner ? (
                <Badge variant="outline">{scanner}</Badge>
            ) : (
                <span className="text-muted-foreground">—</span>
            )
        },
        filterFn: (row, id, value) => {
            if (!value || !Array.isArray(value) || value.length === 0) return true
            const scanner = row.getValue(id) as string | null
            return value.includes(scanner || "")
        },
    },
    {
        accessorKey: "file_path",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="File" />
        ),
        cell: ({ row }) => {
            const filePath = row.getValue("file_path") as string | null
            const lineStart = row.original.line_start
            if (!filePath) return <span className="text-muted-foreground">—</span>
            return (
                <span className="font-mono text-xs max-w-xs truncate block" title={filePath}>
                    {filePath}
                    {lineStart && <span className="text-muted-foreground">:{lineStart}</span>}
                </span>
            )
        },
    },
    {
        accessorKey: "status",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Status" />
        ),
        cell: ({ row }) => {
            const status = row.getValue("status") as string
            const statusLower = status?.toLowerCase()
            const colorMap: Record<string, string> = {
                open: "border-danger text-danger-text",
                in_progress: "border-warning text-warning-text",
                resolved: "border-success text-success-text",
                false_positive: "border-border-strong text-muted-foreground",
                accepted_risk: "border-ai text-ai-text",
            }
            return (
                <Badge variant="outline" className={colorMap[statusLower] || ""}>
                    {status}
                </Badge>
            )
        },
        filterFn: (row, id, value) => {
            if (!value || !Array.isArray(value) || value.length === 0) return true
            return value.includes(row.getValue(id))
        },
    },
    {
        accessorKey: "risk_score",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Risk" />
        ),
        cell: ({ row }) => getRiskBadge(row.original.risk_score, row.original.risk_level),
        sortingFn: (rowA, rowB) => {
            const scoreA = rowA.original.risk_score ?? -1
            const scoreB = rowB.original.risk_score ?? -1
            return scoreB - scoreA // Higher risk first
        },
    },
    {
        accessorKey: "last_commit",
        id: "last_commit",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Last Commit" />
        ),
        accessorFn: (row) => row.file_last_commit_at || row.repo_pushed_at,
        cell: ({ row }) => {
            const finding = row.original
            const date = finding.file_last_commit_at || finding.repo_pushed_at
            const days = getDaysSince(date)
            return getCommitAgeBadge(days, !!finding.file_last_commit_at, finding.is_archived)
        },
        sortingFn: (rowA, rowB) => {
            const dateA = rowA.original.file_last_commit_at || rowA.original.repo_pushed_at
            const dateB = rowB.original.file_last_commit_at || rowB.original.repo_pushed_at
            if (!dateA && !dateB) return 0
            if (!dateA) return 1
            if (!dateB) return -1
            return new Date(dateA).getTime() - new Date(dateB).getTime()
        },
    },
]

export default function FindingsPage() {
    const [findings, setFindings] = useState<Finding[]>([])
    const [loading, setLoading] = useState(true)
    const [viewMode, setViewMode] = useState<"table" | "scorecard">("table")
    const [total, setTotal] = useState(0)
    const [filingIndex, setFilingIndex] = useState<FilingIndex | null>(null)
    // Bumped after a selection action files an issue or deletes findings, so
    // the AuditBoard column and the row set reflect what just happened rather
    // than waiting for a page reload.
    const [reloadKey, setReloadKey] = useState(0)

    // One request for every filing, not one per row. Failure is silent: a
    // missing AuditBoard column should not stop the findings table rendering.
    useEffect(() => {
        let cancelled = false
        apiFetch(`${API_BASE}/findings/auditboard/filings`, { credentials: "include" })
            .then((res) => (res.ok ? res.json() : []))
            .then((rows: AuditBoardFiling[]) => {
                if (!cancelled) setFilingIndex(buildFilingIndex(Array.isArray(rows) ? rows : []))
            })
            .catch(() => {})
        return () => {
            cancelled = true
        }
    }, [reloadKey])

    const columns = useMemo(
        () => [...baseColumns, auditBoardColumn(filingIndex)],
        [filingIndex],
    )

    useEffect(() => {
        const fetchFindings = async () => {
            setLoading(true)
            try {
                // Fetch all findings (with a reasonable limit for client-side processing)
                // We'll fetch in batches to get all data
                let allFindings: Finding[] = []
                let page = 1
                const pageSize = 100
                let hasMore = true

                while (hasMore) {
                    const params = new URLSearchParams({
                        page: page.toString(),
                        page_size: pageSize.toString(),
                        order_by: "severity"
                    })

                    const res = await apiFetch(`${API_BASE}/findings/paginated?${params}`, {
                        credentials: 'include'
                    })

                    if (res.ok) {
                        const data: PaginatedResponse = await res.json()
                        allFindings = [...allFindings, ...data.items]
                        setTotal(data.total)

                        // Continue fetching if there are more pages (up to a reasonable limit)
                        hasMore = data.has_next && allFindings.length < 5000
                        page++

                        // Update findings progressively for better UX
                        setFindings(allFindings)
                    } else {
                        hasMore = false
                    }
                }
            } catch (error) {
                console.error("Failed to fetch findings:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchFindings()
    }, [reloadKey])

    if (loading && findings.length === 0) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    return (
        <PageShell>
            <PageHeader
                icon={ShieldAlert}
                eyebrow="Security"
                title="All findings"
                description={
                    <>
                        {total.toLocaleString()} security issues across all repositories.
                        {loading && findings.length > 0 && (
                            <span className="ml-2 inline-flex items-center gap-1 text-info-text">
                                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                                Loading more
                            </span>
                        )}
                    </>
                }
                actions={
                <div className="flex items-center gap-1 rounded-lg border bg-muted p-1">
                    <Button
                        variant={viewMode === "scorecard" ? "secondary" : "ghost"}
                        size="sm"
                        onClick={() => setViewMode("scorecard")}
                        className="h-8 px-2 lg:px-3"
                    >
                        <LayoutGrid className="h-4 w-4 lg:mr-2" />
                        <span className="hidden lg:inline">Scorecard</span>
                    </Button>
                    <Button
                        variant={viewMode === "table" ? "secondary" : "ghost"}
                        size="sm"
                        onClick={() => setViewMode("table")}
                        className="h-8 px-2 lg:px-3"
                    >
                        <List className="h-4 w-4 lg:mr-2" />
                        <span className="hidden lg:inline">Table</span>
                    </Button>
                </div>
                }
            />

            {viewMode === "table" ? (
                <DataTable
                    columns={columns}
                    data={findings}
                    searchKey="title"
                    searchPlaceholder={`Search ${findings.length.toLocaleString()} findings...`}
                    tableId="findings"
                    enableGrouping={true}
                    initialPageSize={50}
                    enableSelectionColumn={true}
                    // Keyed on the finding's own id, not the row index.
                    // Without this the ticks stay on positions, so sorting or
                    // filtering would move a selection onto other findings —
                    // and one of the buttons on the selection toolbar files a
                    // GRC record that cannot be deleted.
                    getRowId={(row) => row.id}
                    selectionToolbar={(selection) => (
                        <FindingsSelectionToolbar
                            findings={selection.rows}
                            hiddenCount={selection.hiddenCount}
                            filteredCount={selection.filteredCount}
                            loadedCount={findings.length}
                            totalCount={total}
                            onClear={selection.clear}
                            onChanged={() => setReloadKey((key) => key + 1)}
                        />
                    )}
                />
            ) : (
                <ProjectScorecard />
            )}
        </PageShell>
    )
}
