"use client"

import { useEffect, useState } from "react"
import { DataTable } from "@/components/data-table"
import { ColumnDef } from "@tanstack/react-table"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Loader2, LayoutGrid, List, Clock, FileCode, Archive, ShieldAlert } from "lucide-react"
import Link from "next/link"
import { ProjectScorecard } from "@/components/project-scorecard"
import { API_BASE } from "@/lib/api"

interface Finding {
    id: string
    title: string
    description: string | null
    severity: string
    status: string
    scanner_name: string | null
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
        critical: "bg-red-500 hover:bg-red-600",
        high: "bg-orange-500 hover:bg-orange-600",
        medium: "bg-yellow-500 hover:bg-yellow-600",
        low: "bg-blue-500 hover:bg-blue-600",
        info: "bg-gray-400 hover:bg-gray-500",
        warning: "bg-amber-500 hover:bg-amber-600",
    }
    return (
        <Badge className={colorMap[severityLower] || "bg-gray-500"}>
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
                <FileCode className="h-3 w-3 text-blue-500" />
            </span>
        )
    }
    if (isArchived) {
        icons.push(
            <span key="archived" title="Archived repository">
                <Archive className="h-3 w-3 text-amber-500" />
            </span>
        )
    }

    let badge
    if (days < 31) {
        badge = (
            <Badge className="bg-green-500 hover:bg-green-600">
                <Clock className="h-3 w-3 mr-1" />
                {days}d ago
            </Badge>
        )
    } else if (days < 365) {
        badge = (
            <Badge className="bg-yellow-500 hover:bg-yellow-600">
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
        critical: "bg-red-500 hover:bg-red-600",
        high: "bg-orange-500 hover:bg-orange-600",
        medium: "bg-yellow-500 hover:bg-yellow-600",
        low: "bg-blue-500 hover:bg-blue-600",
    }

    return (
        <Badge className={colorMap[riskLevel?.toLowerCase() || ""] || "bg-gray-500"}>
            <ShieldAlert className="h-3 w-3 mr-1" />
            {riskScore}
        </Badge>
    )
}

// Column definitions
const columns: ColumnDef<Finding>[] = [
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
                className="font-medium text-blue-600 hover:underline max-w-md truncate block"
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
                        className="font-medium text-blue-600 hover:underline"
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
                open: "border-red-500 text-red-600",
                in_progress: "border-yellow-500 text-yellow-600",
                resolved: "border-green-500 text-green-600",
                false_positive: "border-gray-500 text-gray-600",
                accepted_risk: "border-purple-500 text-purple-600",
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

                    const res = await fetch(`${API_BASE}/findings/paginated?${params}`, {
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
    }, [])

    if (loading && findings.length === 0) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">All Findings</h1>
                    <p className="text-muted-foreground">
                        {total.toLocaleString()} security issues across all repositories.
                        {loading && findings.length > 0 && (
                            <span className="ml-2 text-blue-500">
                                <Loader2 className="h-4 w-4 animate-spin inline mr-1" />
                                Loading more...
                            </span>
                        )}
                    </p>
                </div>
                <div className="flex items-center gap-2 rounded-lg border p-1 bg-muted">
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
            </div>

            {viewMode === "table" ? (
                <DataTable
                    columns={columns}
                    data={findings}
                    searchKey="title"
                    searchPlaceholder={`Search ${findings.length.toLocaleString()} findings...`}
                    tableId="findings"
                    enableGrouping={true}
                    initialPageSize={50}
                />
            ) : (
                <ProjectScorecard />
            )}
        </div>
    )
}
