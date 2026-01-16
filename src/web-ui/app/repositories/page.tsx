"use client"

import { useEffect, useState } from "react"
import { DataTable } from "@/components/data-table"
import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Loader2, Clock, ScanSearch, Eye, EyeOff, Globe, Archive } from "lucide-react"
import Link from "next/link"
import { DataTableColumnHeader } from "@/components/data-table-column-header"

const API_BASE = "http://localhost:8000"

function getDaysSince(date: string | null): number | null {
    if (!date) return null
    const now = new Date()
    const pastDate = new Date(date)
    const diffTime = Math.abs(now.getTime() - pastDate.getTime())
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    return diffDays
}

function getCommitAgeBadge(days: number | null) {
    if (days === null) {
        return (
            <Badge variant="secondary">
                <Clock className="h-3 w-3 mr-1" />
                No data
            </Badge>
        )
    }

    if (days < 31) {
        return (
            <Badge className="bg-green-500 hover:bg-green-600">
                <Clock className="h-3 w-3 mr-1" />
                {days}d ago
            </Badge>
        )
    } else if (days < 365) {
        return (
            <Badge className="bg-yellow-500 hover:bg-yellow-600">
                <Clock className="h-3 w-3 mr-1" />
                {days}d ago
            </Badge>
        )
    } else {
        const years = Math.floor(days / 365)
        return (
            <Badge variant="destructive">
                <Clock className="h-3 w-3 mr-1" />
                {years}y ago
            </Badge>
        )
    }
}

function getScanAgeBadge(days: number | null) {
    if (days === null) {
        return (
            <Badge variant="secondary">
                <ScanSearch className="h-3 w-3 mr-1" />
                Never scanned
            </Badge>
        )
    }

    // Color coding for scan age:
    // < 7 days: green (fresh scan)
    // 7-30 days: yellow (scan aging)
    // > 30 days: red (scan outdated)
    if (days < 7) {
        return (
            <Badge className="bg-green-500 hover:bg-green-600">
                <ScanSearch className="h-3 w-3 mr-1" />
                Scanned {days}d ago
            </Badge>
        )
    } else if (days < 30) {
        return (
            <Badge className="bg-yellow-500 hover:bg-yellow-600">
                <ScanSearch className="h-3 w-3 mr-1" />
                Scanned {days}d ago
            </Badge>
        )
    } else if (days < 365) {
        return (
            <Badge variant="destructive">
                <ScanSearch className="h-3 w-3 mr-1" />
                Scanned {days}d ago
            </Badge>
        )
    } else {
        const years = Math.floor(days / 365)
        return (
            <Badge variant="destructive">
                <ScanSearch className="h-3 w-3 mr-1" />
                Scanned {years}y ago
            </Badge>
        )
    }
}

export default function RepositoriesPage() {
    const [projects, setProjects] = useState<any[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchProjects = async () => {
            try {
                const res = await fetch(`${API_BASE}/projects/`)
                if (res.ok) {
                    const data = await res.json()
                    setProjects(data)
                }
            } catch (error) {
                console.error("Failed to fetch projects:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchProjects()
    }, [])

    const columns: ColumnDef<any>[] = [
        {
            accessorKey: "name",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Name" />
            ),
            cell: ({ row }) => {
                const isArchived = row.original.is_archived
                return (
                    <div className="flex items-center gap-2">
                        <Link href={`/projects/${row.original.id}`} className="font-medium text-blue-600 hover:underline">
                            {row.getValue("name")}
                        </Link>
                        {isArchived && (
                            <Badge variant="secondary" className="text-xs">
                                <Archive className="h-3 w-3 mr-1" />
                                Archived
                            </Badge>
                        )}
                    </div>
                )
            }
        },
        {
            accessorKey: "visibility",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Visibility" />
            ),
            cell: ({ row }) => {
                const visibility = row.getValue("visibility") as string | null
                const isPrivate = row.original.is_private
                
                // Determine visibility: use visibility field, fallback to is_private
                const effectiveVisibility = visibility || (isPrivate ? "private" : "public")
                
                if (effectiveVisibility === "public") {
                    return (
                        <Badge variant="destructive" className="bg-red-500 hover:bg-red-600">
                            <Globe className="h-3 w-3 mr-1" />
                            Public
                        </Badge>
                    )
                } else if (effectiveVisibility === "internal") {
                    return (
                        <Badge className="bg-green-500 hover:bg-green-600">
                            <Eye className="h-3 w-3 mr-1" />
                            Internal
                        </Badge>
                    )
                } else {
                    return (
                        <Badge className="bg-green-500 hover:bg-green-600">
                            <EyeOff className="h-3 w-3 mr-1" />
                            Private
                        </Badge>
                    )
                }
            },
            filterFn: (row, id, value) => {
                const visibility = row.getValue(id) as string | null
                const isPrivate = row.original.is_private
                const effectiveVisibility = visibility || (isPrivate ? "private" : "public")
                return value.includes(effectiveVisibility)
            }
        },
        {
            accessorKey: "last_commit_at",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Last Commit" />
            ),
            cell: ({ row }) => {
                // Use pushed_at from GitHub API (already mapped to last_commit_at in API)
                const commitDays = getDaysSince(row.getValue("last_commit_at") as string)
                return getCommitAgeBadge(commitDays)
            },
            sortingFn: (rowA, rowB) => {
                const dateA = rowA.original.last_commit_at
                const dateB = rowB.original.last_commit_at
                if (!dateA && !dateB) return 0
                if (!dateA) return 1
                if (!dateB) return -1
                return new Date(dateA).getTime() - new Date(dateB).getTime()
            }
        },
        {
            accessorKey: "last_scanned_at",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Last Scan" />
            ),
            cell: ({ row }) => {
                const scanDays = getDaysSince(row.getValue("last_scanned_at") as string)
                return getScanAgeBadge(scanDays)
            },
            sortingFn: (rowA, rowB) => {
                const dateA = rowA.original.last_scanned_at
                const dateB = rowB.original.last_scanned_at
                if (!dateA && !dateB) return 0
                if (!dateA) return 1
                if (!dateB) return -1
                return new Date(dateA).getTime() - new Date(dateB).getTime()
            }
        },
        {
            accessorKey: "stats.open_findings",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Open Findings" />
            ),
            cell: ({ row }) => {
                const count = row.original.stats.open_findings
                return (
                    <Badge variant={count > 0 ? "destructive" : "secondary"}>
                        {count}
                    </Badge>
                )
            }
        },
        {
            accessorKey: "max_severity",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Severity" />
            ),
            cell: ({ row }) => {
                const severity = row.getValue("max_severity") as string | null
                if (!severity) {
                    return (
                        <Badge variant="secondary">
                            None
                        </Badge>
                    )
                }
                const severityLower = severity.toLowerCase()
                return (
                    <Badge
                        className={
                            severityLower === "critical" ? "bg-red-500 hover:bg-red-600" :
                            severityLower === "high" ? "bg-orange-500 hover:bg-orange-600" :
                            severityLower === "medium" ? "bg-yellow-500 hover:bg-yellow-600" :
                            "bg-blue-500 hover:bg-blue-600"
                        }
                    >
                        {severity}
                    </Badge>
                )
            },
            filterFn: (row, id, value) => {
                return value.includes(row.getValue(id))
            },
            sortingFn: (rowA, rowB) => {
                const severityOrder: { [key: string]: number } = {
                    'critical': 4,
                    'high': 3,
                    'medium': 2,
                    'low': 1
                }
                const sevA = rowA.getValue("max_severity") as string | null
                const sevB = rowB.getValue("max_severity") as string | null
                const valueA = sevA ? severityOrder[sevA.toLowerCase()] || 0 : 0
                const valueB = sevB ? severityOrder[sevB.toLowerCase()] || 0 : 0
                return valueA - valueB
            }
        }
    ]

    if (loading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Repositories</h1>
                <p className="text-muted-foreground">
                    List of all monitored repositories.
                </p>
            </div>
            <DataTable columns={columns} data={projects} searchKey="name" tableId="repositories" />
        </div>
    )
}
