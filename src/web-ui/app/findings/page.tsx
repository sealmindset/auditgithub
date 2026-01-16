"use client"

import { useEffect, useState } from "react"
import { DataTable } from "@/components/data-table"
import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Loader2, LayoutGrid, List } from "lucide-react"
import Link from "next/link"
import { ProjectScorecard } from "@/components/project-scorecard"
import { DataTableColumnHeader } from "@/components/data-table-column-header"

const API_BASE = "http://localhost:8000"

export default function FindingsPage() {
    const [findings, setFindings] = useState<any[]>([])
    const [loading, setLoading] = useState(true)
    const [viewMode, setViewMode] = useState<"table" | "scorecard">("table")

    useEffect(() => {
        const fetchFindings = async () => {
            try {
                // Fetch all findings (limit=0 means no limit)
                const res = await fetch(`${API_BASE}/findings/?limit=0&order_by=severity`)
                if (res.ok) {
                    const data = await res.json()
                    setFindings(data)
                }
            } catch (error) {
                console.error("Failed to fetch findings:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchFindings()
    }, [])

    const columns: ColumnDef<any>[] = [
        {
            accessorKey: "severity",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Severity" />
            ),
            cell: ({ row }) => {
                const severity = row.getValue("severity") as string
                return (
                    <Badge
                        className={
                            severity === "critical" ? "bg-red-500" :
                                severity === "high" ? "bg-orange-500" :
                                    severity === "medium" ? "bg-yellow-500" : "bg-blue-500"
                        }
                    >
                        {severity}
                    </Badge>
                )
            },
            filterFn: (row, id, value) => {
                return value.includes(row.getValue(id))
            },
        },
        {
            accessorKey: "title",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Title" />
            ),
            cell: ({ row }) => (
                <Link href={`/findings/${row.original.id}`} className="font-medium text-blue-600 hover:underline">
                    {row.getValue("title")}
                </Link>
            )
        },
        {
            accessorKey: "repo_name",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Repository" />
            ),
            cell: ({ row }) => {
                const repoId = row.original.repository_id
                const repoName = row.getValue("repo_name") as string
                return repoId ? (
                    <Link href={`/projects/${repoId}`} className="font-medium text-blue-600 hover:underline">
                        {repoName}
                    </Link>
                ) : (
                    <span className="font-medium">{repoName}</span>
                )
            },
            filterFn: (row, id, value) => {
                return value.includes(row.getValue(id))
            },
        },
        {
            accessorKey: "file_path",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="File" />
            ),
            cell: ({ row }) => (
                <span className="font-mono text-xs">{row.getValue("file_path")}</span>
            )
        },
        {
            accessorKey: "repo_pushed_at",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Last Commit" />
            ),
            cell: ({ row }) => {
                // Prefer file-level commit date, fall back to repo pushed_at
                const fileCommit = row.original.file_last_commit_at as string | null
                const repoPushed = row.getValue("repo_pushed_at") as string | null
                const date = fileCommit || repoPushed
                const isArchived = row.original.is_archived as boolean | null
                
                if (!date) return <span className="text-muted-foreground">—</span>
                return (
                    <div className="flex items-center gap-1">
                        <span className="text-sm text-muted-foreground">
                            {new Date(date).toLocaleDateString()}
                        </span>
                        {fileCommit && (
                            <span className="text-xs text-blue-500" title="File-level commit date">📄</span>
                        )}
                        {isArchived && (
                            <span className="text-xs text-amber-500" title="Archived repository">📦</span>
                        )}
                    </div>
                )
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
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">All Findings</h1>
                    <p className="text-muted-foreground">
                        Global view of security issues across all repositories.
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
                <DataTable columns={columns} data={findings} searchKey="title" tableId="findings" />
            ) : (
                <ProjectScorecard />
            )}
        </div>
    )
}
