"use client"

import { useEffect, useState } from "react"
import { DataTable } from "@/components/data-table"
import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Loader2 } from "lucide-react"
import Link from "next/link"
import { DataTableColumnHeader } from "@/components/data-table-column-header"

const API_BASE = "http://localhost:8000"

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
            cell: ({ row }) => (
                <Link href={`/projects/${row.original.id}`} className="font-medium text-blue-600 hover:underline">
                    {row.getValue("name")}
                </Link>
            ),
            filterFn: (row, id, value) => {
                return value.includes(row.getValue(id))
            },
        },
        {
            accessorKey: "language",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Language" />
            ),
            filterFn: (row, id, value) => {
                return value.includes(row.getValue(id))
            },
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
            accessorKey: "last_scanned_at",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Last Scanned" />
            ),
            cell: ({ row }) => {
                const date = row.getValue("last_scanned_at") as string
                return date ? new Date(date).toLocaleDateString() : "Never"
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
            <DataTable columns={columns} data={projects} searchKey="name" />
        </div>
    )
}
