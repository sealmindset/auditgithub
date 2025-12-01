"use client"

import { useEffect, useState } from "react"
import { DataTable } from "@/components/data-table"
import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Loader2 } from "lucide-react"
import Link from "next/link"
import { AiTriageDialog } from "@/components/ai-triage-dialog"

const API_BASE = "http://localhost:8000"

export default function FindingsPage() {
    const [findings, setFindings] = useState<any[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchFindings = async () => {
            try {
                const res = await fetch(`${API_BASE}/findings/?limit=500`)
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
            header: "Severity",
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
            }
        },
        {
            accessorKey: "title",
            header: "Title",
            cell: ({ row }) => (
                <Link href={`/findings/${row.original.id}`} className="font-medium text-blue-600 hover:underline">
                    {row.getValue("title")}
                </Link>
            )
        },
        {
            accessorKey: "repo_name",
            header: "Repository",
            cell: ({ row }) => (
                <span className="font-medium">{row.getValue("repo_name")}</span>
            )
        },
        {
            accessorKey: "file_path",
            header: "File",
            cell: ({ row }) => (
                <span className="font-mono text-xs">{row.getValue("file_path")}</span>
            )
        },
        {
            id: "actions",
            cell: ({ row }) => <AiTriageDialog finding={row.original} />
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
                <h1 className="text-3xl font-bold tracking-tight">All Findings</h1>
                <p className="text-muted-foreground">
                    Global view of security issues across all repositories.
                </p>
            </div>
            <DataTable columns={columns} data={findings} searchKey="title" />
        </div>
    )
}
