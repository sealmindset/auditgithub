"use client"

import { useEffect, useState } from "react"
import { DataTable } from "@/components/data-table"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Loader2 } from "lucide-react"

interface LanguageStat {
    name: string
    files: number
    lines: number
    blanks: number
    comments: number
    findings: {
        critical: number
        high: number
        medium: number
        low: number
    }
}

interface LanguagesViewProps {
    projectId: string
}

const API_BASE = "http://localhost:8000"

export function LanguagesView({ projectId }: LanguagesViewProps) {
    const [languages, setLanguages] = useState<LanguageStat[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchLanguages = async () => {
            try {
                const res = await fetch(`${API_BASE}/projects/${projectId}/languages`)
                if (res.ok) {
                    const data = await res.json()
                    setLanguages(data)
                }
            } catch (error) {
                console.error("Failed to fetch languages:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchLanguages()
    }, [projectId])

    const columns: ColumnDef<LanguageStat>[] = [
        {
            accessorKey: "name",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Language" />
            ),
            cell: ({ row }) => (
                <div className="font-medium">{row.getValue("name")}</div>
            )
        },
        {
            accessorKey: "files",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Files" />
            ),
            cell: ({ row }) => (
                <div>{row.getValue("files")}</div>
            )
        },
        {
            accessorKey: "lines",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Lines of Code" />
            ),
            cell: ({ row }) => (
                <div className="font-mono">{row.getValue("lines")}</div>
            )
        },
        {
            id: "total_lines",
            header: "Total Lines",
            cell: ({ row }) => {
                const total = row.original.lines + row.original.blanks + row.original.comments
                return <div className="text-muted-foreground">{total}</div>
            }
        },
        {
            id: "findings",
            header: "Findings by Severity",
            cell: ({ row }) => {
                const findings = row.original.findings
                return (
                    <div className="flex gap-2">
                        {findings.critical > 0 && (
                            <Badge variant="destructive" className="h-5 px-1.5 text-[10px]">
                                Crit: {findings.critical}
                            </Badge>
                        )}
                        {findings.high > 0 && (
                            <Badge className="bg-orange-500 hover:bg-orange-600 h-5 px-1.5 text-[10px]">
                                High: {findings.high}
                            </Badge>
                        )}
                        {findings.medium > 0 && (
                            <Badge className="bg-yellow-500 hover:bg-yellow-600 h-5 px-1.5 text-[10px]">
                                Med: {findings.medium}
                            </Badge>
                        )}
                        {findings.low > 0 && (
                            <Badge className="bg-blue-500 hover:bg-blue-600 h-5 px-1.5 text-[10px]">
                                Low: {findings.low}
                            </Badge>
                        )}
                        {Object.values(findings).reduce((a, b) => a + b, 0) === 0 && (
                            <span className="text-xs text-muted-foreground">No findings</span>
                        )}
                    </div>
                )
            }
        }
    ]

    if (loading) {
        return (
            <div className="flex h-40 items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        )
    }

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <div>
                    <h3 className="text-lg font-medium">Language Statistics</h3>
                    <p className="text-sm text-muted-foreground">
                        Breakdown of code lines and security findings by language.
                    </p>
                </div>
            </div>
            <DataTable columns={columns} data={languages} searchKey="name" tableId="languages" />
        </div>
    )
}
