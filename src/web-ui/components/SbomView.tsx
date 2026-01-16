"use client"

import { useEffect, useState } from "react"
import { DataTable } from "@/components/data-table"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Loader2, Package, FileCode } from "lucide-react"
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip"

import { AskComponentDialog } from "./AskComponentDialog"

interface Dependency {
    id: string
    name: string
    version: string
    type: string
    package_manager: string
    license: string
    locations: string[]
    source?: string
    vulnerability_count: number
    max_severity: string
    ai_analysis?: any
}

interface SbomViewProps {
    projectId: string
}

const API_BASE = "http://localhost:8000"

export function SbomView({ projectId }: SbomViewProps) {
    const [dependencies, setDependencies] = useState<Dependency[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchDependencies = async () => {
            try {
                const res = await fetch(`${API_BASE}/projects/${projectId}/dependencies`)
                if (res.ok) {
                    const data = await res.json()
                    setDependencies(data)
                }
            } catch (error) {
                console.error("Failed to fetch dependencies:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchDependencies()
    }, [projectId])

    const getSeverityBadge = (sev: string) => {
        switch (sev?.toLowerCase()) {
            case "critical": return "bg-red-500 hover:bg-red-600"
            case "high": return "bg-orange-500 hover:bg-orange-600"
            case "medium": return "bg-yellow-500 hover:bg-yellow-600"
            case "low": return "bg-blue-500 hover:bg-blue-600"
            default: return "bg-gray-500"
        }
    }

    const columns: ColumnDef<Dependency>[] = [
        {
            accessorKey: "name",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Component" />
            ),
            cell: ({ row }) => (
                <div className="flex items-center gap-2">
                    <Package className="h-4 w-4 text-muted-foreground" />
                    <span className="font-medium">{row.getValue("name")}</span>
                </div>
            )
        },
        {
            accessorKey: "version",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Version" />
            ),
            cell: ({ row }) => (
                <div className="font-mono text-sm">{row.getValue("version")}</div>
            )
        },
        {
            accessorKey: "vulnerability_count",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Vulnerabilities" />
            ),
            cell: ({ row }) => {
                const count = row.original.vulnerability_count
                const maxSev = row.original.max_severity

                if (count === 0) {
                    return <Badge variant="outline" className="text-muted-foreground">Safe</Badge>
                }

                return (
                    <div className="flex items-center gap-2">
                        <Badge className={getSeverityBadge(maxSev)}>{maxSev}</Badge>
                        <span className="text-sm text-muted-foreground">({count})</span>
                    </div>
                )
            }
        },
        {
            id: "analysis",
            header: "AI Analysis",
            cell: ({ row }) => {
                const dep = row.original
                return (
                    <AskComponentDialog
                        packageName={dep.name}
                        version={dep.version}
                        packageManager={dep.package_manager}
                        existingAnalysis={dep.ai_analysis}
                    />
                )
            }
        },
        {
            accessorKey: "type",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Type" />
            ),
            cell: ({ row }) => (
                <Badge variant="outline">{row.getValue("type")}</Badge>
            ),
            filterFn: (row, id, value) => {
                return value.includes(row.getValue(id))
            },
        },
        {
            accessorKey: "license",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="License" />
            ),
            cell: ({ row }) => {
                const license = row.getValue("license") as string
                return (
                    <div className="max-w-[200px] truncate" title={license}>
                        {license === "[]" || !license ? (
                            <span className="text-muted-foreground italic">Unknown</span>
                        ) : (
                            license.replace(/[\[\]']/g, "")
                        )}
                    </div>
                )
            }
        },
        {
            accessorKey: "source",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Source/Vendor" />
            ),
            cell: ({ row }) => (
                <div className="text-sm text-muted-foreground">
                    {row.getValue("source") || "-"}
                </div>
            )
        },
        {
            id: "locations",
            header: "Locations",
            cell: ({ row }) => {
                const locations = row.original.locations
                return (
                    <TooltipProvider>
                        <Tooltip>
                            <TooltipTrigger asChild>
                                <div className="flex items-center gap-1 cursor-help">
                                    <FileCode className="h-3 w-3 text-muted-foreground" />
                                    <span className="text-xs">{locations.length} file(s)</span>
                                </div>
                            </TooltipTrigger>
                            <TooltipContent>
                                <div className="flex flex-col gap-1">
                                    {locations.slice(0, 5).map((loc, i) => (
                                        <span key={i} className="text-xs font-mono">{loc}</span>
                                    ))}
                                    {locations.length > 5 && (
                                        <span className="text-xs text-muted-foreground">...and {locations.length - 5} more</span>
                                    )}
                                </div>
                            </TooltipContent>
                        </Tooltip>
                    </TooltipProvider>
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
                    <h3 className="text-lg font-medium">Software Bill of Materials (SBOM)</h3>
                    <p className="text-sm text-muted-foreground">
                        Inventory of all third-party components, libraries, and modules.
                    </p>
                </div>
                <div className="text-sm text-muted-foreground">
                    Total Components: <span className="font-medium text-foreground">{dependencies.length}</span>
                </div>
            </div>
            <DataTable columns={columns} data={dependencies} searchKey="name" tableId="sbom-dependencies" />
        </div>
    )
}
