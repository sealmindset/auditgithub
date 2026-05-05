"use client"

import { useEffect, useState, useCallback } from "react"
import { DataTable } from "@/components/data-table"
import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Loader2, Clock, ScanSearch, Eye, EyeOff, Globe, Archive, FileText, Activity, Building2 } from "lucide-react"
import Link from "next/link"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { API_BASE, apiFetch } from "@/lib/api"

interface Organization {
    id: string
    name: string
    display_name: string | null
    github_org: string
    is_default: boolean
    total_repos: number
    total_findings: number
}

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
    const [initialLoading, setInitialLoading] = useState(true)
    const [refreshing, setRefreshing] = useState(false)
    const [organizations, setOrganizations] = useState<Organization[]>([])
    const [selectedOrgId, setSelectedOrgId] = useState<string>("")

    useEffect(() => {
        let cancelled = false
        const init = async () => {
            try {
                const orgRes = await apiFetch(`${API_BASE}/organizations/`)
                if (orgRes.ok && !cancelled) {
                    const orgs: Organization[] = await orgRes.json()
                    setOrganizations(orgs)

                    const savedOrgName = typeof window !== "undefined"
                        ? localStorage.getItem("selectedOrganization")
                        : null
                    const savedOrg = savedOrgName
                        ? orgs.find(o => o.name === savedOrgName)
                        : null
                    const activeOrg = savedOrg || orgs.find(o => o.is_default) || orgs[0]

                    if (activeOrg) {
                        setSelectedOrgId(activeOrg.id)
                        const res = await apiFetch(`${API_BASE}/projects/?organization_id=${activeOrg.id}`)
                        if (res.ok && !cancelled) {
                            setProjects(await res.json())
                        }
                    }
                }
            } catch (error) {
                console.error("Failed to initialize:", error)
            } finally {
                if (!cancelled) setInitialLoading(false)
            }
        }
        init()
        return () => { cancelled = true }
    }, [])

    const handleOrgChange = useCallback(async (orgId: string) => {
        setSelectedOrgId(orgId)
        setRefreshing(true)
        try {
            const org = organizations.find(o => o.id === orgId)
            if (org && typeof window !== "undefined") {
                localStorage.setItem("selectedOrganization", org.name)
            }
            const url = `${API_BASE}/projects/?organization_id=${orgId}`
            const res = await apiFetch(url)
            if (res.ok) {
                setProjects(await res.json())
            }
        } catch (error) {
            console.error("Failed to fetch projects:", error)
        } finally {
            setRefreshing(false)
        }
    }, [organizations])

    const deploymentStatusConfig: Record<string, { label: string; color: string }> = {
        production: { label: "Production", color: "bg-green-500 hover:bg-green-600" },
        staging: { label: "Staging", color: "bg-blue-500 hover:bg-blue-600" },
        development: { label: "Development", color: "bg-yellow-500 hover:bg-yellow-600" },
        deprecated: { label: "Deprecated", color: "bg-orange-500 hover:bg-orange-600" },
        archived: { label: "Archived", color: "bg-gray-500 hover:bg-gray-600" },
        decommissioned: { label: "Decommissioned", color: "bg-red-500 hover:bg-red-600" },
        unknown: { label: "Unknown", color: "" },
    }

    const columns: ColumnDef<any>[] = [
        {
            accessorKey: "name",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Name" />
            ),
            cell: ({ row }) => {
                const isArchived = row.original.is_archived
                const deploymentStatus = row.original.deployment_status as string | null
                const config = deploymentStatus ? deploymentStatusConfig[deploymentStatus] : null
                return (
                    <div className="flex items-center gap-2">
                        <Link href={`/projects/${row.original.id}`} className="font-medium text-blue-600 hover:underline">
                            {row.getValue("name")}
                        </Link>
                        {deploymentStatus && deploymentStatus !== "unknown" && config && (
                            <Badge className={`text-xs text-white ${config.color}`}>
                                <Activity className="h-3 w-3 mr-1" />
                                {config.label}
                            </Badge>
                        )}
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
        },
        {
            accessorKey: "has_architecture",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Architecture" />
            ),
            cell: ({ row }) => {
                const hasArchitecture = row.getValue("has_architecture") as boolean
                if (hasArchitecture) {
                    return (
                        <Badge className="bg-green-500 hover:bg-green-600">
                            <FileText className="h-3 w-3 mr-1" />
                            Yes
                        </Badge>
                    )
                } else {
                    return (
                        <Badge variant="secondary">
                            <FileText className="h-3 w-3 mr-1" />
                            No
                        </Badge>
                    )
                }
            },
            filterFn: (row, id, value) => {
                const hasArchitecture = row.getValue(id) as boolean
                return value.includes(hasArchitecture ? "yes" : "no")
            },
            sortingFn: (rowA, rowB) => {
                const a = rowA.getValue("has_architecture") as boolean
                const b = rowB.getValue("has_architecture") as boolean
                return (a === b) ? 0 : a ? -1 : 1
            }
        }
    ]

    if (initialLoading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    const selectedOrg = organizations.find(o => o.id === selectedOrgId)

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Repositories</h1>
                    <p className="text-muted-foreground">
                        {selectedOrg
                            ? `${selectedOrg.total_repos.toLocaleString()} repositories in ${selectedOrg.display_name || selectedOrg.github_org}`
                            : "All monitored repositories"}
                    </p>
                </div>
                {organizations.length > 0 && (
                    <Select value={selectedOrgId} onValueChange={handleOrgChange}>
                        <SelectTrigger className="w-[280px]">
                            <div className="flex items-center gap-2">
                                <Building2 className="h-4 w-4 text-muted-foreground" />
                                <SelectValue placeholder="Select organization" />
                            </div>
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">All Organizations</SelectItem>
                            {organizations.map(org => (
                                <SelectItem key={org.id} value={org.id}>
                                    <div className="flex items-center justify-between gap-4">
                                        <span>{org.display_name || org.github_org}</span>
                                        <span className="text-xs text-muted-foreground">
                                            {org.total_repos.toLocaleString()} repos
                                        </span>
                                    </div>
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                )}
            </div>
            {refreshing ? (
                <div className="flex items-center justify-center py-12">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
            ) : (
                <DataTable columns={columns} data={projects} searchKey="name" tableId="repositories" />
            )}
        </div>
    )
}
