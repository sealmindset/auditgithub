"use client"

import { useEffect, useState } from "react"
import {
    ColumnDef,
    flexRender,
    getCoreRowModel,
    getSortedRowModel,
    getFilteredRowModel,
    SortingState,
    useReactTable,
} from "@tanstack/react-table"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Loader2, Users, GitCommit, AlertTriangle, FolderOpen, FileCode, Shield, Brain } from "lucide-react"
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import { ScrollArea } from "@/components/ui/scroll-area"

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

// Types
interface FileWithSeverity {
    path: string
    severity: string | null
    findings_count: number
}

interface ContributorSummary {
    id: string
    name: string
    email: string | null
    github_username: string | null
    commits: number
    commit_percentage: number | null
    last_commit_at: string | null
    languages: string[]
    files_count: number
    folders_count: number
    risk_score: number
    highest_severity: string | null
}

interface ContributorDetail {
    id: string
    name: string
    email: string | null
    github_username: string | null
    commits: number
    commit_percentage: number | null
    last_commit_at: string | null
    languages: string[]
    files_contributed: FileWithSeverity[]
    folders_contributed: string[]
    risk_score: number
    ai_summary: string | null
    critical_files_count: number
    high_files_count: number
    medium_files_count: number
    low_files_count: number
}

interface ContributorsResponse {
    total_contributors: number
    total_commits: number
    bus_factor: number
    team_ai_summary: string | null
    contributors: ContributorSummary[]
}

interface ContributorsViewProps {
    projectId: string
}

// Simple Progress component
function Progress({ value, className }: { value: number; className?: string }) {
    return (
        <div className={`h-2 w-full rounded-full bg-muted overflow-hidden ${className || ""}`}>
            <div
                className={`h-full transition-all ${value >= 50 ? "bg-red-500" : value >= 25 ? "bg-yellow-500" : "bg-green-500"}`}
                style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
            />
        </div>
    )
}

// Severity badge component
function SeverityBadge({ severity }: { severity: string | null }) {
    if (!severity) return null

    const variants: Record<string, string> = {
        critical: "bg-red-600 text-white hover:bg-red-600",
        high: "bg-orange-500 text-white hover:bg-orange-500",
        medium: "bg-yellow-500 text-black hover:bg-yellow-500",
        low: "bg-blue-500 text-white hover:bg-blue-500"
    }

    return (
        <Badge className={`text-xs ${variants[severity] || "bg-gray-500"}`}>
            {severity.toUpperCase()}
        </Badge>
    )
}

// Contributor Detail Modal Component
function ContributorModal({
    contributorId,
    projectId,
    isOpen,
    onClose
}: {
    contributorId: string | null
    projectId: string
    isOpen: boolean
    onClose: () => void
}) {
    const [detail, setDetail] = useState<ContributorDetail | null>(null)
    const [loading, setLoading] = useState(false)

    useEffect(() => {
        if (isOpen && contributorId) {
            setLoading(true)
            fetch(`${API_BASE}/projects/${projectId}/contributors/${contributorId}`)
                .then(res => res.json())
                .then(data => setDetail(data))
                .catch(console.error)
                .finally(() => setLoading(false))
        }
    }, [isOpen, contributorId, projectId])

    if (!isOpen) return null

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <DialogHeader>
                            <DialogTitle className="sr-only">Loading contributor details</DialogTitle>
                        </DialogHeader>
                        <Loader2 className="h-8 w-8 animate-spin" />
                    </div>
                ) : detail ? (
                    <>
                        <DialogHeader>
                            <div className="flex items-center gap-4">
                                <Avatar className="h-16 w-16">
                                    {detail.github_username && (
                                        <AvatarImage
                                            src={`https://github.com/${detail.github_username}.png`}
                                            alt={detail.name}
                                        />
                                    )}
                                    <AvatarFallback className="text-xl">
                                        {detail.name.split(" ").map(n => n[0]).join("").toUpperCase().slice(0, 2)}
                                    </AvatarFallback>
                                </Avatar>
                                <div className="flex-1">
                                    <DialogTitle className="text-2xl">{detail.name}</DialogTitle>
                                    <div className="text-sm text-muted-foreground">
                                        {detail.email}
                                        {detail.github_username && (
                                            <span className="ml-2 text-blue-500">@{detail.github_username}</span>
                                        )}
                                    </div>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Badge variant={detail.risk_score >= 50 ? "destructive" : "secondary"}>
                                        Risk Score: {detail.risk_score}
                                    </Badge>
                                </div>
                            </div>
                        </DialogHeader>

                        {/* Stats Cards */}
                        <div className="grid grid-cols-4 gap-4 my-4">
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold">{detail.commits}</div>
                                    <div className="text-xs text-muted-foreground">
                                        Commits ({detail.commit_percentage?.toFixed(1)}%)
                                    </div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold text-red-600">{detail.critical_files_count}</div>
                                    <div className="text-xs text-muted-foreground">Critical Files</div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold text-orange-500">{detail.high_files_count}</div>
                                    <div className="text-xs text-muted-foreground">High Severity</div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold">{detail.files_contributed.length}</div>
                                    <div className="text-xs text-muted-foreground">Total Files</div>
                                </CardContent>
                            </Card>
                        </div>

                        {/* AI Summary */}
                        {detail.ai_summary && (
                            <Card className="mb-4 bg-gradient-to-r from-purple-50 to-blue-50 dark:from-purple-950 dark:to-blue-950">
                                <CardHeader className="pb-2">
                                    <CardTitle className="text-sm flex items-center gap-2">
                                        <Brain className="h-4 w-4" />
                                        AI Security Analysis
                                    </CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-sm">{detail.ai_summary}</p>
                                </CardContent>
                            </Card>
                        )}

                        {/* Tabs for Files, Folders, Languages */}
                        <Tabs defaultValue="files" className="flex-1">
                            <TabsList className="grid w-full grid-cols-3">
                                <TabsTrigger value="files">
                                    <FileCode className="h-4 w-4 mr-2" />
                                    Files ({detail.files_contributed.length})
                                </TabsTrigger>
                                <TabsTrigger value="folders">
                                    <FolderOpen className="h-4 w-4 mr-2" />
                                    Folders ({detail.folders_contributed.length})
                                </TabsTrigger>
                                <TabsTrigger value="languages">
                                    <Shield className="h-4 w-4 mr-2" />
                                    Languages ({detail.languages.length})
                                </TabsTrigger>
                            </TabsList>

                            <TabsContent value="files" className="mt-4">
                                <ScrollArea className="h-[300px] pr-4">
                                    <div className="space-y-1">
                                        {detail.files_contributed.map((file, idx) => (
                                            <div
                                                key={idx}
                                                className="flex items-center justify-between p-2 rounded hover:bg-muted"
                                            >
                                                <div className="flex items-center gap-2 flex-1 min-w-0">
                                                    <FileCode className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                                                    <span className="text-sm font-mono truncate">{file.path}</span>
                                                </div>
                                                <div className="flex items-center gap-2 flex-shrink-0">
                                                    {file.findings_count > 0 && (
                                                        <span className="text-xs text-muted-foreground">
                                                            {file.findings_count} findings
                                                        </span>
                                                    )}
                                                    <SeverityBadge severity={file.severity} />
                                                </div>
                                            </div>
                                        ))}
                                        {detail.files_contributed.length === 0 && (
                                            <div className="text-center text-muted-foreground py-8">
                                                No files tracked for this contributor
                                            </div>
                                        )}
                                    </div>
                                </ScrollArea>
                            </TabsContent>

                            <TabsContent value="folders" className="mt-4">
                                <ScrollArea className="h-[300px] pr-4">
                                    <div className="grid grid-cols-3 gap-2">
                                        {detail.folders_contributed.map((folder, idx) => (
                                            <div
                                                key={idx}
                                                className="flex items-center gap-2 p-3 rounded-lg bg-muted"
                                            >
                                                <FolderOpen className="h-5 w-5 text-yellow-500" />
                                                <span className="text-sm font-medium">{folder}</span>
                                            </div>
                                        ))}
                                        {detail.folders_contributed.length === 0 && (
                                            <div className="col-span-3 text-center text-muted-foreground py-8">
                                                No folders tracked for this contributor
                                            </div>
                                        )}
                                    </div>
                                </ScrollArea>
                            </TabsContent>

                            <TabsContent value="languages" className="mt-4">
                                <div className="flex flex-wrap gap-3">
                                    {detail.languages.map((lang, idx) => (
                                        <Badge
                                            key={idx}
                                            variant="outline"
                                            className="text-base px-4 py-2"
                                        >
                                            {lang}
                                        </Badge>
                                    ))}
                                    {detail.languages.length === 0 && (
                                        <div className="text-center text-muted-foreground py-8 w-full">
                                            No languages detected for this contributor
                                        </div>
                                    )}
                                </div>
                            </TabsContent>
                        </Tabs>
                    </>
                ) : (
                    <div className="text-center text-muted-foreground">
                        <DialogHeader>
                            <DialogTitle className="sr-only">Contributor not found</DialogTitle>
                        </DialogHeader>
                        Contributor not found
                    </div>
                )}
            </DialogContent>
        </Dialog>
    )
}

// Main Contributors View Component
export function ContributorsView({ projectId }: ContributorsViewProps) {
    const [data, setData] = useState<ContributorsResponse | null>(null)
    const [loading, setLoading] = useState(true)
    const [sorting, setSorting] = useState<SortingState>([])
    const [globalFilter, setGlobalFilter] = useState("")
    const [selectedContributor, setSelectedContributor] = useState<string | null>(null)
    const [modalOpen, setModalOpen] = useState(false)

    useEffect(() => {
        fetch(`${API_BASE}/projects/${projectId}/contributors`)
            .then(res => {
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`)
                }
                return res.json()
            })
            .then(data => {
                // Ensure data has expected structure
                if (data && !data.contributors) {
                    // Handle old API format or error response
                    console.warn("API returned unexpected format:", data)
                    setData(null)
                } else {
                    setData(data)
                }
            })
            .catch(err => {
                console.error("Failed to fetch contributors:", err)
                setData(null)
            })
            .finally(() => setLoading(false))
    }, [projectId])

    const handleContributorClick = (contributorId: string) => {
        setSelectedContributor(contributorId)
        setModalOpen(true)
    }

    const columns: ColumnDef<ContributorSummary>[] = [
        {
            accessorKey: "name",
            header: "Contributor",
            cell: ({ row }) => {
                const name = row.getValue("name") as string
                const email = row.original.email
                const github = row.original.github_username
                const initials = name.split(" ").map(n => n[0]).join("").toUpperCase().slice(0, 2)

                return (
                    <button
                        onClick={() => handleContributorClick(row.original.id)}
                        className="flex items-center gap-3 hover:bg-muted p-2 rounded-lg transition-colors w-full text-left"
                    >
                        <Avatar className="h-10 w-10">
                            {github && <AvatarImage src={`https://github.com/${github}.png`} alt={name} />}
                            <AvatarFallback>{initials}</AvatarFallback>
                        </Avatar>
                        <div>
                            <div className="font-medium text-primary hover:underline">{name}</div>
                            {email && <div className="text-xs text-muted-foreground">{email}</div>}
                        </div>
                    </button>
                )
            },
        },
        {
            accessorKey: "commits",
            header: "Commits",
            cell: ({ row }) => (
                <div className="text-center">
                    <div className="font-semibold">{row.getValue("commits")}</div>
                    <div className="text-xs text-muted-foreground">
                        {row.original.commit_percentage?.toFixed(1)}%
                    </div>
                </div>
            ),
        },
        {
            accessorKey: "files_count",
            header: "Files",
            cell: ({ row }) => (
                <Badge variant="secondary">{row.getValue("files_count")} files</Badge>
            ),
        },
        {
            accessorKey: "highest_severity",
            header: "Severity",
            cell: ({ row }) => <SeverityBadge severity={row.getValue("highest_severity")} />,
        },
        {
            accessorKey: "risk_score",
            header: "Risk",
            cell: ({ row }) => {
                const score = row.getValue("risk_score") as number
                return (
                    <div className="flex items-center gap-2">
                        <Progress value={score} className="w-16" />
                        <span className={`text-sm font-medium ${score >= 50 ? 'text-red-500' : ''}`}>
                            {score}
                        </span>
                    </div>
                )
            },
        },
        {
            accessorKey: "languages",
            header: "Languages",
            cell: ({ row }) => {
                const languages = row.getValue("languages") as string[]
                return (
                    <div className="flex flex-wrap gap-1">
                        {languages.slice(0, 3).map(lang => (
                            <Badge key={lang} variant="outline" className="text-xs">{lang}</Badge>
                        ))}
                        {languages.length > 3 && (
                            <Badge variant="secondary" className="text-xs">+{languages.length - 3}</Badge>
                        )}
                    </div>
                )
            },
        },
    ]

    const table = useReactTable({
        data: data?.contributors || [],
        columns,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
        onSortingChange: setSorting,
        onGlobalFilterChange: setGlobalFilter,
        state: { sorting, globalFilter },
    })

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        )
    }

    if (!data || !data.contributors || data.contributors.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                <Users className="h-12 w-12 mb-4" />
                <p>No contributor data available</p>
                <p className="text-sm">Run a scan to collect contributor information</p>
            </div>
        )
    }

    return (
        <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card>
                    <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <Users className="h-4 w-4" /> Total Contributors
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{data.total_contributors}</div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <GitCommit className="h-4 w-4" /> Total Commits
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{data.total_commits.toLocaleString()}</div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4" /> Bus Factor
                        </CardTitle>
                        <CardDescription className="text-xs">
                            Contributors needed for 50% of commits
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {data.bus_factor}
                            {data.bus_factor <= 2 && (
                                <Badge variant="destructive" className="ml-2 text-xs">Risk</Badge>
                            )}
                        </div>
                    </CardContent>
                </Card>
            </div>

            {/* Search */}
            <div className="flex items-center gap-4">
                <Input
                    placeholder="Search contributors..."
                    value={globalFilter}
                    onChange={(e) => setGlobalFilter(e.target.value)}
                    className="max-w-sm"
                />
                <p className="text-sm text-muted-foreground">
                    Click on a contributor name to view full details
                </p>
            </div>

            {/* Contributors Table */}
            <div className="rounded-md border">
                <Table>
                    <TableHeader>
                        {table.getHeaderGroups().map(headerGroup => (
                            <TableRow key={headerGroup.id}>
                                {headerGroup.headers.map(header => (
                                    <TableHead key={header.id}>
                                        {header.isPlaceholder ? null : flexRender(
                                            header.column.columnDef.header,
                                            header.getContext()
                                        )}
                                    </TableHead>
                                ))}
                            </TableRow>
                        ))}
                    </TableHeader>
                    <TableBody>
                        {table.getRowModel().rows?.length ? (
                            table.getRowModel().rows.map(row => (
                                <TableRow key={row.id}>
                                    {row.getVisibleCells().map(cell => (
                                        <TableCell key={cell.id}>
                                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                        </TableCell>
                                    ))}
                                </TableRow>
                            ))
                        ) : (
                            <TableRow>
                                <TableCell colSpan={columns.length} className="h-24 text-center">
                                    No contributors found.
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </div>

            {/* Contributor Detail Modal */}
            <ContributorModal
                contributorId={selectedContributor}
                projectId={projectId}
                isOpen={modalOpen}
                onClose={() => setModalOpen(false)}
            />
        </div>
    )
}
