"use client"

import { useEffect, useState, useCallback } from "react"
import { ColumnDef } from "@tanstack/react-table"
import Link from "next/link"
import { DataTable } from "@/components/data-table"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { API_BASE, apiFetch } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog"
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip"
import {
    Loader2,
    Plus,
    FileText,
    CheckCircle2,
    Layers,
    Bot,
    Search,
    X,
    Lock,
    Tag,
} from "lucide-react"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Prompt {
    id: string
    slug: string
    name: string
    description: string | null
    category: string
    subcategory: string | null
    agent_id: string | null
    provider: string | null
    model: string | null
    current_version: number
    is_active: boolean
    is_locked: boolean
    source_file: string | null
    created_at: string
    updated_at: string
    tags: string[]
    usage_count: number | null
    version_count: number | null
}

interface PromptsResponse {
    items: Prompt[]
    total: number
    skip: number
    limit: number
}

interface AnalyticsOverview {
    total_prompts: number
    active_prompts: number
    total_versions: number
    total_agents: number
}

interface CreatePromptForm {
    slug: string
    name: string
    description: string
    category: string
    provider: string
    model: string
    content: string
    tags: string
    change_summary: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CATEGORIES = ["system", "user", "template", "agent", "skill", "mcp"] as const

const CATEGORY_COLORS: Record<string, string> = {
    system: "bg-purple-500/15 text-purple-700 dark:text-purple-400 border-purple-500/20",
    user: "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/20",
    template: "bg-green-500/15 text-green-700 dark:text-green-400 border-green-500/20",
    agent: "bg-orange-500/15 text-orange-700 dark:text-orange-400 border-orange-500/20",
    skill: "bg-cyan-500/15 text-cyan-700 dark:text-cyan-400 border-cyan-500/20",
    mcp: "bg-pink-500/15 text-pink-700 dark:text-pink-400 border-pink-500/20",
}

const PROVIDERS = [
    "anthropic",
    "openai",
    "azure",
    "google",
    "aws-bedrock",
    "local",
] as const

const EMPTY_FORM: CreatePromptForm = {
    slug: "",
    name: "",
    description: "",
    category: "",
    provider: "",
    model: "",
    content: "",
    tags: "",
    change_summary: "",
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(dateStr: string): string {
    const date = new Date(dateStr)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))

    if (diffDays === 0) return "Today"
    if (diffDays === 1) return "Yesterday"
    if (diffDays < 7) return `${diffDays}d ago`
    if (diffDays < 30) return `${Math.floor(diffDays / 7)}w ago`
    return date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: date.getFullYear() !== now.getFullYear() ? "numeric" : undefined,
    })
}

function getCategoryBadge(category: string) {
    const colorClass = CATEGORY_COLORS[category] ?? "bg-muted text-muted-foreground"
    return (
        <Badge variant="outline" className={colorClass}>
            {category}
        </Badge>
    )
}

function getModelBadge(model: string | null) {
    if (!model) return <span className="text-muted-foreground text-sm">--</span>
    return (
        <Badge
            variant="secondary"
            className="font-mono text-xs bg-slate-500/10 text-slate-700 dark:text-slate-300 border-slate-500/20"
        >
            {model}
        </Badge>
    )
}

function getStatusBadge(isActive: boolean) {
    if (isActive) {
        return (
            <Badge className="bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/20" variant="outline">
                <CheckCircle2 className="h-3 w-3 mr-1" />
                Active
            </Badge>
        )
    }
    return (
        <Badge variant="outline" className="text-muted-foreground">
            Inactive
        </Badge>
    )
}

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

const columns: ColumnDef<Prompt>[] = [
    {
        accessorKey: "name",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Name" />
        ),
        cell: ({ row }) => {
            const prompt = row.original
            return (
                <div className="flex items-center gap-2 min-w-[180px]">
                    <Link
                        href={`/prompts/${prompt.slug}`}
                        className="font-medium text-blue-600 dark:text-blue-400 hover:underline truncate"
                    >
                        {prompt.name}
                    </Link>
                    {prompt.is_locked && (
                        <TooltipProvider>
                            <Tooltip>
                                <TooltipTrigger asChild>
                                    <Lock className="h-3.5 w-3.5 text-amber-500 shrink-0" />
                                </TooltipTrigger>
                                <TooltipContent>Locked prompt</TooltipContent>
                            </Tooltip>
                        </TooltipProvider>
                    )}
                </div>
            )
        },
    },
    {
        accessorKey: "slug",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Slug" />
        ),
        cell: ({ row }) => (
            <span className="font-mono text-xs text-muted-foreground">
                {row.getValue("slug")}
            </span>
        ),
    },
    {
        accessorKey: "category",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Category" />
        ),
        cell: ({ row }) => getCategoryBadge(row.getValue("category")),
        filterFn: (row, id, value) => {
            return value.includes(row.getValue(id))
        },
    },
    {
        accessorKey: "model",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Model" />
        ),
        cell: ({ row }) => getModelBadge(row.getValue("model")),
    },
    {
        accessorKey: "provider",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Provider" />
        ),
        cell: ({ row }) => {
            const provider = row.getValue("provider") as string | null
            return provider ? (
                <span className="text-sm capitalize">{provider}</span>
            ) : (
                <span className="text-muted-foreground text-sm">--</span>
            )
        },
        filterFn: (row, id, value) => {
            return value.includes(row.getValue(id))
        },
    },
    {
        accessorKey: "agent_id",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Agent" />
        ),
        cell: ({ row }) => {
            const agentId = row.getValue("agent_id") as string | null
            return agentId ? (
                <Badge variant="outline" className="text-xs">
                    <Bot className="h-3 w-3 mr-1" />
                    {agentId.slice(0, 8)}
                </Badge>
            ) : (
                <span className="text-muted-foreground text-sm">--</span>
            )
        },
    },
    {
        accessorKey: "current_version",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Version" />
        ),
        cell: ({ row }) => (
            <Badge variant="secondary" className="font-mono text-xs">
                v{row.getValue("current_version")}
            </Badge>
        ),
    },
    {
        accessorKey: "is_active",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Status" />
        ),
        cell: ({ row }) => getStatusBadge(row.getValue("is_active")),
        filterFn: (row, id, value) => {
            const isActive = row.getValue(id) as boolean
            return value.includes(isActive ? "active" : "inactive")
        },
    },
    {
        accessorKey: "source_file",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Used In" />
        ),
        cell: ({ row }) => {
            const sourceFile = row.getValue("source_file") as string | null
            if (!sourceFile) return <span className="text-muted-foreground text-sm">--</span>
            // Show just the filename, with full path in tooltip
            const shortName = sourceFile.split("/").pop() ?? sourceFile
            return (
                <TooltipProvider>
                    <Tooltip>
                        <TooltipTrigger asChild>
                            <span className="font-mono text-xs text-muted-foreground truncate max-w-[140px] inline-block">
                                {shortName}
                            </span>
                        </TooltipTrigger>
                        <TooltipContent>
                            <span className="font-mono text-xs">{sourceFile}</span>
                        </TooltipContent>
                    </Tooltip>
                </TooltipProvider>
            )
        },
    },
    {
        accessorKey: "updated_at",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Updated" />
        ),
        cell: ({ row }) => (
            <TooltipProvider>
                <Tooltip>
                    <TooltipTrigger asChild>
                        <span className="text-sm text-muted-foreground whitespace-nowrap">
                            {formatDate(row.getValue("updated_at"))}
                        </span>
                    </TooltipTrigger>
                    <TooltipContent>
                        {new Date(row.getValue("updated_at")).toLocaleString()}
                    </TooltipContent>
                </Tooltip>
            </TooltipProvider>
        ),
        sortingFn: (rowA, rowB) => {
            const dateA = new Date(rowA.original.updated_at).getTime()
            const dateB = new Date(rowB.original.updated_at).getTime()
            return dateA - dateB
        },
    },
]

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

export default function PromptsPage() {
    // Data state
    const [prompts, setPrompts] = useState<Prompt[]>([])
    const [analytics, setAnalytics] = useState<AnalyticsOverview | null>(null)
    const [loading, setLoading] = useState(true)
    const [total, setTotal] = useState(0)
    const [fetchError, setFetchError] = useState<string | null>(null)

    // Filter state
    const [searchQuery, setSearchQuery] = useState("")
    const [categoryFilter, setCategoryFilter] = useState<string>("all")
    const [providerFilter, setProviderFilter] = useState<string>("all")
    const [statusFilter, setStatusFilter] = useState<string>("all")

    // Create dialog state
    const [createDialogOpen, setCreateDialogOpen] = useState(false)
    const [createForm, setCreateForm] = useState<CreatePromptForm>(EMPTY_FORM)
    const [creating, setCreating] = useState(false)

    // Fetch analytics
    useEffect(() => {
        const fetchAnalytics = async () => {
            try {
                const res = await apiFetch(`${API_BASE}/prompts/analytics/overview`)
                if (res.ok) {
                    const data = await res.json()
                    setAnalytics(data)
                }
            } catch (error) {
                console.error("Failed to fetch analytics:", error)
            }
        }
        fetchAnalytics()
    }, [])

    // Fetch prompts with filters
    const fetchPrompts = useCallback(async () => {
        setLoading(true)
        try {
            const params = new URLSearchParams()
            params.set("skip", "0")
            params.set("limit", "200")
            if (searchQuery) params.set("search", searchQuery)
            if (categoryFilter !== "all") params.set("category", categoryFilter)
            if (providerFilter !== "all") params.set("provider", providerFilter)
            if (statusFilter === "active") params.set("is_active", "true")
            if (statusFilter === "inactive") params.set("is_active", "false")

            const url = `${API_BASE}/prompts/?${params.toString()}`
            console.log("[prompts] fetching:", url)
            const res = await apiFetch(url)
            console.log("[prompts] response:", res.status, res.statusText, "ok:", res.ok)
            if (res.ok) {
                const raw = await res.text()
                console.log("[prompts] raw response length:", raw.length, "preview:", raw.slice(0, 200))
                try {
                    const data: PromptsResponse = JSON.parse(raw)
                    console.log("[prompts] parsed - total:", data.total, "items:", data.items?.length)
                    setPrompts(data.items ?? [])
                    setTotal(data.total ?? 0)
                    setFetchError(null)
                } catch (parseErr) {
                    console.error("[prompts] JSON parse error:", parseErr)
                    setFetchError(`JSON parse error: ${parseErr}`)
                }
            } else {
                const body = await res.text()
                console.error("[prompts] fetch failed:", res.status, res.statusText, body)
                setFetchError(`API returned ${res.status}: ${body.slice(0, 200)}`)
            }
        } catch (error) {
            console.error("[prompts] fetch exception:", error)
            setFetchError(`Fetch exception: ${error}`)
        } finally {
            setLoading(false)
        }
    }, [searchQuery, categoryFilter, providerFilter, statusFilter])

    useEffect(() => {
        fetchPrompts()
    }, [fetchPrompts])

    // Create prompt handler
    const handleCreate = async () => {
        if (!createForm.slug || !createForm.name || !createForm.content) return
        setCreating(true)
        try {
            const body: Record<string, unknown> = {
                slug: createForm.slug,
                name: createForm.name,
                content: createForm.content,
            }
            if (createForm.description) body.description = createForm.description
            if (createForm.category) body.category = createForm.category
            if (createForm.provider) body.provider = createForm.provider
            if (createForm.model) body.model = createForm.model
            if (createForm.tags) {
                body.tags = createForm.tags
                    .split(",")
                    .map((t) => t.trim())
                    .filter(Boolean)
            }
            if (createForm.change_summary) body.change_summary = createForm.change_summary

            const res = await apiFetch(`${API_BASE}/prompts/`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            })
            if (res.ok) {
                setCreateDialogOpen(false)
                setCreateForm(EMPTY_FORM)
                fetchPrompts()
                // Refresh analytics
                const analyticsRes = await apiFetch(`${API_BASE}/prompts/analytics/overview`)
                if (analyticsRes.ok) {
                    setAnalytics(await analyticsRes.json())
                }
            }
        } catch (error) {
            console.error("Failed to create prompt:", error)
        } finally {
            setCreating(false)
        }
    }

    // Debounced search
    const [searchInput, setSearchInput] = useState("")
    useEffect(() => {
        const timeout = setTimeout(() => {
            setSearchQuery(searchInput)
        }, 300)
        return () => clearTimeout(timeout)
    }, [searchInput])

    if (loading && prompts.length === 0) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            {/* Debug banner — remove once prompts rendering is confirmed */}
            {fetchError && (
                <div className="rounded-md border border-red-500/50 bg-red-500/10 p-4 text-sm text-red-700 dark:text-red-400">
                    <strong>Prompts fetch error:</strong> {fetchError}
                </div>
            )}

            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">AI Prompt Registry</h1>
                    <p className="text-muted-foreground mt-1">
                        Manage, version, and organize prompts across agents and providers.
                    </p>
                </div>
                <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
                    <DialogTrigger asChild>
                        <Button>
                            <Plus className="h-4 w-4 mr-2" />
                            New Prompt
                        </Button>
                    </DialogTrigger>
                    <DialogContent className="sm:max-w-[600px] max-h-[90vh] overflow-y-auto">
                        <DialogHeader>
                            <DialogTitle>Create New Prompt</DialogTitle>
                            <DialogDescription>
                                Add a new prompt to the registry. It will be created as version 1.
                            </DialogDescription>
                        </DialogHeader>
                        <div className="grid gap-4 py-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <Label htmlFor="create-slug">Slug *</Label>
                                    <Input
                                        id="create-slug"
                                        placeholder="my-prompt-slug"
                                        value={createForm.slug}
                                        onChange={(e) =>
                                            setCreateForm({ ...createForm, slug: e.target.value })
                                        }
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="create-name">Name *</Label>
                                    <Input
                                        id="create-name"
                                        placeholder="My Prompt"
                                        value={createForm.name}
                                        onChange={(e) =>
                                            setCreateForm({ ...createForm, name: e.target.value })
                                        }
                                    />
                                </div>
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="create-description">Description</Label>
                                <Input
                                    id="create-description"
                                    placeholder="Brief description of this prompt"
                                    value={createForm.description}
                                    onChange={(e) =>
                                        setCreateForm({ ...createForm, description: e.target.value })
                                    }
                                />
                            </div>
                            <div className="grid grid-cols-3 gap-4">
                                <div className="space-y-2">
                                    <Label>Category</Label>
                                    <Select
                                        value={createForm.category}
                                        onValueChange={(val) =>
                                            setCreateForm({ ...createForm, category: val })
                                        }
                                    >
                                        <SelectTrigger>
                                            <SelectValue placeholder="Select..." />
                                        </SelectTrigger>
                                        <SelectContent>
                                            {CATEGORIES.map((cat) => (
                                                <SelectItem key={cat} value={cat}>
                                                    {cat}
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>
                                </div>
                                <div className="space-y-2">
                                    <Label>Provider</Label>
                                    <Select
                                        value={createForm.provider}
                                        onValueChange={(val) =>
                                            setCreateForm({ ...createForm, provider: val })
                                        }
                                    >
                                        <SelectTrigger>
                                            <SelectValue placeholder="Select..." />
                                        </SelectTrigger>
                                        <SelectContent>
                                            {PROVIDERS.map((prov) => (
                                                <SelectItem key={prov} value={prov}>
                                                    {prov}
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="create-model">Model</Label>
                                    <Input
                                        id="create-model"
                                        placeholder="e.g. claude-3-opus"
                                        value={createForm.model}
                                        onChange={(e) =>
                                            setCreateForm({ ...createForm, model: e.target.value })
                                        }
                                    />
                                </div>
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="create-content">Content *</Label>
                                <Textarea
                                    id="create-content"
                                    placeholder="Enter the prompt content..."
                                    rows={6}
                                    value={createForm.content}
                                    onChange={(e) =>
                                        setCreateForm({ ...createForm, content: e.target.value })
                                    }
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="create-tags">
                                    <span className="flex items-center gap-1.5">
                                        <Tag className="h-3.5 w-3.5" />
                                        Tags
                                    </span>
                                </Label>
                                <Input
                                    id="create-tags"
                                    placeholder="Comma-separated, e.g. security, analysis, code-review"
                                    value={createForm.tags}
                                    onChange={(e) =>
                                        setCreateForm({ ...createForm, tags: e.target.value })
                                    }
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="create-change-summary">Change Summary</Label>
                                <Input
                                    id="create-change-summary"
                                    placeholder="Initial version"
                                    value={createForm.change_summary}
                                    onChange={(e) =>
                                        setCreateForm({
                                            ...createForm,
                                            change_summary: e.target.value,
                                        })
                                    }
                                />
                            </div>
                        </div>
                        <DialogFooter>
                            <Button
                                variant="outline"
                                onClick={() => {
                                    setCreateDialogOpen(false)
                                    setCreateForm(EMPTY_FORM)
                                }}
                            >
                                Cancel
                            </Button>
                            <Button
                                onClick={handleCreate}
                                disabled={
                                    creating || !createForm.slug || !createForm.name || !createForm.content
                                }
                            >
                                {creating && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                                Create Prompt
                            </Button>
                        </DialogFooter>
                    </DialogContent>
                </Dialog>
            </div>

            {/* Stats Cards */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Prompts</CardTitle>
                        <FileText className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {analytics?.total_prompts ?? total}
                        </div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Active</CardTitle>
                        <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {analytics?.active_prompts ?? "--"}
                        </div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Versions</CardTitle>
                        <Layers className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {analytics?.total_versions ?? "--"}
                        </div>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Agents</CardTitle>
                        <Bot className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {analytics?.total_agents ?? "--"}
                        </div>
                    </CardContent>
                </Card>
            </div>

            {/* Filter Bar */}
            <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-[200px] max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                        placeholder="Search prompts..."
                        value={searchInput}
                        onChange={(e) => setSearchInput(e.target.value)}
                        className="pl-9"
                    />
                    {searchInput && (
                        <button
                            onClick={() => setSearchInput("")}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                        >
                            <X className="h-4 w-4" />
                        </button>
                    )}
                </div>
                <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                    <SelectTrigger className="w-[150px]">
                        <SelectValue placeholder="Category" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Categories</SelectItem>
                        {CATEGORIES.map((cat) => (
                            <SelectItem key={cat} value={cat}>
                                {cat}
                            </SelectItem>
                        ))}
                    </SelectContent>
                </Select>
                <Select value={providerFilter} onValueChange={setProviderFilter}>
                    <SelectTrigger className="w-[150px]">
                        <SelectValue placeholder="Provider" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Providers</SelectItem>
                        {PROVIDERS.map((prov) => (
                            <SelectItem key={prov} value={prov}>
                                {prov}
                            </SelectItem>
                        ))}
                    </SelectContent>
                </Select>
                <div className="flex items-center rounded-lg border bg-background p-1 gap-0.5">
                    {(["all", "active", "inactive"] as const).map((status) => (
                        <button
                            key={status}
                            onClick={() => setStatusFilter(status)}
                            className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                                statusFilter === status
                                    ? "bg-primary text-primary-foreground shadow-sm"
                                    : "text-muted-foreground hover:text-foreground hover:bg-muted"
                            }`}
                        >
                            {status.charAt(0).toUpperCase() + status.slice(1)}
                        </button>
                    ))}
                </div>
                {(searchInput || categoryFilter !== "all" || providerFilter !== "all" || statusFilter !== "all") && (
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                            setSearchInput("")
                            setCategoryFilter("all")
                            setProviderFilter("all")
                            setStatusFilter("all")
                        }}
                    >
                        <X className="h-4 w-4 mr-1" />
                        Clear filters
                    </Button>
                )}
            </div>

            {/* Results count */}
            <div className="text-sm text-muted-foreground">
                Showing {prompts.length} of {total} prompt{total !== 1 ? "s" : ""}
                {loading && <Loader2 className="inline h-3 w-3 ml-2 animate-spin" />}
            </div>

            {/* Data Table */}
            <DataTable
                columns={columns}
                data={prompts}
                searchKey="name"
                tableId="prompts"
                initialPageSize={20}
            />
        </div>
    )
}
