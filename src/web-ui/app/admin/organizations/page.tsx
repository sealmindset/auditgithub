"use client"

import { useState, useEffect, useCallback } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
    Building2, RefreshCw, Search, Plus, Play, Loader2, CheckCircle2,
    XCircle, GitBranch, Globe, EyeOff, Archive, AlertTriangle, Download
} from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { API_BASE, apiFetch } from "@/lib/api"

interface Organization {
    id: string
    name: string
    display_name: string | null
    github_org: string
    is_default: boolean
    is_active: boolean
    total_repos: number
    total_findings: number
}

interface GitHubRepoResult {
    name: string
    full_name: string
    description: string | null
    language: string | null
    visibility: string | null
    is_archived: boolean
    updated_at: string | null
    already_imported: boolean
}

interface ImportResult {
    success: boolean
    message: string
    total: number
    created: number
    updated: number
    failed: number
}

interface ScanStatus {
    organization: string
    scan_status: string | null
    last_scan_at: string | null
    total_repos: number
    total_findings: number
}

export default function OrganizationsAdminPage() {
    const [organizations, setOrganizations] = useState<Organization[]>([])
    const [selectedOrg, setSelectedOrg] = useState<string>("")
    const [loading, setLoading] = useState(true)

    const [syncing, setSyncing] = useState(false)
    const [syncResult, setSyncResult] = useState<ImportResult | null>(null)

    const [repoSearch, setRepoSearch] = useState("")
    const [searchResults, setSearchResults] = useState<GitHubRepoResult[]>([])
    const [searchTotal, setSearchTotal] = useState(0)
    const [searching, setSearching] = useState(false)
    const [importingRepo, setImportingRepo] = useState<string | null>(null)
    const [autoScanOnImport, setAutoScanOnImport] = useState(false)

    const [scanRunning, setScanRunning] = useState(false)
    const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null)
    const [autoScanAfterSync, setAutoScanAfterSync] = useState(false)

    const { toast } = useToast()

    const currentOrg = organizations.find(o => o.name === selectedOrg)

    useEffect(() => {
        const fetchOrgs = async () => {
            try {
                const res = await apiFetch(`${API_BASE}/organizations/`)
                if (res.ok) {
                    const orgs: Organization[] = await res.json()
                    setOrganizations(orgs)
                    const defaultOrg = orgs.find(o => o.is_default) || orgs[0]
                    if (defaultOrg) setSelectedOrg(defaultOrg.name)
                }
            } catch (error) {
                console.error("Failed to fetch organizations:", error)
            } finally {
                setLoading(false)
            }
        }
        fetchOrgs()
    }, [])

    const handleOrgChange = (orgName: string) => {
        setSelectedOrg(orgName)
        setSyncResult(null)
        setSearchResults([])
        setRepoSearch("")
        setScanStatus(null)
    }

    const handleFullSync = async () => {
        if (!selectedOrg) return
        setSyncing(true)
        setSyncResult(null)
        try {
            const res = await apiFetch(`${API_BASE}/organizations/${selectedOrg}/import?confirm=true`, {
                method: "POST",
            })
            if (res.ok) {
                const data: ImportResult = await res.json()
                setSyncResult(data)
                toast({
                    title: "Sync Complete",
                    description: `${data.created} new, ${data.updated} updated, ${data.failed} failed out of ${data.total} repos`,
                })
                refreshOrgList()

                if (autoScanAfterSync && data.created > 0) {
                    handleStartScan()
                }
            } else {
                const err = await res.json()
                toast({ title: "Sync Failed", description: err.detail || "Unknown error", variant: "destructive" })
            }
        } catch (error) {
            toast({ title: "Sync Failed", description: "Connection error", variant: "destructive" })
        } finally {
            setSyncing(false)
        }
    }

    const handleSearchRepos = useCallback(async () => {
        if (!selectedOrg || repoSearch.length < 2) return
        setSearching(true)
        try {
            const params = new URLSearchParams({ q: repoSearch })
            const res = await apiFetch(`${API_BASE}/organizations/${selectedOrg}/search-github-repos?${params}`)
            if (res.ok) {
                const data = await res.json()
                setSearchResults(data.results || [])
                setSearchTotal(data.total || 0)
            } else {
                const err = await res.json()
                toast({ title: "Search Failed", description: err.detail || "Unknown error", variant: "destructive" })
            }
        } catch {
            toast({ title: "Search Failed", description: "Connection error", variant: "destructive" })
        } finally {
            setSearching(false)
        }
    }, [selectedOrg, repoSearch, toast])

    const handleImportRepo = async (repoName: string) => {
        if (!selectedOrg) return
        setImportingRepo(repoName)
        try {
            const res = await apiFetch(`${API_BASE}/organizations/${selectedOrg}/import-repo`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ repo_name: repoName, auto_scan: autoScanOnImport }),
            })
            if (res.ok) {
                const data = await res.json()
                toast({
                    title: `Repository ${data.action}`,
                    description: `${repoName} ${data.action} successfully${data.scan_started ? " — scan started" : ""}`,
                })
                setSearchResults(prev =>
                    prev.map(r => r.name === repoName ? { ...r, already_imported: true } : r)
                )
                refreshOrgList()
            } else {
                const err = await res.json()
                toast({ title: "Import Failed", description: err.detail || "Unknown error", variant: "destructive" })
            }
        } catch {
            toast({ title: "Import Failed", description: "Connection error", variant: "destructive" })
        } finally {
            setImportingRepo(null)
        }
    }

    const handleStartScan = async () => {
        if (!selectedOrg) return
        setScanRunning(true)
        try {
            const res = await apiFetch(`${API_BASE}/organizations/${selectedOrg}/scan?scan_type=full`, {
                method: "POST",
            })
            if (res.ok) {
                toast({ title: "Scan Started", description: `Full scan initiated for ${selectedOrg}` })
                pollScanStatus()
            } else {
                const err = await res.json()
                toast({ title: "Scan Failed", description: err.detail || "Unknown error", variant: "destructive" })
                setScanRunning(false)
            }
        } catch {
            toast({ title: "Scan Failed", description: "Connection error", variant: "destructive" })
            setScanRunning(false)
        }
    }

    const pollScanStatus = useCallback(async () => {
        if (!selectedOrg) return
        try {
            const res = await apiFetch(`${API_BASE}/organizations/${selectedOrg}/scan/status`)
            if (res.ok) {
                const data: ScanStatus = await res.json()
                setScanStatus(data)
                if (data.scan_status === "running" || data.scan_status === "pending") {
                    setTimeout(pollScanStatus, 5000)
                } else {
                    setScanRunning(false)
                }
            }
        } catch {
            setScanRunning(false)
        }
    }, [selectedOrg])

    const refreshOrgList = async () => {
        try {
            const res = await apiFetch(`${API_BASE}/organizations/`)
            if (res.ok) {
                const orgs: Organization[] = await res.json()
                setOrganizations(orgs)
            }
        } catch {}
    }

    if (loading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    return (
        <div className="container mx-auto py-8 px-4 space-y-6">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
                        <Building2 className="h-8 w-8" />
                        Organizations
                    </h1>
                    <p className="text-muted-foreground mt-1">
                        Sync repositories from GitHub and manage scans
                    </p>
                </div>
                <Select value={selectedOrg} onValueChange={handleOrgChange}>
                    <SelectTrigger className="w-[300px]">
                        <div className="flex items-center gap-2">
                            <Building2 className="h-4 w-4 text-muted-foreground" />
                            <SelectValue placeholder="Select organization" />
                        </div>
                    </SelectTrigger>
                    <SelectContent>
                        {organizations.map(org => (
                            <SelectItem key={org.name} value={org.name}>
                                <div className="flex items-center gap-3">
                                    <span>{org.display_name || org.github_org}</span>
                                    <span className="text-xs text-muted-foreground">
                                        {org.total_repos.toLocaleString()} repos
                                    </span>
                                    {org.is_default && (
                                        <Badge variant="secondary" className="text-[10px] px-1 py-0">default</Badge>
                                    )}
                                </div>
                            </SelectItem>
                        ))}
                    </SelectContent>
                </Select>
            </div>

            {currentOrg && (
                <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                        <CardHeader className="pb-2">
                            <CardDescription>Repositories</CardDescription>
                            <CardTitle className="text-2xl">{currentOrg.total_repos.toLocaleString()}</CardTitle>
                        </CardHeader>
                    </Card>
                    <Card>
                        <CardHeader className="pb-2">
                            <CardDescription>Findings</CardDescription>
                            <CardTitle className="text-2xl">{currentOrg.total_findings.toLocaleString()}</CardTitle>
                        </CardHeader>
                    </Card>
                    <Card>
                        <CardHeader className="pb-2">
                            <CardDescription>GitHub Org</CardDescription>
                            <CardTitle className="text-2xl">{currentOrg.github_org}</CardTitle>
                        </CardHeader>
                    </Card>
                </div>
            )}

            {/* Full Sync Card */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <RefreshCw className="h-5 w-5" />
                        Full Repository Sync
                    </CardTitle>
                    <CardDescription>
                        Import all repositories from GitHub. New repos are created, existing repos are updated with latest metadata.
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex items-center gap-6">
                        <div className="flex items-center gap-2">
                            <Switch
                                id="auto-scan-sync"
                                checked={autoScanAfterSync}
                                onCheckedChange={setAutoScanAfterSync}
                            />
                            <Label htmlFor="auto-scan-sync" className="text-sm">
                                Auto-scan new repos after sync
                            </Label>
                        </div>
                        <Button onClick={handleFullSync} disabled={syncing || !selectedOrg}>
                            {syncing ? (
                                <>
                                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                    Syncing...
                                </>
                            ) : (
                                <>
                                    <Download className="h-4 w-4 mr-2" />
                                    Sync All Repos
                                </>
                            )}
                        </Button>
                    </div>

                    {syncResult && (
                        <div className="p-4 rounded-lg border bg-muted/50 space-y-2">
                            <div className="flex items-center gap-2">
                                {syncResult.failed === 0 ? (
                                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                                ) : (
                                    <AlertTriangle className="h-5 w-5 text-yellow-500" />
                                )}
                                <span className="font-medium">{syncResult.message}</span>
                            </div>
                            <div className="flex gap-4 text-sm text-muted-foreground">
                                <span>{syncResult.total} total</span>
                                <span className="text-green-600">{syncResult.created} new</span>
                                <span className="text-blue-600">{syncResult.updated} updated</span>
                                {syncResult.failed > 0 && (
                                    <span className="text-red-600">{syncResult.failed} failed</span>
                                )}
                            </div>
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Single Repo Import Card */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Search className="h-5 w-5" />
                        Add Individual Repository
                    </CardTitle>
                    <CardDescription>
                        Search for a specific repository on GitHub and import it
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex gap-2">
                        <Input
                            value={repoSearch}
                            onChange={e => setRepoSearch(e.target.value)}
                            onKeyDown={e => e.key === "Enter" && handleSearchRepos()}
                            placeholder="Search repos (e.g., devops-security-hub-ai)"
                            className="flex-1"
                            disabled={!selectedOrg}
                        />
                        <Button
                            onClick={handleSearchRepos}
                            disabled={searching || !selectedOrg || repoSearch.length < 2}
                            variant="secondary"
                        >
                            {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                        </Button>
                    </div>

                    <div className="flex items-center gap-2">
                        <Switch
                            id="auto-scan-import"
                            checked={autoScanOnImport}
                            onCheckedChange={setAutoScanOnImport}
                        />
                        <Label htmlFor="auto-scan-import" className="text-sm">
                            Auto-scan after import
                        </Label>
                    </div>

                    {searchResults.length > 0 && (
                        <div className="space-y-1">
                            <p className="text-xs text-muted-foreground">
                                {searchTotal} results on GitHub
                            </p>
                            <ScrollArea className="max-h-[400px]">
                                <div className="space-y-2">
                                    {searchResults.map(repo => (
                                        <div
                                            key={repo.name}
                                            className="flex items-center justify-between p-3 rounded-md border hover:bg-accent/50"
                                        >
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2">
                                                    <GitBranch className="h-4 w-4 text-muted-foreground shrink-0" />
                                                    <span className="font-medium truncate">{repo.name}</span>
                                                    {repo.language && (
                                                        <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                                                            {repo.language}
                                                        </Badge>
                                                    )}
                                                    {repo.visibility === "private" ? (
                                                        <EyeOff className="h-3 w-3 text-muted-foreground" />
                                                    ) : repo.visibility === "public" ? (
                                                        <Globe className="h-3 w-3 text-red-500" />
                                                    ) : null}
                                                    {repo.is_archived && (
                                                        <Archive className="h-3 w-3 text-muted-foreground" />
                                                    )}
                                                </div>
                                                {repo.description && (
                                                    <p className="text-xs text-muted-foreground mt-0.5 truncate">
                                                        {repo.description}
                                                    </p>
                                                )}
                                            </div>
                                            <div className="ml-3 shrink-0">
                                                {repo.already_imported ? (
                                                    <Badge variant="secondary" className="text-xs">
                                                        <CheckCircle2 className="h-3 w-3 mr-1" />
                                                        Imported
                                                    </Badge>
                                                ) : (
                                                    <Button
                                                        size="sm"
                                                        onClick={() => handleImportRepo(repo.name)}
                                                        disabled={importingRepo === repo.name}
                                                    >
                                                        {importingRepo === repo.name ? (
                                                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                                        ) : (
                                                            <>
                                                                <Plus className="h-3.5 w-3.5 mr-1" />
                                                                Import
                                                            </>
                                                        )}
                                                    </Button>
                                                )}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </ScrollArea>
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Scan Card */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Play className="h-5 w-5" />
                        Security Scan
                    </CardTitle>
                    <CardDescription>
                        Run a full security scan across all repositories in this organization
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <Button
                        onClick={handleStartScan}
                        disabled={scanRunning || !selectedOrg}
                        className="bg-green-600 hover:bg-green-700"
                    >
                        {scanRunning ? (
                            <>
                                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                Scanning...
                            </>
                        ) : (
                            <>
                                <Play className="h-4 w-4 mr-2" />
                                Start Full Scan
                            </>
                        )}
                    </Button>

                    {scanStatus && (
                        <div className="p-4 rounded-lg border bg-muted/50 space-y-2">
                            <div className="flex items-center gap-2">
                                {scanStatus.scan_status === "completed" ? (
                                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                                ) : scanStatus.scan_status === "failed" ? (
                                    <XCircle className="h-5 w-5 text-red-500" />
                                ) : (
                                    <Loader2 className="h-5 w-5 animate-spin text-blue-500" />
                                )}
                                <span className="font-medium capitalize">
                                    {scanStatus.scan_status || "Unknown"}
                                </span>
                            </div>
                            {scanStatus.last_scan_at && (
                                <p className="text-xs text-muted-foreground">
                                    Last scan: {new Date(scanStatus.last_scan_at).toLocaleString()}
                                </p>
                            )}
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    )
}
