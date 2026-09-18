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
import { PageHeader, PageShell } from "@/components/ui/page-header"

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

interface OrgScanRun {
    status: string
    mode: string
    scan_type: string
    repos: string[] | null
    repos_total: number | null
    repos_completed: number
    // null when a whole-org scan is running: that is one scanner process whose
    // per-repository progress goes to its log, so there is no percentage to
    // show. An indeterminate bar is honest; a made-up number is not.
    progress: number | null
    started_at: string
    finished_at: string | null
    elapsed_seconds: number
    returncode: number | null
    error: string | null
    log_path: string
}

interface ScanStatus {
    organization: string
    scan_status: string | null
    last_scan_at: string | null
    total_repos: number
    total_findings: number
    // True when the row said "scanning" but the API no longer had the process.
    stale?: boolean
    run?: OrgScanRun
}

// scan_status values the backend writes. "scanning" is the only live one --
// this page used to test for "running"/"pending", which never appear, so it
// stopped polling on the first tick and cleared the spinner immediately.
const LIVE_SCAN_STATUSES = ["scanning", "queued"]

// The column stores agent states, not sentences. "idle" after a scan means it
// finished, which is not what the word says to an operator reading the card.
const SCAN_STATUS_LABELS: Record<string, string> = {
    idle: "Completed",
    scanning: "Scanning",
    queued: "Queued",
    error: "Failed",
    cancelled: "Cancelled",
    syncing: "Syncing",
}

function formatElapsed(seconds: number): string {
    const h = Math.floor(seconds / 3600)
    const m = Math.floor((seconds % 3600) / 60)
    const s = seconds % 60
    if (h > 0) return `${h}h ${m}m`
    if (m > 0) return `${m}m ${s}s`
    return `${s}s`
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
    const [scanStopping, setScanStopping] = useState(false)
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
                // The import succeeded either way; a scan that could not be
                // queued is reported rather than hidden behind a green toast.
                toast({
                    title: `Repository ${data.action}`,
                    description: data.scan_error
                        ? `${repoName} ${data.action}, but the scan could not be queued: ${data.scan_error}`
                        : `${repoName} ${data.action} successfully${data.scan_started ? " — scan started" : ""}`,
                    variant: data.scan_error ? "destructive" : undefined,
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
                const run: OrgScanRun = await res.json()
                toast({
                    title: "Scan Started",
                    description: run.mode === "local"
                        ? `Full scan running inside the API container for ${selectedOrg}. Only the scanners installed there will run.`
                        : `Full scan initiated for ${selectedOrg}`,
                })
                pollScanStatus()
            } else {
                const err = await res.json()
                if (res.status === 409) {
                    // Already running -- not a failure, just show the live one.
                    toast({ title: "Scan Already Running", description: err.detail })
                    pollScanStatus()
                    return
                }
                toast({ title: "Scan Failed", description: err.detail || "Unknown error", variant: "destructive" })
                setScanRunning(false)
            }
        } catch {
            toast({ title: "Scan Failed", description: "Connection error", variant: "destructive" })
            setScanRunning(false)
        }
    }

    const handleStopScan = async () => {
        if (!selectedOrg) return
        setScanStopping(true)
        try {
            const res = await apiFetch(`${API_BASE}/organizations/${selectedOrg}/scan`, {
                method: "DELETE",
            })
            if (res.ok) {
                toast({
                    title: "Scan Stopped",
                    description: "Repositories already scanned keep their results; the rest were not scanned.",
                })
            } else {
                const err = await res.json()
                toast({ title: "Stop Failed", description: err.detail || "Unknown error", variant: "destructive" })
            }
        } catch {
            toast({ title: "Stop Failed", description: "Connection error", variant: "destructive" })
        } finally {
            setScanStopping(false)
            pollScanStatus()
        }
    }

    const pollScanStatus = useCallback(async () => {
        if (!selectedOrg) return
        try {
            const res = await apiFetch(`${API_BASE}/organizations/${selectedOrg}/scan/status`)
            if (res.ok) {
                const data: ScanStatus = await res.json()
                setScanStatus(data)
                const live = LIVE_SCAN_STATUSES.includes(data.scan_status ?? "")
                setScanRunning(live)
                if (live) {
                    setTimeout(pollScanStatus, 5000)
                } else {
                    // Totals move as the scan ingests; pick them up at the end.
                    refreshOrgList()
                }
            } else {
                setScanRunning(false)
            }
        } catch {
            setScanRunning(false)
        }
    }, [selectedOrg])

    // Pick up a scan already in flight -- started from another browser tab, or
    // before this page was opened. Without this the button reads "Start Full
    // Scan" while a scan is running, and pressing it returns 409.
    useEffect(() => {
        if (selectedOrg) pollScanStatus()
    }, [selectedOrg, pollScanStatus])

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
        <PageShell>
            <PageHeader
                icon={Building2}
                eyebrow="Administration"
                title="Organizations"
                description="Sync repositories from GitHub and manage scans."
                actions={
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
                }
            />

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
                                    <CheckCircle2 className="h-5 w-5 text-success-text" />
                                ) : (
                                    <AlertTriangle className="h-5 w-5 text-warning-text" />
                                )}
                                <span className="font-medium">{syncResult.message}</span>
                            </div>
                            <div className="flex gap-4 text-sm text-muted-foreground">
                                <span>{syncResult.total} total</span>
                                <span className="text-success-text">{syncResult.created} new</span>
                                <span className="text-info-text">{syncResult.updated} updated</span>
                                {syncResult.failed > 0 && (
                                    <span className="text-danger-text">{syncResult.failed} failed</span>
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
                        <Input aria-label="Search repositories"
                            value={repoSearch}
                            onChange={e => setRepoSearch(e.target.value)}
                            onKeyDown={e => e.key === "Enter" && handleSearchRepos()}
                            placeholder="Search repos (e.g., devops-security-hub-ai)"
                            className="flex-1"
                            disabled={!selectedOrg}
                        />
                        <Button aria-label="Search repositories"
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
                                                        <Globe className="h-3 w-3 text-danger-text" />
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
                    <div className="flex items-center gap-2">
                        <Button
                            onClick={handleStartScan}
                            disabled={scanRunning || !selectedOrg}
                            className="bg-success hover:bg-success"
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

                        {scanRunning && (
                            <Button
                                variant="outline"
                                onClick={handleStopScan}
                                disabled={scanStopping}
                            >
                                {scanStopping ? (
                                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                ) : (
                                    <XCircle className="h-4 w-4 mr-2" />
                                )}
                                Stop
                            </Button>
                        )}
                    </div>

                    {scanStatus && (
                        <div className="p-4 rounded-lg border bg-muted/50 space-y-2">
                            <div className="flex items-center gap-2">
                                {scanStatus.scan_status === "idle" ? (
                                    <CheckCircle2 className="h-5 w-5 text-success-text" />
                                ) : scanStatus.scan_status === "error" ? (
                                    <XCircle className="h-5 w-5 text-danger-text" />
                                ) : scanStatus.scan_status === "cancelled" ? (
                                    <AlertTriangle className="h-5 w-5 text-warning-text" />
                                ) : (
                                    <Loader2 className="h-5 w-5 animate-spin text-info-text" />
                                )}
                                <span className="font-medium">
                                    {SCAN_STATUS_LABELS[scanStatus.scan_status ?? ""] ?? "Unknown"}
                                </span>
                                {scanStatus.run && scanStatus.run.status === "scanning" && (
                                    <span className="text-xs text-muted-foreground">
                                        {formatElapsed(scanStatus.run.elapsed_seconds)} elapsed
                                        {scanStatus.run.progress !== null &&
                                            ` — ${scanStatus.run.repos_completed}/${scanStatus.run.repos_total} repos`}
                                    </span>
                                )}
                            </div>

                            {scanStatus.stale && (
                                <p className="text-xs text-danger-text">
                                    The API restarted while this scan was running, so the scanner was
                                    killed with it. Nothing was ingested from the repositories it had
                                    not finished. Start the scan again.
                                </p>
                            )}

                            {scanStatus.run?.mode === "local" && (
                                <p className="text-xs text-warning-text">
                                    Running inside the API container, which has only some of the
                                    scanners installed. Install the docker package and rebuild the API
                                    image to run scans in the scanner container instead.
                                </p>
                            )}

                            {scanStatus.run?.error && (
                                <p className="text-xs text-danger-text break-all">
                                    {scanStatus.run.error}
                                </p>
                            )}

                            {scanStatus.run && (
                                <p className="text-xs text-muted-foreground break-all">
                                    Log: {scanStatus.run.log_path}
                                </p>
                            )}

                            {scanStatus.last_scan_at && (
                                <p className="text-xs text-muted-foreground">
                                    Last scan: {new Date(scanStatus.last_scan_at).toLocaleString()}
                                </p>
                            )}
                        </div>
                    )}
                </CardContent>
            </Card>
        </PageShell>
    )
}
