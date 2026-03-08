"use client"

import { useEffect, useState, useCallback } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
    Loader2,
    Save,
    Sparkles,
    Check,
    X,
    ExternalLink,
    Server,
    Shield,
    Users,
    Activity,
    Clock,
    Plus,
    Trash2,
    RefreshCw,
} from "lucide-react"
import { API_BASE, apiFetch } from "@/lib/api"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface EnvironmentUrl {
    name: string
    url: string
    is_primary: boolean
}

interface DiscoverySuggestion {
    field: string
    value: string
    confidence: number
    evidence: string
    accepted: boolean | null
}

interface OperationsData {
    id: string | null
    repository_id: string
    deployment_status: string | null
    deployment_status_notes: string | null
    environment_urls: EnvironmentUrl[]
    hosting_platform: string | null
    hosting_detail: string | null
    deployment_method: string | null
    deployment_method_detail: string | null
    team_owner: string | null
    team_contact_email: string | null
    team_slack_channel: string | null
    business_criticality: string | null
    business_criticality_notes: string | null
    compliance_frameworks: string[]
    data_classification: string | null
    regulatory_notes: string | null
    last_compliance_audit_at: string | null
    cicd_platform: string | null
    cicd_pipeline_url: string | null
    container_registry: string | null
    iac_type: string | null
    iac_path: string | null
    monitoring_url: string | null
    alerting_url: string | null
    logging_url: string | null
    last_discovery_at: string | null
    last_discovery_status: string | null
    discovery_confidence: number | null
    custom_metadata: Record<string, string> | null
    notes: string | null
    created_at: string | null
    updated_at: string | null
}

interface DiscoveryRun {
    id: string
    repository_id: string
    status: string
    started_at: string | null
    completed_at: string | null
    suggestions: DiscoverySuggestion[]
    evidence_files: string[]
    triggered_by: string | null
    error_message: string | null
    tokens_used: number | null
    created_at: string | null
}

interface OperationsViewProps {
    projectId: string
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DEPLOYMENT_STATUSES = [
    { value: "production", label: "Production", color: "bg-green-500" },
    { value: "staging", label: "Staging", color: "bg-blue-500" },
    { value: "development", label: "Development", color: "bg-yellow-500" },
    { value: "deprecated", label: "Deprecated", color: "bg-orange-500" },
    { value: "archived", label: "Archived", color: "bg-gray-500" },
    { value: "decommissioned", label: "Decommissioned", color: "bg-red-500" },
    { value: "unknown", label: "Unknown", color: "bg-gray-400" },
]

const HOSTING_PLATFORMS = [
    "aws", "azure", "gcp", "on-prem", "hybrid", "heroku", "vercel", "netlify", "other",
]

const DEPLOYMENT_METHODS = [
    "kubernetes", "ecs", "lambda", "vm", "container", "serverless", "static", "other",
]

const CICD_PLATFORMS = [
    "github-actions", "jenkins", "gitlab-ci", "azure-devops", "circleci", "other",
]

const IAC_TYPES = [
    "terraform", "bicep", "cloudformation", "pulumi", "ansible", "none", "other",
]

const CRITICALITY_LEVELS = [
    { value: "critical", label: "Critical", color: "bg-red-500" },
    { value: "high", label: "High", color: "bg-orange-500" },
    { value: "medium", label: "Medium", color: "bg-yellow-500" },
    { value: "low", label: "Low", color: "bg-blue-500" },
]

const DATA_CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"]

function DeploymentStatusBadge({ status }: { status: string | null }) {
    const found = DEPLOYMENT_STATUSES.find(s => s.value === status)
    if (!found) {
        return <Badge variant="secondary">Unknown</Badge>
    }
    return <Badge className={`${found.color} text-white`}>{found.label}</Badge>
}

function ConfidenceBadge({ confidence }: { confidence: number }) {
    const pct = Math.round(confidence * 100)
    const color = pct >= 80 ? "bg-green-500" : pct >= 50 ? "bg-yellow-500" : "bg-orange-500"
    return <Badge className={`${color} text-white text-xs`}>{pct}%</Badge>
}

function fieldLabel(field: string): string {
    return field
        .replace(/_/g, " ")
        .replace(/\b\w/g, c => c.toUpperCase())
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export function OperationsView({ projectId }: OperationsViewProps) {
    const [ops, setOps] = useState<OperationsData | null>(null)
    const [loading, setLoading] = useState(true)
    const [saving, setSaving] = useState(false)
    const [dirty, setDirty] = useState(false)

    // Discovery
    const [discoveries, setDiscoveries] = useState<DiscoveryRun[]>([])
    const [discovering, setDiscovering] = useState(false)
    const [latestDiscovery, setLatestDiscovery] = useState<DiscoveryRun | null>(null)
    const [acceptingIds, setAcceptingIds] = useState<Set<string>>(new Set())

    // Environment URLs editing
    const [envUrls, setEnvUrls] = useState<EnvironmentUrl[]>([])

    // Compliance frameworks editing
    const [frameworks, setFrameworks] = useState<string[]>([])
    const [newFramework, setNewFramework] = useState("")

    // -----------------------------------------------------------------------
    // Data fetching
    // -----------------------------------------------------------------------

    const fetchOps = useCallback(async () => {
        try {
            const res = await apiFetch(`${API_BASE}/projects/${projectId}/operations`)
            if (res.ok) {
                const data = await res.json()
                setOps(data)
                setEnvUrls(data.environment_urls || [])
                setFrameworks(data.compliance_frameworks || [])
            }
        } catch (err) {
            console.error("Failed to fetch operations:", err)
        } finally {
            setLoading(false)
        }
    }, [projectId])

    const fetchDiscoveries = useCallback(async () => {
        try {
            const res = await apiFetch(`${API_BASE}/projects/${projectId}/operations/discoveries`)
            if (res.ok) {
                const data = await res.json()
                setDiscoveries(data)
                if (data.length > 0) {
                    setLatestDiscovery(data[0])
                }
            }
        } catch (err) {
            console.error("Failed to fetch discoveries:", err)
        }
    }, [projectId])

    useEffect(() => {
        fetchOps()
        fetchDiscoveries()
    }, [fetchOps, fetchDiscoveries])

    // -----------------------------------------------------------------------
    // Save
    // -----------------------------------------------------------------------

    const handleSave = async () => {
        if (!ops) return
        setSaving(true)
        try {
            const body = {
                deployment_status: ops.deployment_status,
                deployment_status_notes: ops.deployment_status_notes,
                environment_urls: envUrls,
                hosting_platform: ops.hosting_platform,
                hosting_detail: ops.hosting_detail,
                deployment_method: ops.deployment_method,
                deployment_method_detail: ops.deployment_method_detail,
                team_owner: ops.team_owner,
                team_contact_email: ops.team_contact_email,
                team_slack_channel: ops.team_slack_channel,
                business_criticality: ops.business_criticality,
                business_criticality_notes: ops.business_criticality_notes,
                compliance_frameworks: frameworks,
                data_classification: ops.data_classification,
                regulatory_notes: ops.regulatory_notes,
                cicd_platform: ops.cicd_platform,
                cicd_pipeline_url: ops.cicd_pipeline_url,
                container_registry: ops.container_registry,
                iac_type: ops.iac_type,
                iac_path: ops.iac_path,
                monitoring_url: ops.monitoring_url,
                alerting_url: ops.alerting_url,
                logging_url: ops.logging_url,
                notes: ops.notes,
            }
            const res = await apiFetch(`${API_BASE}/projects/${projectId}/operations`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            })
            if (res.ok) {
                const updated = await res.json()
                setOps(updated)
                setDirty(false)
            }
        } catch (err) {
            console.error("Failed to save operations:", err)
        } finally {
            setSaving(false)
        }
    }

    // -----------------------------------------------------------------------
    // AI Discovery
    // -----------------------------------------------------------------------

    const handleDiscover = async () => {
        setDiscovering(true)
        try {
            const res = await apiFetch(`${API_BASE}/projects/${projectId}/operations/discover`, {
                method: "POST",
            })
            if (res.ok) {
                // Poll for completion
                const run = await res.json()
                pollDiscovery(run.id)
            }
        } catch (err) {
            console.error("Failed to trigger discovery:", err)
            setDiscovering(false)
        }
    }

    const pollDiscovery = async (runId: string) => {
        const maxAttempts = 30
        for (let i = 0; i < maxAttempts; i++) {
            await new Promise(r => setTimeout(r, 2000))
            try {
                const res = await apiFetch(`${API_BASE}/projects/${projectId}/operations/discoveries`)
                if (res.ok) {
                    const runs = await res.json()
                    const run = runs.find((r: DiscoveryRun) => r.id === runId)
                    if (run && (run.status === "completed" || run.status === "failed")) {
                        setDiscoveries(runs)
                        setLatestDiscovery(run)
                        setDiscovering(false)
                        fetchOps()
                        return
                    }
                }
            } catch {
                // continue polling
            }
        }
        setDiscovering(false)
        fetchDiscoveries()
    }

    const handleAcceptSuggestion = async (discoveryId: string, field: string, accepted: boolean, overrideValue?: string) => {
        setAcceptingIds(prev => new Set(prev).add(`${field}-${accepted}`))
        try {
            const res = await apiFetch(
                `${API_BASE}/projects/${projectId}/operations/discoveries/${discoveryId}/accept`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        decisions: [{ field, accepted, override_value: overrideValue || null }],
                    }),
                }
            )
            if (res.ok) {
                fetchOps()
                fetchDiscoveries()
            }
        } catch (err) {
            console.error("Failed to accept suggestion:", err)
        } finally {
            setAcceptingIds(prev => {
                const next = new Set(prev)
                next.delete(`${field}-${accepted}`)
                return next
            })
        }
    }

    // -----------------------------------------------------------------------
    // Field updaters
    // -----------------------------------------------------------------------

    const updateField = (field: string, value: string | null) => {
        if (!ops) return
        setOps({ ...ops, [field]: value })
        setDirty(true)
    }

    const addEnvUrl = () => {
        setEnvUrls([...envUrls, { name: "", url: "", is_primary: false }])
        setDirty(true)
    }

    const updateEnvUrl = (idx: number, field: keyof EnvironmentUrl, value: string | boolean) => {
        const updated = [...envUrls]
        updated[idx] = { ...updated[idx], [field]: value }
        setEnvUrls(updated)
        setDirty(true)
    }

    const removeEnvUrl = (idx: number) => {
        setEnvUrls(envUrls.filter((_, i) => i !== idx))
        setDirty(true)
    }

    const addFramework = () => {
        if (newFramework.trim() && !frameworks.includes(newFramework.trim())) {
            setFrameworks([...frameworks, newFramework.trim()])
            setNewFramework("")
            setDirty(true)
        }
    }

    const removeFramework = (fw: string) => {
        setFrameworks(frameworks.filter(f => f !== fw))
        setDirty(true)
    }

    // -----------------------------------------------------------------------
    // Render
    // -----------------------------------------------------------------------

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        )
    }

    if (!ops) {
        return (
            <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                <Server className="h-12 w-12 mb-4" />
                <p>Unable to load operations data</p>
            </div>
        )
    }

    const pendingSuggestions = latestDiscovery?.suggestions?.filter(s => s.accepted === null) || []

    return (
        <div className="space-y-6">
            {/* Header bar with save + discover */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <DeploymentStatusBadge status={ops.deployment_status} />
                    {ops.updated_at && (
                        <span className="text-xs text-muted-foreground">
                            Last updated {new Date(ops.updated_at).toLocaleDateString()}
                        </span>
                    )}
                </div>
                <div className="flex items-center gap-2">
                    <Button
                        variant="outline"
                        onClick={handleDiscover}
                        disabled={discovering}
                    >
                        {discovering ? (
                            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        ) : (
                            <Sparkles className="h-4 w-4 mr-2" />
                        )}
                        {discovering ? "Discovering..." : "AI Discover"}
                    </Button>
                    <Button onClick={handleSave} disabled={!dirty || saving}>
                        {saving ? (
                            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        ) : (
                            <Save className="h-4 w-4 mr-2" />
                        )}
                        Save
                    </Button>
                </div>
            </div>

            {/* AI Discovery Suggestions */}
            {pendingSuggestions.length > 0 && (
                <Card className="border-purple-200 dark:border-purple-800 bg-gradient-to-r from-purple-50 to-blue-50 dark:from-purple-950 dark:to-blue-950">
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2">
                            <Sparkles className="h-4 w-4 text-purple-500" />
                            AI Discovery Suggestions
                        </CardTitle>
                        <CardDescription>
                            Review and accept or reject AI-discovered operations details
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="grid gap-3">
                            {pendingSuggestions.map((suggestion, idx) => (
                                <div
                                    key={`${suggestion.field}-${idx}`}
                                    className="flex items-start justify-between gap-4 p-3 rounded-lg bg-white dark:bg-gray-900 border"
                                >
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className="text-sm font-medium">
                                                {fieldLabel(suggestion.field)}
                                            </span>
                                            <ConfidenceBadge confidence={suggestion.confidence} />
                                        </div>
                                        <div className="text-sm font-mono text-blue-600 dark:text-blue-400 mb-1">
                                            {suggestion.value}
                                        </div>
                                        <div className="text-xs text-muted-foreground">
                                            {suggestion.evidence}
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-1 flex-shrink-0">
                                        <Button
                                            size="sm"
                                            variant="ghost"
                                            className="h-8 w-8 p-0 text-green-600 hover:text-green-700 hover:bg-green-50"
                                            onClick={() =>
                                                latestDiscovery &&
                                                handleAcceptSuggestion(latestDiscovery.id, suggestion.field, true)
                                            }
                                            disabled={acceptingIds.has(`${suggestion.field}-true`)}
                                        >
                                            {acceptingIds.has(`${suggestion.field}-true`) ? (
                                                <Loader2 className="h-4 w-4 animate-spin" />
                                            ) : (
                                                <Check className="h-4 w-4" />
                                            )}
                                        </Button>
                                        <Button
                                            size="sm"
                                            variant="ghost"
                                            className="h-8 w-8 p-0 text-red-600 hover:text-red-700 hover:bg-red-50"
                                            onClick={() =>
                                                latestDiscovery &&
                                                handleAcceptSuggestion(latestDiscovery.id, suggestion.field, false)
                                            }
                                            disabled={acceptingIds.has(`${suggestion.field}-false`)}
                                        >
                                            {acceptingIds.has(`${suggestion.field}-false`) ? (
                                                <Loader2 className="h-4 w-4 animate-spin" />
                                            ) : (
                                                <X className="h-4 w-4" />
                                            )}
                                        </Button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* Main form sections */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Deployment Status */}
                <Card>
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2">
                            <Activity className="h-4 w-4" />
                            Deployment Status
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label>Status</Label>
                            <Select
                                value={ops.deployment_status || "unknown"}
                                onValueChange={(v) => updateField("deployment_status", v)}
                            >
                                <SelectTrigger>
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    {DEPLOYMENT_STATUSES.map(s => (
                                        <SelectItem key={s.value} value={s.value}>
                                            {s.label}
                                        </SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="space-y-2">
                            <Label>Notes</Label>
                            <Textarea
                                value={ops.deployment_status_notes || ""}
                                onChange={(e) => updateField("deployment_status_notes", e.target.value)}
                                placeholder="Additional deployment notes..."
                                rows={2}
                            />
                        </div>
                    </CardContent>
                </Card>

                {/* Hosting & Platform */}
                <Card>
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2">
                            <Server className="h-4 w-4" />
                            Hosting & Platform
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label>Platform</Label>
                                <Select
                                    value={ops.hosting_platform || ""}
                                    onValueChange={(v) => updateField("hosting_platform", v)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select..." />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {HOSTING_PLATFORMS.map(p => (
                                            <SelectItem key={p} value={p}>
                                                {p.toUpperCase()}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label>Deployment Method</Label>
                                <Select
                                    value={ops.deployment_method || ""}
                                    onValueChange={(v) => updateField("deployment_method", v)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select..." />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {DEPLOYMENT_METHODS.map(m => (
                                            <SelectItem key={m} value={m}>
                                                {m}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                        </div>
                        <div className="space-y-2">
                            <Label>Hosting Detail</Label>
                            <Input
                                value={ops.hosting_detail || ""}
                                onChange={(e) => updateField("hosting_detail", e.target.value)}
                                placeholder="e.g. AWS ECS Fargate in us-east-1"
                            />
                        </div>
                    </CardContent>
                </Card>

                {/* Team & Ownership */}
                <Card>
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2">
                            <Users className="h-4 w-4" />
                            Team & Ownership
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label>Team Owner</Label>
                            <Input
                                value={ops.team_owner || ""}
                                onChange={(e) => updateField("team_owner", e.target.value)}
                                placeholder="e.g. Platform Engineering"
                            />
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label>Contact Email</Label>
                                <Input
                                    type="email"
                                    value={ops.team_contact_email || ""}
                                    onChange={(e) => updateField("team_contact_email", e.target.value)}
                                    placeholder="team@example.com"
                                />
                            </div>
                            <div className="space-y-2">
                                <Label>Slack Channel</Label>
                                <Input
                                    value={ops.team_slack_channel || ""}
                                    onChange={(e) => updateField("team_slack_channel", e.target.value)}
                                    placeholder="#team-channel"
                                />
                            </div>
                        </div>
                    </CardContent>
                </Card>

                {/* Business Criticality */}
                <Card>
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2">
                            <Shield className="h-4 w-4" />
                            Business Criticality
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label>Criticality</Label>
                                <Select
                                    value={ops.business_criticality || "medium"}
                                    onValueChange={(v) => updateField("business_criticality", v)}
                                >
                                    <SelectTrigger>
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {CRITICALITY_LEVELS.map(c => (
                                            <SelectItem key={c.value} value={c.value}>
                                                {c.label}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label>Data Classification</Label>
                                <Select
                                    value={ops.data_classification || ""}
                                    onValueChange={(v) => updateField("data_classification", v)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select..." />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {DATA_CLASSIFICATIONS.map(d => (
                                            <SelectItem key={d} value={d}>
                                                {d.charAt(0).toUpperCase() + d.slice(1)}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                        </div>
                        <div className="space-y-2">
                            <Label>Notes</Label>
                            <Textarea
                                value={ops.business_criticality_notes || ""}
                                onChange={(e) => updateField("business_criticality_notes", e.target.value)}
                                placeholder="Business criticality justification..."
                                rows={2}
                            />
                        </div>
                    </CardContent>
                </Card>

                {/* Environment URLs - full width */}
                <Card className="lg:col-span-2">
                    <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                            <CardTitle className="text-sm flex items-center gap-2">
                                <ExternalLink className="h-4 w-4" />
                                Environment URLs
                            </CardTitle>
                            <Button variant="outline" size="sm" onClick={addEnvUrl}>
                                <Plus className="h-3 w-3 mr-1" />
                                Add
                            </Button>
                        </div>
                    </CardHeader>
                    <CardContent>
                        {envUrls.length === 0 ? (
                            <p className="text-sm text-muted-foreground text-center py-4">
                                No environment URLs configured. Click Add to create one.
                            </p>
                        ) : (
                            <div className="space-y-3">
                                {envUrls.map((env, idx) => (
                                    <div key={idx} className="flex items-center gap-3">
                                        <Input
                                            value={env.name}
                                            onChange={(e) => updateEnvUrl(idx, "name", e.target.value)}
                                            placeholder="Environment name"
                                            className="w-40"
                                        />
                                        <Input
                                            value={env.url}
                                            onChange={(e) => updateEnvUrl(idx, "url", e.target.value)}
                                            placeholder="https://..."
                                            className="flex-1"
                                        />
                                        <label className="flex items-center gap-1 text-xs text-muted-foreground whitespace-nowrap">
                                            <input
                                                type="checkbox"
                                                checked={env.is_primary}
                                                onChange={(e) => updateEnvUrl(idx, "is_primary", e.target.checked)}
                                                className="rounded"
                                            />
                                            Primary
                                        </label>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            className="h-8 w-8 p-0 text-red-500"
                                            onClick={() => removeEnvUrl(idx)}
                                        >
                                            <Trash2 className="h-3 w-3" />
                                        </Button>
                                    </div>
                                ))}
                            </div>
                        )}
                    </CardContent>
                </Card>

                {/* Compliance & Governance */}
                <Card>
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2">
                            <Shield className="h-4 w-4" />
                            Compliance & Governance
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label>Compliance Frameworks</Label>
                            <div className="flex flex-wrap gap-2 mb-2">
                                {frameworks.map(fw => (
                                    <Badge key={fw} variant="outline" className="pr-1">
                                        {fw}
                                        <button
                                            onClick={() => removeFramework(fw)}
                                            className="ml-1 hover:text-red-500"
                                        >
                                            <X className="h-3 w-3" />
                                        </button>
                                    </Badge>
                                ))}
                            </div>
                            <div className="flex gap-2">
                                <Input
                                    value={newFramework}
                                    onChange={(e) => setNewFramework(e.target.value)}
                                    placeholder="e.g. SOC2, PCI-DSS, HIPAA"
                                    onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addFramework())}
                                    className="flex-1"
                                />
                                <Button variant="outline" size="sm" onClick={addFramework}>
                                    <Plus className="h-3 w-3" />
                                </Button>
                            </div>
                        </div>
                        <div className="space-y-2">
                            <Label>Regulatory Notes</Label>
                            <Textarea
                                value={ops.regulatory_notes || ""}
                                onChange={(e) => updateField("regulatory_notes", e.target.value)}
                                placeholder="Regulatory requirements..."
                                rows={2}
                            />
                        </div>
                    </CardContent>
                </Card>

                {/* Infrastructure */}
                <Card>
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2">
                            <Server className="h-4 w-4" />
                            Infrastructure
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label>CI/CD Platform</Label>
                                <Select
                                    value={ops.cicd_platform || ""}
                                    onValueChange={(v) => updateField("cicd_platform", v)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select..." />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {CICD_PLATFORMS.map(p => (
                                            <SelectItem key={p} value={p}>
                                                {p}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="space-y-2">
                                <Label>IaC Type</Label>
                                <Select
                                    value={ops.iac_type || ""}
                                    onValueChange={(v) => updateField("iac_type", v)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select..." />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {IAC_TYPES.map(t => (
                                            <SelectItem key={t} value={t}>
                                                {t}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                        </div>
                        <div className="space-y-2">
                            <Label>CI/CD Pipeline URL</Label>
                            <Input
                                value={ops.cicd_pipeline_url || ""}
                                onChange={(e) => updateField("cicd_pipeline_url", e.target.value)}
                                placeholder="https://..."
                            />
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label>Container Registry</Label>
                                <Input
                                    value={ops.container_registry || ""}
                                    onChange={(e) => updateField("container_registry", e.target.value)}
                                    placeholder="e.g. ECR, ACR, DockerHub"
                                />
                            </div>
                            <div className="space-y-2">
                                <Label>IaC Path</Label>
                                <Input
                                    value={ops.iac_path || ""}
                                    onChange={(e) => updateField("iac_path", e.target.value)}
                                    placeholder="e.g. infra/, terraform/"
                                />
                            </div>
                        </div>
                    </CardContent>
                </Card>

                {/* Observability URLs */}
                <Card className="lg:col-span-2">
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2">
                            <Activity className="h-4 w-4" />
                            Observability
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="grid grid-cols-3 gap-4">
                            <div className="space-y-2">
                                <Label>Monitoring URL</Label>
                                <Input
                                    value={ops.monitoring_url || ""}
                                    onChange={(e) => updateField("monitoring_url", e.target.value)}
                                    placeholder="https://..."
                                />
                            </div>
                            <div className="space-y-2">
                                <Label>Alerting URL</Label>
                                <Input
                                    value={ops.alerting_url || ""}
                                    onChange={(e) => updateField("alerting_url", e.target.value)}
                                    placeholder="https://..."
                                />
                            </div>
                            <div className="space-y-2">
                                <Label>Logging URL</Label>
                                <Input
                                    value={ops.logging_url || ""}
                                    onChange={(e) => updateField("logging_url", e.target.value)}
                                    placeholder="https://..."
                                />
                            </div>
                        </div>
                    </CardContent>
                </Card>

                {/* Notes - full width */}
                <Card className="lg:col-span-2">
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm">Notes</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <Textarea
                            value={ops.notes || ""}
                            onChange={(e) => updateField("notes", e.target.value)}
                            placeholder="General operations notes..."
                            rows={3}
                        />
                    </CardContent>
                </Card>
            </div>

            {/* Discovery History */}
            {discoveries.length > 0 && (
                <Card>
                    <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                            <CardTitle className="text-sm flex items-center gap-2">
                                <Clock className="h-4 w-4" />
                                Discovery History
                            </CardTitle>
                            <Button variant="ghost" size="sm" onClick={fetchDiscoveries}>
                                <RefreshCw className="h-3 w-3" />
                            </Button>
                        </div>
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-2">
                            {discoveries.slice(0, 5).map(run => (
                                <div
                                    key={run.id}
                                    className="flex items-center justify-between p-2 rounded hover:bg-muted text-sm"
                                >
                                    <div className="flex items-center gap-3">
                                        <Badge
                                            variant={
                                                run.status === "completed" ? "default" :
                                                run.status === "failed" ? "destructive" : "secondary"
                                            }
                                        >
                                            {run.status}
                                        </Badge>
                                        <span className="text-muted-foreground">
                                            {run.suggestions?.length || 0} suggestions
                                        </span>
                                        {run.evidence_files && (
                                            <span className="text-muted-foreground">
                                                {run.evidence_files.length} files scanned
                                            </span>
                                        )}
                                    </div>
                                    <span className="text-xs text-muted-foreground">
                                        {run.created_at ? new Date(run.created_at).toLocaleString() : ""}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}
        </div>
    )
}
