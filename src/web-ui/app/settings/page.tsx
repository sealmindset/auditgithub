"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Switch } from "@/components/ui/switch"
import { Checkbox } from "@/components/ui/checkbox"
import { Loader2, CheckCircle2, XCircle, Database, Send } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { Badge } from "@/components/ui/badge"
import AuthConfigTab from "@/components/AuthConfigTab"

const API_BASE = "http://localhost:8000"

interface CriblConfig {
    id: string
    ingest_url: string | null
    auth_token_set: boolean
    verify_ssl: boolean
    enabled: boolean
    log_levels: string[]
    include_app_context: boolean
    include_security_audit: boolean
    minio_fallback: boolean
    minio_endpoint: string | null
    minio_bucket: string | null
    minio_access_key_set: boolean
    minio_secret_key_set: boolean
    last_test_at: string | null
    last_test_status: string | null
    last_test_message: string | null
}

interface CriblTestResult {
    success: boolean
    message: string
    response_time_ms: number | null
    status_code: number | null
    details: Record<string, unknown> | null
}

export default function SettingsPage() {
    const [loading, setLoading] = useState(false)
    const [saving, setSaving] = useState(false)
    const [verifyingOpenAI, setVerifyingOpenAI] = useState(false)
    const [verifyingJira, setVerifyingJira] = useState(false)

    const [openaiKey, setOpenaiKey] = useState("")
    const [jiraUrl, setJiraUrl] = useState("")
    const [jiraEmail, setJiraEmail] = useState("")
    const [jiraToken, setJiraToken] = useState("")

    const [openaiStatus, setOpenaiStatus] = useState<{ valid: boolean, message: string } | null>(null)
    const [jiraStatus, setJiraStatus] = useState<{ valid: boolean, message: string } | null>(null)

    // Cribl configuration state
    const [criblConfig, setCriblConfig] = useState<CriblConfig | null>(null)
    const [criblIngestUrl, setCriblIngestUrl] = useState("")
    const [criblAuthToken, setCriblAuthToken] = useState("")
    const [criblVerifySsl, setCriblVerifySsl] = useState(true)
    const [criblEnabled, setCriblEnabled] = useState(false)
    const [criblLogLevels, setCriblLogLevels] = useState<string[]>(["INFO", "WARNING", "ERROR", "CRITICAL"])
    const [criblIncludeAppContext, setCriblIncludeAppContext] = useState(true)
    const [criblIncludeSecurityAudit, setCriblIncludeSecurityAudit] = useState(true)
    const [criblMinioFallback, setCriblMinioFallback] = useState(true)
    const [criblMinioEndpoint, setCriblMinioEndpoint] = useState("http://minio:9000")
    const [criblMinioBucket, setCriblMinioBucket] = useState("auditgh-logs")
    const [criblMinioAccessKey, setCriblMinioAccessKey] = useState("")
    const [criblMinioSecretKey, setCriblMinioSecretKey] = useState("")
    const [savingCribl, setSavingCribl] = useState(false)
    const [testingCribl, setTestingCribl] = useState(false)
    const [testingMinio, setTestingMinio] = useState(false)
    const [criblTestResult, setCriblTestResult] = useState<CriblTestResult | null>(null)
    const [minioTestResult, setMinioTestResult] = useState<CriblTestResult | null>(null)

    useEffect(() => {
        const fetchSettings = async () => {
            setLoading(true)
            try {
                const res = await fetch(`${API_BASE}/settings/`)
                if (res.ok) {
                    const data = await res.json()
                    setOpenaiKey(data.OPENAI_API_KEY || "")
                    setJiraUrl(data.JIRA_URL || "")
                    setJiraEmail(data.JIRA_EMAIL || "")
                    setJiraToken(data.JIRA_API_TOKEN || "")
                }
            } catch (error) {
                console.error("Failed to fetch settings:", error)
            } finally {
                setLoading(false)
            }
        }
        
        const fetchCriblConfig = async () => {
            try {
                const res = await fetch(`${API_BASE}/cribl/config`)
                if (res.ok) {
                    const data: CriblConfig = await res.json()
                    setCriblConfig(data)
                    setCriblIngestUrl(data.ingest_url || "")
                    setCriblVerifySsl(data.verify_ssl)
                    setCriblEnabled(data.enabled)
                    setCriblLogLevels(data.log_levels || ["INFO", "WARNING", "ERROR", "CRITICAL"])
                    setCriblIncludeAppContext(data.include_app_context)
                    setCriblIncludeSecurityAudit(data.include_security_audit)
                    setCriblMinioFallback(data.minio_fallback)
                    setCriblMinioEndpoint(data.minio_endpoint || "http://minio:9000")
                    setCriblMinioBucket(data.minio_bucket || "auditgh-logs")
                }
            } catch (error) {
                console.error("Failed to fetch Cribl config:", error)
            }
        }
        
        fetchSettings()
        fetchCriblConfig()
    }, [])

    const handleSave = async () => {
        setSaving(true)
        try {
            const res = await fetch(`${API_BASE}/settings/`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    openai_api_key: openaiKey,
                    jira_url: jiraUrl,
                    jira_email: jiraEmail,
                    jira_api_token: jiraToken
                })
            })

            if (res.ok) {
                alert("Settings saved successfully!")
            } else {
                alert("Failed to save settings.")
            }
        } catch (error) {
            console.error("Failed to save settings:", error)
            alert("Error saving settings.")
        } finally {
            setSaving(false)
        }
    }

    const verifyOpenAI = async () => {
        setVerifyingOpenAI(true)
        setOpenaiStatus(null)
        try {
            const res = await fetch(`${API_BASE}/settings/verify/openai`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token: openaiKey })
            })
            const data = await res.json()
            setOpenaiStatus(data)
        } catch (error) {
            setOpenaiStatus({ valid: false, message: "Verification request failed" })
        } finally {
            setVerifyingOpenAI(false)
        }
    }

    const verifyJira = async () => {
        setVerifyingJira(true)
        setJiraStatus(null)
        try {
            const res = await fetch(`${API_BASE}/settings/verify/jira`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    token: jiraToken,
                    url: jiraUrl,
                    email: jiraEmail
                })
            })
            const data = await res.json()
            setJiraStatus(data)
        } catch (error) {
            setJiraStatus({ valid: false, message: "Verification request failed" })
        } finally {
            setVerifyingJira(false)
        }
    }

    const handleSaveCribl = async () => {
        setSavingCribl(true)
        try {
            const res = await fetch(`${API_BASE}/cribl/config`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    ingest_url: criblIngestUrl,
                    auth_token: criblAuthToken || undefined,
                    verify_ssl: criblVerifySsl,
                    enabled: criblEnabled,
                    log_levels: criblLogLevels,
                    include_app_context: criblIncludeAppContext,
                    include_security_audit: criblIncludeSecurityAudit,
                    minio_fallback: criblMinioFallback,
                    minio_endpoint: criblMinioEndpoint,
                    minio_bucket: criblMinioBucket,
                    minio_access_key: criblMinioAccessKey || undefined,
                    minio_secret_key: criblMinioSecretKey || undefined
                })
            })
            if (res.ok) {
                const data = await res.json()
                setCriblConfig(data)
                setCriblAuthToken("")
                setCriblMinioAccessKey("")
                setCriblMinioSecretKey("")
                alert("Cribl configuration saved successfully!")
            } else {
                alert("Failed to save Cribl configuration.")
            }
        } catch (error) {
            console.error("Failed to save Cribl config:", error)
            alert("Error saving Cribl configuration.")
        } finally {
            setSavingCribl(false)
        }
    }

    const testCriblConnection = async () => {
        setTestingCribl(true)
        setCriblTestResult(null)
        try {
            const res = await fetch(`${API_BASE}/cribl/test`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    ingest_url: criblIngestUrl || undefined,
                    auth_token: criblAuthToken || undefined,
                    verify_ssl: criblVerifySsl
                })
            })
            const data: CriblTestResult = await res.json()
            setCriblTestResult(data)
        } catch (error) {
            setCriblTestResult({ success: false, message: "Test request failed", response_time_ms: null, status_code: null, details: null })
        } finally {
            setTestingCribl(false)
        }
    }

    const testMinioConnection = async () => {
        setTestingMinio(true)
        setMinioTestResult(null)
        try {
            const res = await fetch(`${API_BASE}/cribl/test-minio`, {
                method: "POST",
                headers: { "Content-Type": "application/json" }
            })
            const data: CriblTestResult = await res.json()
            setMinioTestResult(data)
        } catch (error) {
            setMinioTestResult({ success: false, message: "Test request failed", response_time_ms: null, status_code: null, details: null })
        } finally {
            setTestingMinio(false)
        }
    }

    const toggleLogLevel = (level: string) => {
        if (criblLogLevels.includes(level)) {
            setCriblLogLevels(criblLogLevels.filter(l => l !== level))
        } else {
            setCriblLogLevels([...criblLogLevels, level])
        }
    }

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
                <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
                <p className="text-muted-foreground">
                    Manage your platform configuration and integrations.
                </p>
            </div>

            <Tabs defaultValue="general" className="space-y-4">
                <TabsList>
                    <TabsTrigger value="general">General</TabsTrigger>
                    <TabsTrigger value="auth">Authentication & Authorization</TabsTrigger>
                    <TabsTrigger value="integrations">Integrations</TabsTrigger>
                    <TabsTrigger value="cribl">Cribl</TabsTrigger>
                    <TabsTrigger value="notifications">Notifications</TabsTrigger>
                </TabsList>

                <TabsContent value="general" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>General Configuration</CardTitle>
                            <CardDescription>
                                Configure general platform settings.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Automatic Scanning</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Automatically scan repositories on push events.
                                    </p>
                                </div>
                                <Switch />
                            </div>
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>AI Analysis</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Enable AI-powered triage and remediation suggestions.
                                    </p>
                                </div>
                                <Switch defaultChecked />
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="auth" className="space-y-4">
                    <AuthConfigTab />
                </TabsContent>

                <TabsContent value="integrations" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>OpenAI Integration</CardTitle>
                            <CardDescription>
                                Configure OpenAI API key for AI features.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label htmlFor="openai-key">API Key</Label>
                                <div className="flex gap-2">
                                    <Input
                                        id="openai-key"
                                        type="password"
                                        placeholder="sk-..."
                                        value={openaiKey}
                                        onChange={(e) => setOpenaiKey(e.target.value)}
                                    />
                                    <Button variant="secondary" onClick={verifyOpenAI} disabled={verifyingOpenAI || !openaiKey}>
                                        {verifyingOpenAI ? <Loader2 className="h-4 w-4 animate-spin" /> : "Verify"}
                                    </Button>
                                </div>
                                {openaiStatus && (
                                    <div className={`flex items-center gap-2 text-sm ${openaiStatus.valid ? "text-green-600" : "text-red-600"}`}>
                                        {openaiStatus.valid ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                                        {openaiStatus.message}
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle>Jira Integration</CardTitle>
                            <CardDescription>
                                Connect to Jira for ticket management.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="grid gap-4">
                                <div className="grid gap-2">
                                    <Label htmlFor="jira-url">Jira URL</Label>
                                    <Input
                                        id="jira-url"
                                        placeholder="https://your-domain.atlassian.net"
                                        value={jiraUrl}
                                        onChange={(e) => setJiraUrl(e.target.value)}
                                    />
                                </div>
                                <div className="grid gap-2">
                                    <Label htmlFor="jira-email">Email</Label>
                                    <Input
                                        id="jira-email"
                                        placeholder="user@example.com"
                                        value={jiraEmail}
                                        onChange={(e) => setJiraEmail(e.target.value)}
                                    />
                                </div>
                                <div className="grid gap-2">
                                    <Label htmlFor="jira-token">API Token</Label>
                                    <div className="flex gap-2">
                                        <Input
                                            id="jira-token"
                                            type="password"
                                            placeholder="Jira API Token"
                                            value={jiraToken}
                                            onChange={(e) => setJiraToken(e.target.value)}
                                        />
                                        <Button variant="secondary" onClick={verifyJira} disabled={verifyingJira || !jiraToken || !jiraUrl || !jiraEmail}>
                                            {verifyingJira ? <Loader2 className="h-4 w-4 animate-spin" /> : "Verify"}
                                        </Button>
                                    </div>
                                    {jiraStatus && (
                                        <div className={`flex items-center gap-2 text-sm ${jiraStatus.valid ? "text-green-600" : "text-red-600"}`}>
                                            {jiraStatus.valid ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                                            {jiraStatus.message}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="cribl" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Send className="h-5 w-5" />
                                Cribl Stream Integration
                                {criblEnabled ? (
                                    <Badge variant="default" className="ml-2">Enabled</Badge>
                                ) : (
                                    <Badge variant="secondary" className="ml-2">Disabled</Badge>
                                )}
                            </CardTitle>
                            <CardDescription>
                                Configure log forwarding to Cribl Stream for centralized log management, processing, and routing.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Enable Cribl Logging</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Forward application logs to Cribl Stream.
                                    </p>
                                </div>
                                <Switch 
                                    checked={criblEnabled} 
                                    onCheckedChange={setCriblEnabled}
                                />
                            </div>

                            <div className="grid gap-4">
                                <div className="grid gap-2">
                                    <Label htmlFor="cribl-url">Ingest URL</Label>
                                    <Input
                                        id="cribl-url"
                                        placeholder="https://cribl.example.com:20000"
                                        value={criblIngestUrl}
                                        onChange={(e) => setCriblIngestUrl(e.target.value)}
                                    />
                                    <p className="text-xs text-muted-foreground">
                                        The HTTP/S endpoint for Cribl Stream. For Cribl.Cloud, use ports 20000-20010.
                                    </p>
                                </div>

                                <div className="grid gap-2">
                                    <Label htmlFor="cribl-token">Auth Token</Label>
                                    <Input
                                        id="cribl-token"
                                        type="password"
                                        placeholder={criblConfig?.auth_token_set ? "••••••••••••••••" : "Enter authentication token"}
                                        value={criblAuthToken}
                                        onChange={(e) => setCriblAuthToken(e.target.value)}
                                    />
                                    <p className="text-xs text-muted-foreground">
                                        Bearer token for authenticating with Cribl. {criblConfig?.auth_token_set && "(Token is set)"}
                                    </p>
                                </div>

                                <div className="flex items-center justify-between">
                                    <div className="space-y-0.5">
                                        <Label>Verify SSL</Label>
                                        <p className="text-sm text-muted-foreground">
                                            Validate SSL certificates when connecting.
                                        </p>
                                    </div>
                                    <Switch 
                                        checked={criblVerifySsl} 
                                        onCheckedChange={setCriblVerifySsl}
                                    />
                                </div>
                            </div>

                            <div className="border-t pt-4">
                                <Label className="text-base font-semibold">Log Levels</Label>
                                <p className="text-sm text-muted-foreground mb-3">
                                    Select which log levels to forward to Cribl.
                                </p>
                                <div className="flex flex-wrap gap-4">
                                    {["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"].map((level) => (
                                        <div key={level} className="flex items-center space-x-2">
                                            <Checkbox
                                                id={`level-${level}`}
                                                checked={criblLogLevels.includes(level)}
                                                onCheckedChange={() => toggleLogLevel(level)}
                                            />
                                            <Label htmlFor={`level-${level}`} className="text-sm font-normal">
                                                {level}
                                            </Label>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="border-t pt-4">
                                <Label className="text-base font-semibold">Log Content Options</Label>
                                <div className="mt-3 space-y-3">
                                    <div className="flex items-center justify-between">
                                        <div className="space-y-0.5">
                                            <Label>Include App Context</Label>
                                            <p className="text-sm text-muted-foreground">
                                                Add org_id, user_id, request_id to log entries.
                                            </p>
                                        </div>
                                        <Switch 
                                            checked={criblIncludeAppContext} 
                                            onCheckedChange={setCriblIncludeAppContext}
                                        />
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <div className="space-y-0.5">
                                            <Label>Include Security Audit</Label>
                                            <p className="text-sm text-muted-foreground">
                                                Add action, resource, outcome fields for audit logs.
                                            </p>
                                        </div>
                                        <Switch 
                                            checked={criblIncludeSecurityAudit} 
                                            onCheckedChange={setCriblIncludeSecurityAudit}
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="flex gap-2">
                                <Button 
                                    variant="secondary" 
                                    onClick={testCriblConnection} 
                                    disabled={testingCribl || !criblIngestUrl}
                                >
                                    {testingCribl ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                                    Test Configuration
                                </Button>
                            </div>

                            {criblTestResult && (
                                <div className={`flex items-start gap-2 p-3 rounded-md ${criblTestResult.success ? "bg-green-50 border border-green-200" : "bg-red-50 border border-red-200"}`}>
                                    {criblTestResult.success ? <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5" /> : <XCircle className="h-5 w-5 text-red-600 mt-0.5" />}
                                    <div>
                                        <p className={`font-medium ${criblTestResult.success ? "text-green-800" : "text-red-800"}`}>
                                            {criblTestResult.message}
                                        </p>
                                        {criblTestResult.response_time_ms && (
                                            <p className="text-sm text-muted-foreground">
                                                Response time: {criblTestResult.response_time_ms}ms
                                            </p>
                                        )}
                                    </div>
                                </div>
                            )}

                            {criblConfig?.last_test_at && (
                                <p className="text-xs text-muted-foreground">
                                    Last test: {new Date(criblConfig.last_test_at).toLocaleString()} - {criblConfig.last_test_status}
                                </p>
                            )}
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Database className="h-5 w-5" />
                                MinIO Log Storage (Fallback)
                            </CardTitle>
                            <CardDescription>
                                Configure local S3-compatible storage for logs when Cribl is unavailable.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Enable MinIO Fallback</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Store logs in MinIO when Cribl is unreachable.
                                    </p>
                                </div>
                                <Switch 
                                    checked={criblMinioFallback} 
                                    onCheckedChange={setCriblMinioFallback}
                                />
                            </div>

                            <div className="grid gap-4">
                                <div className="grid grid-cols-2 gap-4">
                                    <div className="grid gap-2">
                                        <Label htmlFor="minio-endpoint">MinIO Endpoint</Label>
                                        <Input
                                            id="minio-endpoint"
                                            placeholder="http://minio:9000"
                                            value={criblMinioEndpoint}
                                            onChange={(e) => setCriblMinioEndpoint(e.target.value)}
                                        />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="minio-bucket">Bucket Name</Label>
                                        <Input
                                            id="minio-bucket"
                                            placeholder="auditgh-logs"
                                            value={criblMinioBucket}
                                            onChange={(e) => setCriblMinioBucket(e.target.value)}
                                        />
                                    </div>
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <div className="grid gap-2">
                                        <Label htmlFor="minio-access">Access Key</Label>
                                        <Input
                                            id="minio-access"
                                            type="password"
                                            placeholder={criblConfig?.minio_access_key_set ? "••••••••" : "Access key"}
                                            value={criblMinioAccessKey}
                                            onChange={(e) => setCriblMinioAccessKey(e.target.value)}
                                        />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="minio-secret">Secret Key</Label>
                                        <Input
                                            id="minio-secret"
                                            type="password"
                                            placeholder={criblConfig?.minio_secret_key_set ? "••••••••" : "Secret key"}
                                            value={criblMinioSecretKey}
                                            onChange={(e) => setCriblMinioSecretKey(e.target.value)}
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="flex gap-2">
                                <Button 
                                    variant="secondary" 
                                    onClick={testMinioConnection} 
                                    disabled={testingMinio}
                                >
                                    {testingMinio ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                                    Test MinIO Connection
                                </Button>
                            </div>

                            {minioTestResult && (
                                <div className={`flex items-start gap-2 p-3 rounded-md ${minioTestResult.success ? "bg-green-50 border border-green-200" : "bg-red-50 border border-red-200"}`}>
                                    {minioTestResult.success ? <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5" /> : <XCircle className="h-5 w-5 text-red-600 mt-0.5" />}
                                    <div>
                                        <p className={`font-medium ${minioTestResult.success ? "text-green-800" : "text-red-800"}`}>
                                            {minioTestResult.message}
                                        </p>
                                        {minioTestResult.response_time_ms && (
                                            <p className="text-sm text-muted-foreground">
                                                Response time: {minioTestResult.response_time_ms}ms
                                            </p>
                                        )}
                                    </div>
                                </div>
                            )}
                        </CardContent>
                        <CardFooter>
                            <Button onClick={handleSaveCribl} disabled={savingCribl}>
                                {savingCribl && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                Save Cribl Configuration
                            </Button>
                        </CardFooter>
                    </Card>
                </TabsContent>

                <TabsContent value="notifications" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Notifications</CardTitle>
                            <CardDescription>
                                Configure how you want to be notified.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Email Notifications</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Receive emails about critical findings.
                                    </p>
                                </div>
                                <Switch />
                            </div>
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Slack Notifications</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Receive alerts in Slack channels.
                                    </p>
                                </div>
                                <Switch />
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>
            </Tabs>

            <div className="flex justify-end">
                <Button onClick={handleSave} disabled={saving}>
                    {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Save Changes
                </Button>
            </div>
        </div>
    )
}
