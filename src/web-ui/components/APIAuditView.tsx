"use client"

import { useEffect, useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
    Loader2,
    Globe,
    Upload,
    Download,
    FileJson,
    FileCode2,
    Key,
    Shield,
    ShieldAlert,
    ShieldCheck,
    Server,
    ChevronDown,
    ChevronRight,
    AlertTriangle,
    CheckCircle2,
    XCircle,
    ExternalLink,
    FolderOpen,
    Zap,
    Play,
    RefreshCw,
    FileText,
    X,
    Code
} from "lucide-react"
import { DownloadControl } from "./DownloadControl"
import { API_BASE, apiFetch } from "@/lib/api"

// =============================================================================
// Types
// =============================================================================

interface APIEndpoint {
    category: string
    rule_id: string
    path: string
    line: number
    code: string
    endpoint_path?: string
    message: string
    metadata: {
        category: string
        subcategory: string
        secret_type?: string
        environment?: string
        framework?: string
    }
}

interface APIAuditData {
    repository: string
    timestamp: string
    inbound_endpoints: APIEndpoint[]
    outbound_endpoints: APIEndpoint[]
    auth_patterns: APIEndpoint[]
    fingerprint: {
        language: string | null
        frameworks: string[]
        http_clients: string[]
        config_sources: string[]
    }
    servers: { url: string; description?: string }[]
    credentials: {
        high: CredentialFinding[]
        medium: CredentialFinding[]
        low: CredentialFinding[]
    }
}

interface CredentialFinding {
    type: string
    environment: string
    file: string
    code: string
    attack_vector?: string
}

// AI Correlation Types
interface CredentialUrlCorrelation {
    credential: {
        type: string
        value: string
        file: string
        line: number
        environment: string
    }
    url: string
    url_file: string
    confidence: number
    match_reasons: string[]
    llm_enhanced?: boolean
}

interface InboundCorrelation {
    endpoint: {
        path: string
        method: string
        framework: string
        file: string
        line: number
    }
    target_url: string
    server_url: string
    confidence: number
    match_reasons: string[]
}

interface OutboundCorrelation {
    endpoint: {
        code: string
        secret_type: string
        environment: string
        file: string
        line: number
    }
    target_url: string
    server_url: string
    confidence: number
    match_reasons: string[]
}

interface ServerCredCorrelation {
    server: {
        url: string
        description: string
        environment: string
    }
    credentials: Array<{
        credential: {
            type: string
            value: string
            environment: string
            file: string
        }
        confidence: number
        match_reasons: string[]
    }>
    credential_count: number
    top_confidence: number
}

// Swagger Server Credentials (for connection testing)
interface SwaggerServerCredential {
    server_url: string
    server_description: string
    server_environment: string
    source_file: string
    credentials: Array<{
        credential_type: string
        credential_value: string
        credential_file: string
        environment: string
        confidence: number
        match_reasons: string[]
    }>
    credential_count: number
    top_confidence: number
}

// Credential-URL Test Result (from AI Agent)
interface CredentialUrlTestResult {
    id: string
    target_url: string
    credential_type: string
    credential_environment: string
    confidence_score: number
    auth_status: 'yes' | 'failed' | 'not_tested'
    auth_status_code: number
    auth_response_time_ms: number
    auth_error_message: string
    auth_headers_used: string[]
    auth_request_method?: string
    auth_request_url?: string
    auth_request_headers?: Record<string, string>
    auth_request_body?: string
    auth_response_headers?: Record<string, string>
    auth_response_body?: string
    auth_response_body_truncated?: boolean
    credential_value?: string
    detected_service?: string
    service_detection_score?: number
    discovered_paths: Array<{
        method: string
        path: string
        full_url: string
        status_code: number
        success: boolean
        sample_data: any
        content_type: string
    }>
    discovered_paths_count: number
    hidden_paths_found: number
    sample_data_retrieved: any[]
    data_sensitivity_indicators: Array<{
        path: string
        type: string
        count: number
        severity: string
    }>
    osint_findings: Array<{
        url: string
        type: string
        description: string
        relevance: number
    }>
    github_repos_found: number
    documentation_links_found: number
    ai_overview: string
    ai_risk_assessment: string
    ai_recommendations: string[]
    threat_level: 'critical' | 'high' | 'medium' | 'low' | 'info'
    test_mode: string
    tested_at: string
    test_duration_seconds: number
    llm_provider: string
    llm_model: string
}

interface APIAuditViewProps {
    projectId: string
}

// =============================================================================
// Component
// =============================================================================

export function APIAuditView({ projectId }: APIAuditViewProps) {
    const [auditData, setAuditData] = useState<APIAuditData | null>(null)
    const [openApiSpec, setOpenApiSpec] = useState<string | null>(null)
    const [swaggerFiles, setSwaggerFiles] = useState<Array<{ name: string, server_url: string, yaml_file: string, json_file: string | null, path_count: number }>>([])
    const [matchedCredentials, setMatchedCredentials] = useState<Array<{ service: string, type: string, value: string, certainty: number, server_url: string }>>([])
    const [credentialsModalOpen, setCredentialsModalOpen] = useState(false)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    const [activeTab, setActiveTab] = useState("results")
    const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(["servers", "credentials"]))
    const [swaggerModalUrl, setSwaggerModalUrl] = useState<string | null>(null)
    
    // AI Correlation State
    const [credentialUrlCorrelations, setCredentialUrlCorrelations] = useState<CredentialUrlCorrelation[]>([])
    const [inboundCorrelations, setInboundCorrelations] = useState<InboundCorrelation[]>([])
    const [outboundCorrelations, setOutboundCorrelations] = useState<OutboundCorrelation[]>([])
    const [serverCredCorrelations, setServerCredCorrelations] = useState<ServerCredCorrelation[]>([])
    const [swaggerServerCredentials, setSwaggerServerCredentials] = useState<SwaggerServerCredential[]>([])
    const [correlationsLoading, setCorrelationsLoading] = useState(false)
    
    // AI Credential-URL Testing State
    const [credentialTestResults, setCredentialTestResults] = useState<Record<string, CredentialUrlTestResult>>({})
    const [testingInProgress, setTestingInProgress] = useState<Record<string, boolean>>({})
    const [selectedTestMode, setSelectedTestMode] = useState<'none' | 'cautious' | 'insane'>('cautious')
    const [reportModalOpen, setReportModalOpen] = useState(false)
    const [selectedReportResult, setSelectedReportResult] = useState<CredentialUrlTestResult | null>(null)
    const [downloadModalOpen, setDownloadModalOpen] = useState(false)
    const [downloadFilename, setDownloadFilename] = useState('')
    const [downloadFormat, setDownloadFormat] = useState<'pdf' | 'json' | 'docx' | 'csv' | 'markdown'>('pdf')
    const [initialTestCompleted, setInitialTestCompleted] = useState(false)
    const [autoTestTriggered, setAutoTestTriggered] = useState(false)
    const [resultsLoaded, setResultsLoaded] = useState(false)

    useEffect(() => {
        fetchAuditData()
        fetchSwaggerFiles()
        fetchMatchedCredentials()
        fetchAllCorrelations()
        fetchCredentialTestResults().then(() => setResultsLoaded(true))
        checkInitialTestStatus()
    }, [projectId])

    // Auto-test on first page load only (not on every page load)
    // Wait for both correlations AND existing results to be loaded before deciding to auto-test
    useEffect(() => {
        // Don't run until we've loaded existing results from the database
        if (!resultsLoaded) return
        
        // Don't run if already triggered or completed
        if (autoTestTriggered || initialTestCompleted) return
        
        // Don't run if no correlations
        if (credentialUrlCorrelations.length === 0) return
        
        // Check if there are any untested correlations
        const untestedCorrelations = credentialUrlCorrelations.filter(
            corr => !credentialTestResults[getCredentialUrlKey(corr.url, corr.credential.type)]
        )
        
        if (untestedCorrelations.length > 0) {
            console.log(`[APIAuditView] Found ${untestedCorrelations.length} untested correlations, starting auto-test...`)
            setAutoTestTriggered(true)
            runInitialAutoTest()
        } else {
            console.log(`[APIAuditView] All ${credentialUrlCorrelations.length} correlations already tested, skipping auto-test`)
            // Mark as completed since all are already tested
            setInitialTestCompleted(true)
        }
    }, [credentialUrlCorrelations, initialTestCompleted, resultsLoaded, credentialTestResults])

    // Check if initial auto-test has already been completed for this project
    const checkInitialTestStatus = async () => {
        try {
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/credential-url-test-status`)
            if (response.ok) {
                const data = await response.json()
                setInitialTestCompleted(data.initial_test_completed || false)
            }
        } catch (e) {
            console.error("Failed to check initial test status:", e)
        }
    }

    // Mark initial auto-test as complete
    const markInitialTestComplete = async (totalTested: number, totalFound: number) => {
        try {
            await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/credential-url-test-status/mark-complete?total_tested=${totalTested}&total_found=${totalFound}`, {
                method: 'POST'
            })
            setInitialTestCompleted(true)
        } catch (e) {
            console.error("Failed to mark initial test complete:", e)
        }
    }

    // Helper to create unique key for credential-URL pair
    // Normalize URL by removing trailing slash to ensure consistent matching
    const getCredentialUrlKey = (url: string, credentialType: string) => {
        const normalizedUrl = url.replace(/\/+$/, '') // Remove trailing slashes
        return `${normalizedUrl}::${credentialType}`
    }

    // Run initial auto-test (only once per project)
    const runInitialAutoTest = async () => {
        console.log("[APIAuditView] Running initial auto-test for credential-URL pairs...")
        let testedCount = 0
        
        for (const corr of credentialUrlCorrelations) {
            const key = getCredentialUrlKey(corr.url, corr.credential.type)
            if (!credentialTestResults[key]) {
                await testCredentialUrl(
                    corr.url,
                    corr.credential.type,
                    corr.credential.value,
                    corr.credential.environment,
                    corr.confidence
                )
                testedCount++
            }
        }
        
        // Mark initial test as complete so it doesn't run again
        await markInitialTestComplete(testedCount, credentialUrlCorrelations.length)
        console.log(`[APIAuditView] Initial auto-test complete: ${testedCount} tested, ${credentialUrlCorrelations.length} total`)
    }

    // Fetch existing test results from database
    const fetchCredentialTestResults = async () => {
        try {
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/credential-url-results`)
            if (response.ok) {
                const data = await response.json()
                const resultsMap: Record<string, CredentialUrlTestResult> = {}
                for (const result of data.results || []) {
                    // Use composite key to handle multiple credentials per URL
                    const key = getCredentialUrlKey(result.target_url, result.credential_type)
                    resultsMap[key] = result
                }
                setCredentialTestResults(resultsMap)
            }
        } catch (e) {
            console.error("Failed to fetch credential test results:", e)
        }
    }

    // Test a single credential-URL pair
    const testCredentialUrl = async (url: string, credentialType: string, credentialValue: string, environment: string, confidence: number) => {
        const key = getCredentialUrlKey(url, credentialType)
        setTestingInProgress(prev => ({ ...prev, [key]: true }))
        
        try {
            console.log(`[testCredentialUrl] Testing ${url} with ${credentialType}...`)
            
            // Use AbortController for timeout
            // Backend tests can take 3+ minutes due to OSINT gathering and path discovery
            const controller = new AbortController()
            const timeoutId = setTimeout(() => controller.abort(), 300000) // 5 minute timeout
            
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/credential-url-test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_url: url,
                    credential_type: credentialType,
                    credential_value: credentialValue,
                    credential_environment: environment,
                    confidence_score: confidence,
                    test_mode: selectedTestMode
                }),
                signal: controller.signal
            })
            
            clearTimeout(timeoutId)
            
            if (response.ok) {
                const data = await response.json()
                console.log(`[testCredentialUrl] Response for ${url}:`, data)
                if (data.success && data.result_id) {
                    // Fetch the full result
                    const detailResponse = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/credential-url-results/${data.result_id}`)
                    if (detailResponse.ok) {
                        const detailData = await detailResponse.json()
                        setCredentialTestResults(prev => ({
                            ...prev,
                            [key]: detailData.result
                        }))
                    }
                }
            } else {
                const errorText = await response.text()
                console.error(`[testCredentialUrl] Error response for ${url}:`, response.status, errorText)
            }
        } catch (e: any) {
            if (e.name === 'AbortError') {
                console.error(`[testCredentialUrl] Request timed out for ${url}`)
            } else {
                console.error(`[testCredentialUrl] Failed to test ${url}:`, e.message || e)
            }
        } finally {
            setTestingInProgress(prev => ({ ...prev, [key]: false }))
        }
    }

    // Test all credential-URL pairs (manual trigger via button)
    const testAllCredentialUrls = async () => {
        for (const corr of credentialUrlCorrelations) {
            await testCredentialUrl(
                corr.url,
                corr.credential.type,
                corr.credential.value,
                corr.credential.environment,
                corr.confidence
            )
        }
    }

    // Open report modal
    const openReportModal = async (url: string, credentialType: string) => {
        const key = getCredentialUrlKey(url, credentialType)
        const result = credentialTestResults[key]
        console.log(`[openReportModal] url=${url}, credentialType=${credentialType}`)
        console.log(`[openReportModal] key=${key}`)
        console.log(`[openReportModal] result exists=${!!result}, result id=${result?.id}`)
        console.log(`[openReportModal] Available keys:`, Object.keys(credentialTestResults))
        
        if (result) {
            // Always fetch full details to ensure we have auth_request_headers with credential values
            console.log(`[openReportModal] Fetching full details for ${result.id}`)
            try {
                const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/credential-url-results/${result.id}`)
                console.log(`[openReportModal] API response status: ${response.status}`)
                if (response.ok) {
                    const data = await response.json()
                    console.log(`[openReportModal] Full data received, auth_status=${data.result?.auth_status}`)
                    console.log(`[openReportModal] auth_request_headers:`, data.result?.auth_request_headers)
                    console.log(`[openReportModal] credential_value:`, data.result?.credential_value)
                    setSelectedReportResult(data.result)
                } else {
                    console.log(`[openReportModal] API failed, using cached result`)
                    setSelectedReportResult(result)
                }
            } catch (e) {
                console.error(`[openReportModal] Error fetching details:`, e)
                setSelectedReportResult(result)
            }
            console.log(`[openReportModal] Setting reportModalOpen=true`)
            setReportModalOpen(true)
        } else {
            console.warn(`[openReportModal] No result found for key: ${key}`)
        }
    }

    // Download report
    const downloadReport = async () => {
        if (!selectedReportResult) return
        
        const filename = downloadFilename || `credential_url_report_${selectedReportResult.id?.slice(0, 8)}`
        const url = `${API_BASE}/projects/${projectId}/api-audit/credential-url-results/${selectedReportResult.id}/download?format=${downloadFormat}&filename=${encodeURIComponent(filename)}`
        
        try {
            const response = await fetch(url)
            if (response.ok) {
                const blob = await response.blob()
                const downloadUrl = window.URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = downloadUrl
                a.download = `${filename}.${downloadFormat}`
                document.body.appendChild(a)
                a.click()
                document.body.removeChild(a)
                window.URL.revokeObjectURL(downloadUrl)
                setDownloadModalOpen(false)
            }
        } catch (e) {
            console.error("Failed to download report:", e)
        }
    }

    // Get auth status badge
    const getAuthStatusBadge = (url: string, credentialType: string) => {
        const key = getCredentialUrlKey(url, credentialType)
        const result = credentialTestResults[key]
        const testing = testingInProgress[key]
        
        if (testing) {
            return <Badge variant="outline" className="text-xs animate-pulse">Testing...</Badge>
        }
        
        if (!result) {
            return <Badge variant="outline" className="text-xs text-gray-500">Not Tested</Badge>
        }
        
        switch (result.auth_status) {
            case 'yes':
                return <Badge className="text-xs bg-green-500 hover:bg-green-600">Yes</Badge>
            case 'failed':
                return <Badge className="text-xs bg-red-500 hover:bg-red-600">Failed</Badge>
            default:
                return <Badge variant="outline" className="text-xs text-gray-500">Not Tested</Badge>
        }
    }

    // AI Correlation Fetch Functions
    const fetchAllCorrelations = async () => {
        setCorrelationsLoading(true)
        try {
            await Promise.all([
                fetchCredentialUrlCorrelations(),
                fetchInboundCorrelations(),
                fetchOutboundCorrelations(),
                fetchServerCredCorrelations(),
                fetchSwaggerServerCredentials()
            ])
        } finally {
            setCorrelationsLoading(false)
        }
    }
    
    const fetchSwaggerServerCredentials = async () => {
        try {
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/swagger-server-credentials`)
            if (response.ok) {
                const data = await response.json()
                setSwaggerServerCredentials(data.mappings || [])
            }
        } catch (e) {
            console.error("Failed to fetch swagger server credentials:", e)
        }
    }

    const fetchCredentialUrlCorrelations = async () => {
        try {
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/credential-url-correlations`)
            if (response.ok) {
                const data = await response.json()
                setCredentialUrlCorrelations(data.correlations || [])
            }
        } catch (e) {
            console.error("Failed to fetch credential-URL correlations:", e)
        }
    }

    const fetchInboundCorrelations = async () => {
        try {
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/inbound-url-correlations`)
            if (response.ok) {
                const data = await response.json()
                setInboundCorrelations(data.correlations || [])
            }
        } catch (e) {
            console.error("Failed to fetch inbound correlations:", e)
        }
    }

    const fetchOutboundCorrelations = async () => {
        try {
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/outbound-url-correlations`)
            if (response.ok) {
                const data = await response.json()
                setOutboundCorrelations(data.correlations || [])
            }
        } catch (e) {
            console.error("Failed to fetch outbound correlations:", e)
        }
    }

    const fetchServerCredCorrelations = async () => {
        try {
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/server-credential-correlations`)
            if (response.ok) {
                const data = await response.json()
                setServerCredCorrelations(data.correlations || [])
            }
        } catch (e) {
            console.error("Failed to fetch server-credential correlations:", e)
        }
    }

    const fetchMatchedCredentials = async () => {
        try {
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/matched-credentials`)
            if (response.ok) {
                const data = await response.json()
                setMatchedCredentials(data.credentials || [])
            }
        } catch (e) {
            console.error("Failed to fetch matched credentials:", e)
        }
    }

    const fetchSwaggerFiles = async () => {
        try {
            const response = await apiFetch(`${API_BASE}/projects/${projectId}/api-audit/swagger-files`)
            if (response.ok) {
                const data = await response.json()
                setSwaggerFiles(data.files || [])
            }
        } catch (e) {
            console.error("Failed to fetch swagger files:", e)
        }
    }

    const fetchAuditData = async () => {
        setLoading(true)
        setError(null)
        try {
            const [auditRes, specRes] = await Promise.all([
                apiFetch(`${API_BASE}/projects/${projectId}/api-audit/full-report`),
                apiFetch(`${API_BASE}/projects/${projectId}/api-audit/openapi/view`)
            ])

            if (auditRes.ok) {
                const data = await auditRes.json()
                setAuditData(data)
            } else if (auditRes.status === 404) {
                setError("No API audit data found. Run an API audit scan first.")
            }

            if (specRes.ok) {
                const spec = await specRes.json()
                setOpenApiSpec(spec.spec_content)
            }
        } catch (err) {
            console.error("Failed to fetch API audit data:", err)
            setError("Failed to connect to API server.")
        } finally {
            setLoading(false)
        }
    }

    const toggleSection = (section: string) => {
        const newExpanded = new Set(expandedSections)
        if (newExpanded.has(section)) {
            newExpanded.delete(section)
        } else {
            newExpanded.add(section)
        }
        setExpandedSections(newExpanded)
    }

    const handleDownload = (format: "yaml" | "json") => {
        window.open(`${API_BASE}/projects/${projectId}/api-audit/openapi?format=${format}`, '_blank')
    }

    // =========================================================================
    // Render Helpers
    // =========================================================================

    const renderSeverityBadge = (severity: "high" | "medium" | "low", count: number) => {
        const configs = {
            high: { bg: "bg-red-500/10 border-red-500/30", text: "text-red-500", icon: XCircle, label: "HIGH" },
            medium: { bg: "bg-yellow-500/10 border-yellow-500/30", text: "text-yellow-500", icon: AlertTriangle, label: "MEDIUM" },
            low: { bg: "bg-green-500/10 border-green-500/30", text: "text-green-500", icon: CheckCircle2, label: "LOW" }
        }
        const config = configs[severity]
        const Icon = config.icon

        return (
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${config.bg}`}>
                <Icon className={`h-4 w-4 ${config.text}`} />
                <span className={`font-semibold ${config.text}`}>{count}</span>
                <span className="text-xs text-muted-foreground">{config.label}</span>
            </div>
        )
    }

    const groupServersByEnvironment = (servers: { url: string }[]) => {
        const groups = { production: [] as string[], staging: [] as string[], development: [] as string[], other: [] as string[] }

        servers.forEach(s => {
            const url = s.url.toLowerCase()
            if (url.includes('prod') || (url.includes('api.') && !url.includes('dev') && !url.includes('stage') && !url.includes('test'))) {
                groups.production.push(s.url)
            } else if (url.includes('stage')) {
                groups.staging.push(s.url)
            } else if (url.includes('dev') || url.includes('test') || url.includes('qa')) {
                groups.development.push(s.url)
            } else {
                groups.other.push(s.url)
            }
        })

        return groups
    }

    // =========================================================================
    // Loading State
    // =========================================================================

    if (loading) {
        return (
            <div className="flex h-64 items-center justify-center">
                <div className="flex flex-col items-center gap-4">
                    <Loader2 className="h-10 w-10 animate-spin text-primary" />
                    <p className="text-muted-foreground">Loading API Audit data...</p>
                </div>
            </div>
        )
    }

    if (error) {
        return (
            <div className="flex h-64 items-center justify-center">
                <Card className="max-w-md">
                    <CardContent className="flex flex-col items-center gap-4 pt-6">
                        <ShieldAlert className="h-12 w-12 text-muted-foreground" />
                        <p className="text-center text-muted-foreground">{error}</p>
                        <Button variant="outline" onClick={fetchAuditData}>
                            Retry
                        </Button>
                    </CardContent>
                </Card>
            </div>
        )
    }

    if (!auditData) {
        return (
            <div className="flex h-64 items-center justify-center">
                <Card className="max-w-md">
                    <CardContent className="flex flex-col items-center gap-4 pt-6">
                        <FileCode2 className="h-12 w-12 text-muted-foreground" />
                        <p className="text-center text-muted-foreground">
                            No API audit data available. Run an API scan to discover endpoints.
                        </p>
                    </CardContent>
                </Card>
            </div>
        )
    }

    const serverGroups = groupServersByEnvironment(auditData.servers || [])
    const totalCredentials =
        (auditData.credentials?.high?.length || 0) +
        (auditData.credentials?.medium?.length || 0) +
        (auditData.credentials?.low?.length || 0)

    // =========================================================================
    // Main Render
    // =========================================================================

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight">API Security Audit</h2>
                    <p className="text-muted-foreground">
                        Discovered APIs, credentials, and security findings from static analysis.
                    </p>
                </div>

                {/* Download Button */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="outline" className="gap-2">
                            <Download className="h-4 w-4" />
                            Download Spec
                            <ChevronDown className="h-4 w-4" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => handleDownload("yaml")}>
                            <FileCode2 className="h-4 w-4 mr-2" />
                            OpenAPI (YAML)
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleDownload("json")}>
                            <FileJson className="h-4 w-4 mr-2" />
                            OpenAPI (JSON)
                        </DropdownMenuItem>
                    </DropdownMenuContent>
                </DropdownMenu>
            </div>

            {/* Tabs */}
            <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
                <TabsList className="grid w-full max-w-md grid-cols-2">
                    <TabsTrigger value="results" className="gap-2">
                        <Shield className="h-4 w-4" />
                        Results
                    </TabsTrigger>
                    <TabsTrigger value="swagger" className="gap-2">
                        <Zap className="h-4 w-4" />
                        SwaggerUI
                    </TabsTrigger>
                </TabsList>

                {/* ============================================================ */}
                {/* RESULTS TAB */}
                {/* ============================================================ */}
                <TabsContent value="results" className="space-y-6">

                    {/* Executive Summary Cards */}
                    <div className="grid gap-4 md:grid-cols-4">
                        <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
                            <CardHeader className="pb-2">
                                <div className="flex items-center justify-between">
                                    <CardDescription className="flex items-center gap-2">
                                        <Globe className="h-4 w-4" />
                                        Inbound APIs
                                    </CardDescription>
                                    <DownloadControl
                                        data={auditData.inbound_endpoints}
                                        defaultFilename="inbound-apis"
                                        buttonLabel=""
                                        columns={[
                                            { key: "path", label: "Path/URI" },
                                            { key: "message", label: "Description" },
                                            { key: "rule_id", label: "Rule ID" },
                                            { key: "line", label: "Line Number", formatter: (r) => r.line?.toString() || "" }
                                        ]}
                                    />
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="text-3xl font-bold">{auditData.inbound_endpoints.length}</div>
                                <p className="text-xs text-muted-foreground">APIs this project serves</p>
                            </CardContent>
                        </Card>

                        <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/20">
                            <CardHeader className="pb-2">
                                <div className="flex items-center justify-between">
                                    <CardDescription className="flex items-center gap-2">
                                        <Upload className="h-4 w-4" />
                                        Outbound APIs
                                    </CardDescription>
                                    <DownloadControl
                                        data={auditData.outbound_endpoints}
                                        defaultFilename="outbound-apis"
                                        buttonLabel=""
                                        columns={[
                                            { key: "path", label: "Path/URI", formatter: (r) => r.endpoint_path || r.path },
                                            { key: "message", label: "Description" },
                                            { key: "rule_id", label: "Rule ID" },
                                            { key: "metadata.category", label: "Category", formatter: (r) => r.metadata?.category || "" }
                                        ]}
                                    />
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="text-3xl font-bold">{auditData.outbound_endpoints.length}</div>
                                <p className="text-xs text-muted-foreground">External APIs consumed</p>
                            </CardContent>
                        </Card>

                        <Card className="bg-gradient-to-br from-green-500/10 to-green-600/5 border-green-500/20">
                            <CardHeader className="pb-2">
                                <div className="flex items-center justify-between">
                                    <CardDescription className="flex items-center gap-2">
                                        <Server className="h-4 w-4" />
                                        API Servers
                                    </CardDescription>
                                    <DownloadControl
                                        data={auditData.servers || []}
                                        defaultFilename="api-servers"
                                        buttonLabel=""
                                        columns={[
                                            { key: "url", label: "Server URL" },
                                            { key: "description", label: "Description" }
                                        ]}
                                    />
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="text-3xl font-bold">{auditData.servers?.length || 0}</div>
                                <p className="text-xs text-muted-foreground">Discovered server URLs</p>
                            </CardContent>
                        </Card>

                        <Card className="bg-gradient-to-br from-orange-500/10 to-orange-600/5 border-orange-500/20">
                            <CardHeader className="pb-2">
                                <div className="flex items-center justify-between">
                                    <CardDescription className="flex items-center gap-2">
                                        <Key className="h-4 w-4" />
                                        Credentials
                                    </CardDescription>
                                    <DownloadControl
                                        data={[
                                            ...(auditData.credentials?.high || []).map(c => ({ ...c, severity: 'HIGH' })),
                                            ...(auditData.credentials?.medium || []).map(c => ({ ...c, severity: 'MEDIUM' })),
                                            ...(auditData.credentials?.low || []).map(c => ({ ...c, severity: 'LOW' }))
                                        ]}
                                        defaultFilename="security-credentials"
                                        buttonLabel=""
                                        columns={[
                                            { key: "type", label: "Type" },
                                            { key: "severity", label: "Severity" },
                                            { key: "environment", label: "Environment" },
                                            { key: "file", label: "File" },
                                            { key: "code", label: "Code Snippet" }
                                        ]}
                                    />
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="text-3xl font-bold">{totalCredentials}</div>
                                <p className="text-xs text-muted-foreground">Hardcoded secrets found</p>
                            </CardContent>
                        </Card>
                    </div>

                    {/* ============================================================ */}
                    {/* AI CORRELATION SECTIONS */}
                    {/* ============================================================ */}

                    {/* AI Inbound Target URL Mapping */}
                    {inboundCorrelations.length > 0 && (
                        <Card className="overflow-hidden">
                            <CardHeader className="pb-3">
                                <div className="flex items-center gap-3">
                                    <Globe className="h-5 w-5 text-cyan-500" />
                                    <div>
                                        <CardTitle className="text-lg flex items-center gap-2">
                                            Inbound API Target URLs
                                            <Badge variant="outline" className="text-[10px] bg-cyan-500/10 text-cyan-600 border-cyan-500/30">
                                                AI Agent
                                            </Badge>
                                        </CardTitle>
                                        <CardDescription>AI-powered correlation of inbound endpoints to server URLs</CardDescription>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="rounded-lg border border-cyan-500/30 bg-gradient-to-r from-cyan-500/5 to-blue-500/5 p-4">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Zap className="h-4 w-4 text-cyan-500" />
                                        <h4 className="font-semibold text-sm">AI Target URL Mapping</h4>
                                    </div>
                                    <div className="rounded-lg border overflow-hidden">
                                        <table className="w-full text-sm">
                                            <thead className="bg-muted/50">
                                                <tr>
                                                    <th className="px-4 py-2 text-left font-medium">Endpoint</th>
                                                    <th className="px-4 py-2 text-left font-medium">Target URL</th>
                                                    <th className="px-4 py-2 text-center font-medium w-24">Confidence</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {inboundCorrelations.slice(0, 5).map((corr, i) => (
                                                    <tr key={`inbound-${corr.endpoint?.path}-${corr.endpoint?.method}-${i}`} className="border-t hover:bg-muted/30">
                                                        <td className="px-4 py-2">
                                                            <div className="flex items-center gap-2">
                                                                <Badge variant="outline" className="text-xs">{corr.endpoint.method}</Badge>
                                                                <span className="font-mono text-xs">{corr.endpoint.path}</span>
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-2">
                                                            <a href={corr.target_url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-500 hover:underline font-mono truncate block max-w-xs">
                                                                {corr.target_url}
                                                            </a>
                                                        </td>
                                                        <td className="px-4 py-2 text-center">
                                                            <div className="flex items-center justify-center gap-1">
                                                                <div className={`h-2 w-2 rounded-full ${corr.confidence >= 70 ? 'bg-green-500' : corr.confidence >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`} />
                                                                <span className={`text-xs font-medium ${corr.confidence >= 70 ? 'text-green-600' : corr.confidence >= 40 ? 'text-yellow-600' : 'text-red-600'}`}>
                                                                    {corr.confidence}%
                                                                </span>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                    {inboundCorrelations.length > 5 && (
                                        <p className="text-xs text-muted-foreground mt-2">
                                            +{inboundCorrelations.length - 5} more correlations
                                        </p>
                                    )}
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* AI Outbound Target URL Mapping */}
                    {outboundCorrelations.length > 0 && (
                        <Card className="overflow-hidden">
                            <CardHeader className="pb-3">
                                <div className="flex items-center gap-3">
                                    <Upload className="h-5 w-5 text-purple-500" />
                                    <div>
                                        <CardTitle className="text-lg flex items-center gap-2">
                                            Outbound API Target URLs
                                            <Badge variant="outline" className="text-[10px] bg-purple-500/10 text-purple-600 border-purple-500/30">
                                                AI Agent
                                            </Badge>
                                        </CardTitle>
                                        <CardDescription>AI-powered correlation of outbound API calls to target servers</CardDescription>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="rounded-lg border border-purple-500/30 bg-gradient-to-r from-purple-500/5 to-pink-500/5 p-4">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Zap className="h-4 w-4 text-purple-500" />
                                        <h4 className="font-semibold text-sm">AI Target URL Mapping</h4>
                                    </div>
                                    <div className="rounded-lg border overflow-hidden">
                                        <table className="w-full text-sm">
                                            <thead className="bg-muted/50">
                                                <tr>
                                                    <th className="px-4 py-2 text-left font-medium">Code Snippet</th>
                                                    <th className="px-4 py-2 text-left font-medium">Target URL</th>
                                                    <th className="px-4 py-2 text-center font-medium w-24">Confidence</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {outboundCorrelations.slice(0, 5).map((corr, i) => (
                                                    <tr key={`outbound-${corr.external_url}-${i}`} className="border-t hover:bg-muted/30">
                                                        <td className="px-4 py-2">
                                                            <code className="text-xs bg-muted px-2 py-1 rounded font-mono truncate block max-w-xs">
                                                                {corr.endpoint.code.length > 60 ? corr.endpoint.code.slice(0, 60) + '...' : corr.endpoint.code}
                                                            </code>
                                                        </td>
                                                        <td className="px-4 py-2">
                                                            <a href={corr.target_url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-500 hover:underline font-mono truncate block max-w-xs">
                                                                {corr.target_url}
                                                            </a>
                                                        </td>
                                                        <td className="px-4 py-2 text-center">
                                                            <div className="flex items-center justify-center gap-1">
                                                                <div className={`h-2 w-2 rounded-full ${corr.confidence >= 70 ? 'bg-green-500' : corr.confidence >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`} />
                                                                <span className={`text-xs font-medium ${corr.confidence >= 70 ? 'text-green-600' : corr.confidence >= 40 ? 'text-yellow-600' : 'text-red-600'}`}>
                                                                    {corr.confidence}%
                                                                </span>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                    {outboundCorrelations.length > 5 && (
                                        <p className="text-xs text-muted-foreground mt-2">
                                            +{outboundCorrelations.length - 5} more correlations
                                        </p>
                                    )}
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* AI Server-Credential Mapping */}
                    {serverCredCorrelations.length > 0 && (
                        <Card className="overflow-hidden">
                            <CardHeader className="pb-3">
                                <div className="flex items-center gap-3">
                                    <Server className="h-5 w-5 text-green-500" />
                                    <div>
                                        <CardTitle className="text-lg flex items-center gap-2">
                                            Server-Credential Mapping
                                            <Badge variant="outline" className="text-[10px] bg-green-500/10 text-green-600 border-green-500/30">
                                                AI Agent
                                            </Badge>
                                        </CardTitle>
                                        <CardDescription>AI-powered correlation of servers with their associated credentials</CardDescription>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="rounded-lg border border-green-500/30 bg-gradient-to-r from-green-500/5 to-emerald-500/5 p-4">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Zap className="h-4 w-4 text-green-500" />
                                        <h4 className="font-semibold text-sm">AI Server-Credential Mapping</h4>
                                    </div>
                                    <div className="space-y-3">
                                        {serverCredCorrelations.slice(0, 5).map((corr, i) => (
                                            <div key={i} className="rounded-lg border bg-background p-3">
                                                <div className="flex items-center gap-2 mb-2">
                                                    <Globe className="h-4 w-4 text-green-500" />
                                                    <a href={corr.server.url} target="_blank" rel="noopener noreferrer" className="text-sm text-blue-500 hover:underline font-mono">
                                                        {corr.server.url}
                                                    </a>
                                                    <Badge variant="outline" className="text-xs">{corr.server.environment}</Badge>
                                                </div>
                                                <div className="flex flex-wrap gap-2">
                                                    {corr.credentials.slice(0, 5).map((cred, j) => (
                                                        <div key={j} className="flex items-center gap-1 text-xs bg-muted px-2 py-1 rounded">
                                                            <Key className="h-3 w-3" />
                                                            <span>{cred.credential.type}</span>
                                                            <span className={`${cred.confidence >= 70 ? 'text-green-600' : cred.confidence >= 40 ? 'text-yellow-600' : 'text-red-600'}`}>
                                                                ({cred.confidence}%)
                                                            </span>
                                                        </div>
                                                    ))}
                                                    {corr.credentials.length > 5 && (
                                                        <span className="text-xs text-muted-foreground">+{corr.credentials.length - 5} more</span>
                                                    )}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                    {serverCredCorrelations.length > 5 && (
                                        <p className="text-xs text-muted-foreground mt-2">
                                            +{serverCredCorrelations.length - 5} more servers
                                        </p>
                                    )}
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* Swagger Server Credentials - For Connection Testing */}
                    {swaggerServerCredentials.length > 0 && (
                        <Collapsible open={expandedSections.has("swagger-server-credentials")} onOpenChange={() => toggleSection("swagger-server-credentials")}>
                            <Card className="overflow-hidden border-green-500/30">
                                <CollapsibleTrigger asChild>
                                    <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors pb-3">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <Globe className="h-5 w-5 text-green-500" />
                                                <div>
                                                    <CardTitle className="text-lg flex items-center gap-2">
                                                        Server Credentials for Testing
                                                        <Badge variant="outline" className="text-[10px] bg-green-500/10 text-green-600 border-green-500/30">
                                                            API Discovery
                                                        </Badge>
                                                    </CardTitle>
                                                    <CardDescription>Discovered servers from SwaggerUI with matched credentials for connection testing</CardDescription>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                <Badge variant="secondary">{swaggerServerCredentials.length} servers</Badge>
                                                {expandedSections.has("swagger-server-credentials") ? <ChevronDown className="h-5 w-5" /> : <ChevronRight className="h-5 w-5" />}
                                            </div>
                                        </div>
                                    </CardHeader>
                                </CollapsibleTrigger>
                                <CollapsibleContent>
                                    <CardContent>
                                        <div className="rounded-lg border border-green-500/30 bg-gradient-to-r from-green-500/5 to-emerald-500/5 p-4">
                                            <div className="flex items-center gap-2 mb-3">
                                                <Zap className="h-4 w-4 text-green-500" />
                                                <h4 className="font-semibold text-sm">Swagger Server → Credential Mapping</h4>
                                                <span className="text-xs text-muted-foreground">(Use these for API connection testing)</span>
                                            </div>
                                            <div className="space-y-4">
                                                {swaggerServerCredentials.map((server, i) => (
                                                    <div key={i} className="rounded-lg border bg-background p-4">
                                                        <div className="flex items-center justify-between mb-3">
                                                            <div className="flex items-center gap-2">
                                                                <Globe className="h-4 w-4 text-green-500" />
                                                                <a href={server.server_url} target="_blank" rel="noopener noreferrer" className="text-sm text-blue-500 hover:underline font-mono">
                                                                    {server.server_url}
                                                                </a>
                                                                <Badge variant="outline" className="text-xs">{server.server_environment}</Badge>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <Badge variant="secondary" className="text-xs">{server.credential_count} credentials</Badge>
                                                                {server.top_confidence >= 70 && (
                                                                    <Badge className="text-xs bg-green-500">High Match</Badge>
                                                                )}
                                                            </div>
                                                        </div>
                                                        {server.server_description && (
                                                            <p className="text-xs text-muted-foreground mb-2">{server.server_description}</p>
                                                        )}
                                                        {server.credentials.length > 0 ? (
                                                            <div className="rounded-lg border overflow-hidden">
                                                                <table className="w-full text-sm">
                                                                    <thead className="bg-muted/50">
                                                                        <tr>
                                                                            <th className="px-3 py-2 text-left font-medium text-xs">Credential Type</th>
                                                                            <th className="px-3 py-2 text-left font-medium text-xs">Value</th>
                                                                            <th className="px-3 py-2 text-left font-medium text-xs">Environment</th>
                                                                            <th className="px-3 py-2 text-center font-medium text-xs w-20">Confidence</th>
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody>
                                                                        {server.credentials.map((cred, j) => (
                                                                            <tr key={j} className="border-t hover:bg-muted/30">
                                                                                <td className="px-3 py-2">
                                                                                    <Badge variant="outline" className="text-xs">{cred.credential_type}</Badge>
                                                                                </td>
                                                                                <td className="px-3 py-2">
                                                                                    <code className="text-xs bg-muted px-2 py-1 rounded font-mono truncate block max-w-[200px]">
                                                                                        {cred.credential_value}
                                                                                    </code>
                                                                                </td>
                                                                                <td className="px-3 py-2">
                                                                                    <Badge variant="secondary" className="text-xs">{cred.environment || 'unknown'}</Badge>
                                                                                </td>
                                                                                <td className="px-3 py-2 text-center">
                                                                                    <div className="flex items-center justify-center gap-1">
                                                                                        <div className={`h-2 w-2 rounded-full ${cred.confidence >= 70 ? 'bg-green-500' : cred.confidence >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`} />
                                                                                        <span className={`text-xs font-medium ${cred.confidence >= 70 ? 'text-green-600' : cred.confidence >= 40 ? 'text-yellow-600' : 'text-red-600'}`}>
                                                                                            {cred.confidence}%
                                                                                        </span>
                                                                                    </div>
                                                                                </td>
                                                                            </tr>
                                                                        ))}
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        ) : (
                                                            <p className="text-xs text-muted-foreground italic">No matching credentials found for this server</p>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </CardContent>
                                </CollapsibleContent>
                            </Card>
                        </Collapsible>
                    )}

                    {/* AI Credential-URL Mapping */}
                    {credentialUrlCorrelations.length > 0 && (
                        <Collapsible open={expandedSections.has("credential-url-mapping")} onOpenChange={() => toggleSection("credential-url-mapping")}>
                            <Card className="overflow-hidden">
                                <CollapsibleTrigger asChild>
                                    <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors pb-3">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <Key className="h-5 w-5 text-cyan-500" />
                                                <div>
                                                    <CardTitle className="text-lg flex items-center gap-2">
                                                        Credential-URL Mapping
                                                        <Badge variant="outline" className="text-[10px] bg-cyan-500/10 text-cyan-600 border-cyan-500/30">
                                                            AI Agent
                                                        </Badge>
                                                    </CardTitle>
                                                    <CardDescription>AI-powered correlation of credentials to their target URLs</CardDescription>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                <Badge variant="secondary">{credentialUrlCorrelations.length} correlations</Badge>
                                                <DownloadControl
                                                    data={credentialUrlCorrelations.map(c => ({
                                                        url: c.url,
                                                        credential_type: c.credential.type,
                                                        credential_value: c.credential.value,
                                                        environment: c.credential.environment,
                                                        file: c.credential.file,
                                                        confidence: c.confidence,
                                                        match_reasons: c.match_reasons.join(', '),
                                                        llm_enhanced: c.llm_enhanced ? 'Yes' : 'No'
                                                    }))}
                                                    defaultFilename={`${auditData.repository}-credential-url-mapping`}
                                                    buttonLabel=""
                                                    columns={[
                                                        { key: "url", label: "Target URL" },
                                                        { key: "credential_type", label: "Credential Type" },
                                                        { key: "credential_value", label: "Credential Value" },
                                                        { key: "environment", label: "Environment" },
                                                        { key: "file", label: "Source File" },
                                                        { key: "confidence", label: "Confidence %" },
                                                        { key: "match_reasons", label: "Match Reasons" },
                                                        { key: "llm_enhanced", label: "AI Enhanced" }
                                                    ]}
                                                />
                                                {expandedSections.has("credential-url-mapping") ? <ChevronDown className="h-5 w-5" /> : <ChevronRight className="h-5 w-5" />}
                                            </div>
                                        </div>
                                    </CardHeader>
                                </CollapsibleTrigger>
                                <CollapsibleContent>
                                    <CardContent>
                                        <div className="rounded-lg border border-cyan-500/30 bg-gradient-to-r from-cyan-500/5 to-blue-500/5 p-4">
                                            {/* Header with Test All button and Rate Limit selector */}
                                            <div className="flex items-center justify-between mb-4">
                                                <div className="flex items-center gap-2">
                                                    <Zap className="h-4 w-4 text-cyan-500" />
                                                    <h4 className="font-semibold text-sm">AI Credential-URL Mapping</h4>
                                                </div>
                                                <div className="flex items-center gap-3">
                                                    <select 
                                                        value={selectedTestMode}
                                                        onChange={(e) => setSelectedTestMode(e.target.value as 'none' | 'cautious' | 'insane')}
                                                        className="text-xs px-2 py-1 rounded border bg-background"
                                                    >
                                                        <option value="cautious">Cautious (Evasion)</option>
                                                        <option value="none">None (No Limits)</option>
                                                        <option value="insane">Insane (All Off)</option>
                                                    </select>
                                                    <Button 
                                                        size="sm" 
                                                        variant="outline"
                                                        onClick={testAllCredentialUrls}
                                                        disabled={Object.values(testingInProgress).some(v => v)}
                                                        className="text-xs"
                                                    >
                                                        <Play className="h-3 w-3 mr-1" />
                                                        Test All
                                                    </Button>
                                                </div>
                                            </div>
                                            <div className="rounded-lg border overflow-hidden">
                                                <table className="w-full text-sm">
                                                    <thead className="bg-muted/50">
                                                        <tr>
                                                            <th className="px-3 py-2 text-left font-medium">Target URL</th>
                                                            <th className="px-3 py-2 text-left font-medium">Credential Type</th>
                                                            <th className="px-3 py-2 text-left font-medium">Value</th>
                                                            <th className="px-3 py-2 text-center font-medium w-20">Confidence</th>
                                                            <th className="px-3 py-2 text-center font-medium w-24">AuthN/Z</th>
                                                            <th className="px-3 py-2 text-center font-medium w-32">Action</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {credentialUrlCorrelations.map((corr, i) => (
                                                            <tr key={i} className="border-t hover:bg-muted/30">
                                                                <td className="px-3 py-2">
                                                                    <a href={corr.url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-500 hover:underline font-mono truncate block max-w-[200px]" title={corr.url}>
                                                                        {corr.url.length > 40 ? corr.url.slice(0, 40) + '...' : corr.url}
                                                                    </a>
                                                                </td>
                                                                <td className="px-3 py-2">
                                                                    <Badge variant="outline" className="text-xs">{corr.credential.type}</Badge>
                                                                </td>
                                                                <td className="px-3 py-2">
                                                                    <code className="text-xs bg-muted px-2 py-1 rounded font-mono break-all">
                                                                        {corr.credential.value}
                                                                    </code>
                                                                </td>
                                                                <td className="px-3 py-2 text-center">
                                                                    <div className="flex items-center justify-center gap-1">
                                                                        <div className={`h-2 w-2 rounded-full ${corr.confidence >= 70 ? 'bg-green-500' : corr.confidence >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`} />
                                                                        <span className={`text-xs font-medium ${corr.confidence >= 70 ? 'text-green-600' : corr.confidence >= 40 ? 'text-yellow-600' : 'text-red-600'}`}>
                                                                            {corr.confidence}%
                                                                        </span>
                                                                    </div>
                                                                </td>
                                                                <td className="px-3 py-2 text-center">
                                                                    {getAuthStatusBadge(corr.url, corr.credential.type)}
                                                                </td>
                                                                <td className="px-3 py-2">
                                                                    <div className="flex items-center justify-center gap-1">
                                                                        <Button
                                                                            size="sm"
                                                                            variant="ghost"
                                                                            className="h-7 px-2 text-xs"
                                                                            onClick={() => testCredentialUrl(corr.url, corr.credential.type, corr.credential.value, corr.credential.environment, corr.confidence)}
                                                                            disabled={testingInProgress[getCredentialUrlKey(corr.url, corr.credential.type)]}
                                                                            title={credentialTestResults[getCredentialUrlKey(corr.url, corr.credential.type)] ? "Re-test" : "Test"}
                                                                        >
                                                                            {testingInProgress[getCredentialUrlKey(corr.url, corr.credential.type)] ? (
                                                                                <RefreshCw className="h-3 w-3 animate-spin" />
                                                                            ) : credentialTestResults[getCredentialUrlKey(corr.url, corr.credential.type)] ? (
                                                                                <RefreshCw className="h-3 w-3" />
                                                                            ) : (
                                                                                <Play className="h-3 w-3" />
                                                                            )}
                                                                        </Button>
                                                                        <Button
                                                                            size="sm"
                                                                            variant="ghost"
                                                                            className="h-7 px-2 text-xs"
                                                                            onClick={() => openReportModal(corr.url, corr.credential.type)}
                                                                            disabled={!credentialTestResults[getCredentialUrlKey(corr.url, corr.credential.type)]}
                                                                            title="Report"
                                                                        >
                                                                            <FileText className="h-3 w-3" />
                                                                        </Button>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </CardContent>
                                </CollapsibleContent>
                            </Card>
                        </Collapsible>
                    )}

                    {/* Credential Risk Assessment */}
                    {totalCredentials > 0 && (
                        <Collapsible open={expandedSections.has("credentials")} onOpenChange={() => toggleSection("credentials")}>
                            <Card>
                                <CollapsibleTrigger asChild>
                                    <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <ShieldAlert className="h-5 w-5 text-orange-500" />
                                                <div>
                                                    <CardTitle className="text-lg">Hardcoded Credentials Risk Assessment</CardTitle>
                                                    <CardDescription>API keys, tokens, and secrets found in source code</CardDescription>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                <div className="flex gap-2">
                                                    {(auditData.credentials?.high?.length || 0) > 0 && renderSeverityBadge("high", auditData.credentials.high.length)}
                                                    {(auditData.credentials?.medium?.length || 0) > 0 && renderSeverityBadge("medium", auditData.credentials.medium.length)}
                                                    {(auditData.credentials?.low?.length || 0) > 0 && renderSeverityBadge("low", auditData.credentials.low.length)}
                                                </div>
                                                {expandedSections.has("credentials") ? <ChevronDown className="h-5 w-5" /> : <ChevronRight className="h-5 w-5" />}
                                            </div>
                                        </div>
                                    </CardHeader>
                                </CollapsibleTrigger>
                                <CollapsibleContent>
                                    <CardContent className="space-y-6">
                                        {/* High Risk */}
                                        {(auditData.credentials?.high?.length || 0) > 0 && (
                                            <div className="space-y-3">
                                                <div className="flex items-center gap-2">
                                                    <XCircle className="h-4 w-4 text-red-500" />
                                                    <h4 className="font-semibold text-red-500">High Risk</h4>
                                                    <span className="text-xs text-muted-foreground">— May allow infrastructure access or service impersonation</span>
                                                </div>
                                                <div className="rounded-lg border border-red-500/20 bg-red-500/5 overflow-hidden">
                                                    <table className="w-full text-sm">
                                                        <thead className="bg-red-500/10">
                                                            <tr>
                                                                <th className="px-4 py-2 text-left font-medium">Type</th>
                                                                <th className="px-4 py-2 text-left font-medium">Environment</th>
                                                                <th className="px-4 py-2 text-left font-medium">File</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {auditData.credentials.high.slice(0, 10).map((cred, i) => (
                                                                <tr key={`cred-high-${cred.url}-${cred.type}-${i}`} className="border-t border-red-500/10">
                                                                    <td className="px-4 py-2 font-mono text-xs">{cred.type}</td>
                                                                    <td className="px-4 py-2">
                                                                        <Badge variant="outline" className="text-xs">{cred.environment}</Badge>
                                                                    </td>
                                                                    <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{cred.file}</td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>
                                        )}

                                        {/* Medium Risk */}
                                        {(auditData.credentials?.medium?.length || 0) > 0 && (
                                            <div className="space-y-3">
                                                <div className="flex items-center gap-2">
                                                    <AlertTriangle className="h-4 w-4 text-yellow-500" />
                                                    <h4 className="font-semibold text-yellow-500">Medium Risk</h4>
                                                    <span className="text-xs text-muted-foreground">— Allows data injection, analytics pollution, or API abuse</span>
                                                </div>
                                                <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 overflow-hidden">
                                                    <table className="w-full text-sm">
                                                        <thead className="bg-yellow-500/10">
                                                            <tr>
                                                                <th className="px-4 py-2 text-left font-medium">Type</th>
                                                                <th className="px-4 py-2 text-left font-medium">Environment</th>
                                                                <th className="px-4 py-2 text-left font-medium">Attack Vector</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {auditData.credentials.medium.slice(0, 10).map((cred, i) => (
                                                                <tr key={`cred-medium-${cred.url}-${cred.type}-${i}`} className="border-t border-yellow-500/10">
                                                                    <td className="px-4 py-2 font-mono text-xs">{cred.type}</td>
                                                                    <td className="px-4 py-2">
                                                                        <Badge variant="outline" className="text-xs">{cred.environment}</Badge>
                                                                    </td>
                                                                    <td className="px-4 py-2 text-xs text-muted-foreground">{cred.attack_vector || "API abuse, data injection"}</td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>
                                        )}

                                        {/* Low Risk */}
                                        {(auditData.credentials?.low?.length || 0) > 0 && (
                                            <div className="space-y-3">
                                                <div className="flex items-center gap-2">
                                                    <CheckCircle2 className="h-4 w-4 text-green-500" />
                                                    <h4 className="font-semibold text-green-500">Low Risk</h4>
                                                    <span className="text-xs text-muted-foreground">— Public OAuth client IDs, useful for API reconnaissance</span>
                                                </div>
                                                <p className="text-sm text-muted-foreground">
                                                    Found {auditData.credentials.low.length} OAuth client IDs (Cognito, etc.) — typically public but confirm API surface.
                                                </p>
                                            </div>
                                        )}
                                    </CardContent>
                                </CollapsibleContent>
                            </Card>
                        </Collapsible>
                    )}

                    {/* Discovered API Servers */}
                    {(auditData.servers?.length || 0) > 0 && (
                        <Collapsible open={expandedSections.has("servers")} onOpenChange={() => toggleSection("servers")}>
                            <Card>
                                <CollapsibleTrigger asChild>
                                    <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <Server className="h-5 w-5 text-green-500" />
                                                <div>
                                                    <CardTitle className="text-lg">Discovered API Servers</CardTitle>
                                                    <CardDescription>Server URLs extracted from configuration files</CardDescription>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                <Badge variant="secondary">{auditData.servers.length} servers</Badge>
                                                {expandedSections.has("servers") ? <ChevronDown className="h-5 w-5" /> : <ChevronRight className="h-5 w-5" />}
                                            </div>
                                        </div>
                                    </CardHeader>
                                </CollapsibleTrigger>
                                <CollapsibleContent>
                                    <CardContent>
                                        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                                            {serverGroups.production.length > 0 && (
                                                <div className="space-y-2">
                                                    <h4 className="font-semibold text-sm flex items-center gap-2">
                                                        <div className="h-2 w-2 rounded-full bg-green-500" />
                                                        Production ({serverGroups.production.length})
                                                    </h4>
                                                    <div className="space-y-1">
                                                        {serverGroups.production.slice(0, 5).map((url, i) => (
                                                            <div key={i} className="flex items-center gap-2 text-xs font-mono bg-muted/50 px-2 py-1 rounded">
                                                                <Globe className="h-3 w-3 flex-shrink-0" />
                                                                <span className="truncate">{url}</span>
                                                            </div>
                                                        ))}
                                                        {serverGroups.production.length > 5 && (
                                                            <p className="text-xs text-muted-foreground">...and {serverGroups.production.length - 5} more</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {serverGroups.staging.length > 0 && (
                                                <div className="space-y-2">
                                                    <h4 className="font-semibold text-sm flex items-center gap-2">
                                                        <div className="h-2 w-2 rounded-full bg-yellow-500" />
                                                        Staging ({serverGroups.staging.length})
                                                    </h4>
                                                    <div className="space-y-1">
                                                        {serverGroups.staging.slice(0, 5).map((url, i) => (
                                                            <div key={i} className="flex items-center gap-2 text-xs font-mono bg-muted/50 px-2 py-1 rounded">
                                                                <Globe className="h-3 w-3 flex-shrink-0" />
                                                                <span className="truncate">{url}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}

                                            {serverGroups.development.length > 0 && (
                                                <div className="space-y-2">
                                                    <h4 className="font-semibold text-sm flex items-center gap-2">
                                                        <div className="h-2 w-2 rounded-full bg-blue-500" />
                                                        Development/QA ({serverGroups.development.length})
                                                    </h4>
                                                    <div className="space-y-1">
                                                        {serverGroups.development.slice(0, 5).map((url, i) => (
                                                            <div key={i} className="flex items-center gap-2 text-xs font-mono bg-muted/50 px-2 py-1 rounded">
                                                                <Globe className="h-3 w-3 flex-shrink-0" />
                                                                <span className="truncate">{url}</span>
                                                            </div>
                                                        ))}
                                                        {serverGroups.development.length > 5 && (
                                                            <p className="text-xs text-muted-foreground">...and {serverGroups.development.length - 5} more</p>
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </CardContent>
                                </CollapsibleContent>
                            </Card>
                        </Collapsible>
                    )}

                    {/* Configuration Sources */}
                    {(auditData.fingerprint?.config_sources?.length || 0) > 0 && (
                        <Card>
                            <CardHeader>
                                <div className="flex items-center gap-3">
                                    <FolderOpen className="h-5 w-5 text-blue-500" />
                                    <div>
                                        <CardTitle className="text-lg">Configuration Sources</CardTitle>
                                        <CardDescription>Files where API configuration was discovered</CardDescription>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="flex flex-wrap gap-2">
                                    {auditData.fingerprint.config_sources.map((source, i) => (
                                        <Badge key={i} variant="secondary" className="font-mono text-xs">
                                            {source}
                                        </Badge>
                                    ))}
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </TabsContent>

                {/* ============================================================ */}
                {/* SWAGGER UI TAB */}
                {/* ============================================================ */}
                <TabsContent value="swagger" className="space-y-4">
                    <Card className="overflow-hidden">
                        <CardHeader className="bg-muted/30 border-b">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <Zap className="h-5 w-5 text-primary" />
                                    <div>
                                        <CardTitle className="text-lg">Interactive API Explorer</CardTitle>
                                        <CardDescription>Test and inspect API endpoints using SwaggerUI</CardDescription>
                                    </div>
                                </div>
                                <div className="flex gap-2">
                                    <Button
                                        variant="default"
                                        size="sm"
                                        onClick={() => window.open(`${API_BASE}/projects/${projectId}/api-audit/server-testing`, '_blank')}
                                    >
                                        🔍 API Discovery
                                    </Button>
                                </div>
                            </div>
                        </CardHeader>
                        <CardContent className="p-4">
                            {swaggerFiles.length > 0 ? (
                                <div className="rounded-lg border overflow-hidden">
                                    <table className="w-full">
                                        <thead className="bg-muted/50">
                                            <tr>
                                                <th className="text-left p-3 font-medium text-sm">Server Path</th>
                                                <th className="text-center p-3 font-medium text-sm w-24">OpenAPI</th>
                                                <th className="text-center p-3 font-medium text-sm w-24">Swagger</th>
                                                <th className="text-center p-3 font-medium text-sm w-32">Action</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {swaggerFiles.map((file, idx) => (
                                                <tr key={idx} className="border-t hover:bg-muted/30">
                                                    <td className="p-3">
                                                        <div className="flex flex-col">
                                                            <span className="font-mono text-sm truncate max-w-md" title={file.server_url}>
                                                                {file.server_url || file.name}
                                                            </span>
                                                            <span className="text-xs text-muted-foreground">
                                                                {file.path_count} endpoint{file.path_count !== 1 ? 's' : ''}
                                                            </span>
                                                        </div>
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        {file.json_file && (
                                                            <Button
                                                                variant="outline"
                                                                size="sm"
                                                                onClick={() => window.open(`${API_BASE}/projects/${projectId}/api-audit/swagger-file/${file.json_file}`, '_blank')}
                                                                title="Download JSON"
                                                            >
                                                                <Download className="h-4 w-4" />
                                                                <span className="ml-1 text-xs">JSON</span>
                                                            </Button>
                                                        )}
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        <Button
                                                            variant="outline"
                                                            size="sm"
                                                            onClick={() => window.open(`${API_BASE}/projects/${projectId}/api-audit/swagger-file/${file.yaml_file}`, '_blank')}
                                                            title="Download YAML"
                                                        >
                                                            <Download className="h-4 w-4" />
                                                            <span className="ml-1 text-xs">YAML</span>
                                                        </Button>
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        <Button
                                                            variant="default"
                                                            size="sm"
                                                            onClick={() => setSwaggerModalUrl(`${API_BASE}/projects/${projectId}/api-audit/swagger-file/${file.json_file || file.yaml_file}`)}
                                                        >
                                                            <ExternalLink className="h-4 w-4 mr-1" />
                                                            SwaggerUI
                                                        </Button>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            ) : (
                                <div className="flex flex-col items-center justify-center h-48 text-center">
                                    <FileCode2 className="h-12 w-12 text-muted-foreground mb-4" />
                                    <p className="text-muted-foreground">
                                        No Swagger specifications available.
                                    </p>
                                    <p className="text-sm text-muted-foreground mt-2">
                                        Use API Discovery to generate swagger files for each server.
                                    </p>
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        className="mt-4"
                                        onClick={() => window.open(`${API_BASE}/projects/${projectId}/api-audit/server-testing`, '_blank')}
                                    >
                                        🔍 Open API Discovery
                                    </Button>
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {/* AI Matched Credentials */}
                    <Card className="overflow-hidden">
                        <CardHeader className="bg-muted/30 border-b py-3">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <Key className="h-4 w-4 text-primary" />
                                    <CardTitle className="text-base">AI-Matched Credentials</CardTitle>
                                    {matchedCredentials.filter(c => c.certainty >= 80).length > 0 && (
                                        <Badge variant="secondary" className="ml-2">
                                            {matchedCredentials.filter(c => c.certainty >= 80).length} high confidence
                                        </Badge>
                                    )}
                                </div>
                                {matchedCredentials.length > 3 && (
                                    <Button variant="outline" size="sm" onClick={() => setCredentialsModalOpen(true)}>
                                        View All ({matchedCredentials.length})
                                    </Button>
                                )}
                            </div>
                        </CardHeader>
                        <CardContent className="p-4">
                            {matchedCredentials.filter(c => c.certainty >= 80).length > 0 ? (
                                <div className="rounded-lg border overflow-hidden">
                                    <table className="w-full">
                                        <thead className="bg-muted/50">
                                            <tr>
                                                <th className="text-left p-3 font-medium text-sm">Service</th>
                                                <th className="text-left p-3 font-medium text-sm">Type</th>
                                                <th className="text-left p-3 font-medium text-sm">Value</th>
                                                <th className="text-center p-3 font-medium text-sm w-24">Certainty</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {matchedCredentials.filter(c => c.certainty >= 80).slice(0, 3).map((cred, idx) => (
                                                <tr key={idx} className="border-t hover:bg-muted/30">
                                                    <td className="p-3">
                                                        <span className="font-medium">{cred.service}</span>
                                                    </td>
                                                    <td className="p-3">
                                                        <Badge variant="outline">{cred.type}</Badge>
                                                    </td>
                                                    <td className="p-3">
                                                        <code className="text-xs bg-muted px-2 py-1 rounded font-mono break-all">
                                                            {cred.value}
                                                        </code>
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        <Badge className={cred.certainty >= 90 ? 'bg-green-500' : cred.certainty >= 80 ? 'bg-yellow-500' : 'bg-gray-500'}>
                                                            {cred.certainty}%
                                                        </Badge>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            ) : (
                                <div className="flex flex-col items-center justify-center h-24 text-center">
                                    <p className="text-muted-foreground text-sm">
                                        No high-confidence credential matches found.
                                    </p>
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {/* Credentials Modal */}
                    {credentialsModalOpen && (
                        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
                            <div className="bg-white dark:bg-black rounded-lg w-full max-w-4xl max-h-[80vh] flex flex-col overflow-hidden shadow-2xl border dark:border-zinc-800">
                                <div className="flex items-center justify-between p-4 border-b">
                                    <h2 className="text-lg font-semibold">All Matched Credentials ({matchedCredentials.length})</h2>
                                    <Button variant="ghost" size="sm" onClick={() => setCredentialsModalOpen(false)}>
                                        <XCircle className="h-5 w-5" />
                                    </Button>
                                </div>
                                <div className="flex-1 overflow-auto p-4">
                                    <table className="w-full">
                                        <thead className="bg-muted/50 sticky top-0">
                                            <tr>
                                                <th className="text-left p-3 font-medium text-sm">Service</th>
                                                <th className="text-left p-3 font-medium text-sm">Type</th>
                                                <th className="text-left p-3 font-medium text-sm">Value</th>
                                                <th className="text-center p-3 font-medium text-sm w-24">Certainty</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {matchedCredentials.map((cred, idx) => (
                                                <tr key={idx} className="border-t hover:bg-muted/30">
                                                    <td className="p-3">
                                                        <span className="font-medium">{cred.service}</span>
                                                    </td>
                                                    <td className="p-3">
                                                        <Badge variant="outline">{cred.type}</Badge>
                                                    </td>
                                                    <td className="p-3">
                                                        <code className="text-xs bg-muted px-2 py-1 rounded font-mono break-all">
                                                            {cred.value}
                                                        </code>
                                                    </td>
                                                    <td className="p-3 text-center">
                                                        <Badge className={cred.certainty >= 90 ? 'bg-green-500' : cred.certainty >= 80 ? 'bg-yellow-500' : 'bg-gray-500'}>
                                                            {cred.certainty}%
                                                        </Badge>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    )}
                </TabsContent>
            </Tabs>

            {/* SwaggerUI Modal - outside TabsContent for proper z-index */}
            {swaggerModalUrl && (
                <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
                    <div className="bg-white dark:bg-black rounded-lg w-full max-w-6xl h-[90vh] flex flex-col overflow-hidden shadow-2xl border dark:border-zinc-800">
                        <div className="flex items-center justify-between p-4 border-b">
                            <h2 className="text-lg font-semibold">SwaggerUI</h2>
                            <Button variant="ghost" size="sm" onClick={() => setSwaggerModalUrl(null)}>
                                <XCircle className="h-5 w-5" />
                            </Button>
                        </div>
                        <div className="flex-1 overflow-hidden">
                            <iframe
                                src={`${API_BASE}/projects/${projectId}/api-audit/swagger?spec_url=${encodeURIComponent(swaggerModalUrl)}`}
                                className="w-full h-full border-0"
                                title="SwaggerUI"
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* Credential-URL Test Report Modal - outside TabsContent for proper z-index */}
            {reportModalOpen && selectedReportResult && (
                <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
                    <div className="bg-white dark:bg-zinc-900 rounded-lg w-[80vw] max-w-5xl h-[85vh] flex flex-col overflow-hidden shadow-2xl border dark:border-zinc-700">
                        {/* Modal Header - Fixed */}
                        <div className="flex-shrink-0 flex items-center justify-between p-4 border-b bg-gradient-to-r from-cyan-500/10 to-blue-500/10">
                            <div className="flex items-center gap-3">
                                <FileText className="h-5 w-5 text-cyan-500" />
                                <div>
                                    <h2 className="text-lg font-semibold">Credential-URL Test Report</h2>
                                    <p className="text-xs text-muted-foreground font-mono truncate max-w-[500px]">{selectedReportResult.target_url}</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                <Button 
                                    variant="outline" 
                                    size="sm" 
                                    onClick={() => {
                                        setDownloadFilename(`credential_url_report_${selectedReportResult.id?.slice(0, 8)}`)
                                        setDownloadModalOpen(true)
                                    }}
                                >
                                    <Download className="h-4 w-4 mr-1" />
                                    Download
                                </Button>
                                <Button variant="ghost" size="sm" onClick={() => setReportModalOpen(false)}>
                                    <X className="h-5 w-5" />
                                </Button>
                            </div>
                        </div>
                        
                        {/* Modal Content - Scrollable with native scroll */}
                        <div className="flex-1 overflow-y-auto p-6">
                            <div className="space-y-6 max-w-4xl mx-auto">
                                {/* Overview Section */}
                                <div className="rounded-lg border p-4 bg-gradient-to-r from-blue-500/5 to-purple-500/5">
                                    <h3 className="font-semibold mb-2 flex items-center gap-2">
                                        <Zap className="h-4 w-4 text-blue-500" />
                                        Overview
                                    </h3>
                                    <p className="text-sm text-muted-foreground leading-relaxed">
                                        {selectedReportResult.ai_overview || 'No overview available.'}
                                    </p>
                                    {selectedReportResult.threat_level && (
                                        <div className="mt-3 flex items-center gap-2">
                                            <span className="text-xs font-medium">Risk Level:</span>
                                            <Badge className={`text-xs ${
                                                selectedReportResult.threat_level === 'critical' ? 'bg-red-600' :
                                                selectedReportResult.threat_level === 'high' ? 'bg-orange-500' :
                                                selectedReportResult.threat_level === 'medium' ? 'bg-yellow-500' :
                                                selectedReportResult.threat_level === 'low' ? 'bg-blue-500' : 'bg-gray-500'
                                            }`}>
                                                {selectedReportResult.threat_level.toUpperCase()}
                                            </Badge>
                                        </div>
                                    )}
                                </div>

                                {/* Authentication Status */}
                                <div className="rounded-lg border p-4">
                                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                                        <Key className="h-4 w-4 text-green-500" />
                                        Authentication Status
                                    </h3>
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                                        <div>
                                            <span className="text-muted-foreground">Status</span>
                                            <div className="font-medium mt-1">
                                                <Badge className={selectedReportResult.auth_status === 'yes' ? 'bg-green-500' : 'bg-red-500'}>
                                                    {selectedReportResult.auth_status === 'yes' ? 'Authenticated' : 'Failed'}
                                                </Badge>
                                            </div>
                                        </div>
                                        <div>
                                            <span className="text-muted-foreground">HTTP Code</span>
                                            <div className="font-medium mt-1">{selectedReportResult.auth_status_code || 'N/A'}</div>
                                        </div>
                                        <div>
                                            <span className="text-muted-foreground">Response Time</span>
                                            <div className="font-medium mt-1">{selectedReportResult.auth_response_time_ms}ms</div>
                                        </div>
                                        <div>
                                            <span className="text-muted-foreground">Credential Type</span>
                                            <div className="font-medium mt-1">{selectedReportResult.credential_type}</div>
                                        </div>
                                    </div>
                                    {selectedReportResult.auth_error_message && (
                                        <div className="mt-3 text-sm text-red-500">
                                            Error: {selectedReportResult.auth_error_message}
                                        </div>
                                    )}
                                </div>

                                {/* Raw Request/Response Section */}
                                <div className="rounded-lg border p-4 bg-gradient-to-r from-slate-500/5 to-zinc-500/5">
                                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                                        <Code className="h-4 w-4 text-slate-500" />
                                        Raw HTTP Request & Response
                                    </h3>
                                    
                                    <div className="space-y-4">
                                        {/* Request Section */}
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
                                                <span className="text-green-500">→</span> Request
                                            </h4>
                                            <div className="bg-zinc-950 dark:bg-black rounded-lg overflow-hidden">
                                                {/* Request Line */}
                                                <div className="p-3 border-b border-zinc-800">
                                                    <span className="text-green-400 font-mono text-sm">
                                                        {selectedReportResult.auth_request_method || 'GET'} {selectedReportResult.auth_request_url || selectedReportResult.target_url} HTTP/1.1
                                                    </span>
                                                </div>
                                                
                                                {/* Request Headers */}
                                                <div className="p-3 border-b border-zinc-800 max-h-[200px] overflow-y-auto">
                                                    <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide">Headers</div>
                                                    <div className="font-mono text-xs space-y-1">
                                                        {selectedReportResult.auth_request_headers && Object.keys(selectedReportResult.auth_request_headers).length > 0 ? (
                                                            Object.entries(selectedReportResult.auth_request_headers).map(([key, value]: [string, any], idx: number) => (
                                                                <div key={idx} className="flex">
                                                                    <span className="text-cyan-400">{key}:</span>
                                                                    <span className="text-slate-300 ml-2 break-all">{String(value)}</span>
                                                                </div>
                                                            ))
                                                        ) : (
                                                            <>
                                                                <div className="flex">
                                                                    <span className="text-cyan-400">Host:</span>
                                                                    <span className="text-slate-300 ml-2">{(() => { try { return new URL(selectedReportResult.target_url).host } catch { return 'N/A' } })()}</span>
                                                                </div>
                                                                <div className="flex">
                                                                    <span className="text-cyan-400">Accept:</span>
                                                                    <span className="text-slate-300 ml-2">application/json, text/plain, */*</span>
                                                                </div>
                                                                <div className="flex">
                                                                    <span className="text-cyan-400">User-Agent:</span>
                                                                    <span className="text-slate-300 ml-2">AuditGH-SecurityScanner/1.0</span>
                                                                </div>
                                                                {/* Display auth headers with actual credential values for security analyst validation */}
                                                                {selectedReportResult.auth_headers_used && selectedReportResult.auth_headers_used.map((header: string, idx: number) => {
                                                                    const headerName = header.includes(':') ? header.split(':')[0] : header;
                                                                    // Get the actual credential value - security analysts need unmasked values
                                                                    const credValue = selectedReportResult.credential_value || '[No credential stored]';
                                                                    // Determine the header value based on header type
                                                                    let headerValue = credValue;
                                                                    if (header.toLowerCase().includes('bearer')) {
                                                                        headerValue = `Bearer ${credValue}`;
                                                                    } else if (header.toLowerCase().includes('basic')) {
                                                                        headerValue = `Basic ${credValue}`;
                                                                    }
                                                                    return (
                                                                        <div key={idx} className="flex text-yellow-400">
                                                                            <span>{headerName}:</span>
                                                                            <span className="ml-2 break-all">{headerValue}</span>
                                                                        </div>
                                                                    );
                                                                })}
                                                            </>
                                                        )}
                                                    </div>
                                                </div>
                                                
                                                {/* Request Body */}
                                                {selectedReportResult.auth_request_body && (
                                                    <div className="p-3">
                                                        <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide">Body</div>
                                                        <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap break-all max-h-[150px] overflow-y-auto">
                                                            {selectedReportResult.auth_request_body}
                                                        </pre>
                                                    </div>
                                                )}
                                            </div>
                                        </div>

                                        {/* Response Section */}
                                        <div>
                                            <h4 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
                                                <span className={selectedReportResult.auth_status === 'yes' ? 'text-green-500' : 'text-red-500'}>←</span> Response
                                            </h4>
                                            <div className="bg-zinc-950 dark:bg-black rounded-lg overflow-hidden">
                                                {/* Status Line */}
                                                <div className="p-3 border-b border-zinc-800">
                                                    <span className={`font-mono text-sm ${
                                                        selectedReportResult.auth_status_code >= 200 && selectedReportResult.auth_status_code < 300 
                                                            ? 'text-green-400' 
                                                            : selectedReportResult.auth_status_code >= 400 
                                                                ? 'text-red-400' 
                                                                : 'text-yellow-400'
                                                    }`}>
                                                        HTTP/1.1 {selectedReportResult.auth_status_code} {
                                                            selectedReportResult.auth_status_code === 200 ? 'OK' :
                                                            selectedReportResult.auth_status_code === 201 ? 'Created' :
                                                            selectedReportResult.auth_status_code === 204 ? 'No Content' :
                                                            selectedReportResult.auth_status_code === 400 ? 'Bad Request' :
                                                            selectedReportResult.auth_status_code === 401 ? 'Unauthorized' :
                                                            selectedReportResult.auth_status_code === 403 ? 'Forbidden' :
                                                            selectedReportResult.auth_status_code === 404 ? 'Not Found' :
                                                            selectedReportResult.auth_status_code === 500 ? 'Internal Server Error' :
                                                            ''
                                                        }
                                                    </span>
                                                    <span className="text-slate-500 text-xs ml-4">
                                                        ({selectedReportResult.auth_response_time_ms}ms)
                                                    </span>
                                                </div>
                                                
                                                {/* Response Headers */}
                                                <div className="p-3 border-b border-zinc-800 max-h-[200px] overflow-y-auto">
                                                    <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide">Headers</div>
                                                    <div className="font-mono text-xs space-y-1">
                                                        {selectedReportResult.auth_response_headers && Object.keys(selectedReportResult.auth_response_headers).length > 0 ? (
                                                            Object.entries(selectedReportResult.auth_response_headers).map(([key, value]: [string, any], idx: number) => (
                                                                <div key={idx} className="flex">
                                                                    <span className="text-cyan-400">{key}:</span>
                                                                    <span className="text-slate-300 ml-2 break-all">{String(value)}</span>
                                                                </div>
                                                            ))
                                                        ) : (
                                                            <div className="text-slate-500 italic">No headers captured</div>
                                                        )}
                                                    </div>
                                                </div>
                                                
                                                {/* Response Body */}
                                                <div className="p-3">
                                                    <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide flex items-center gap-2">
                                                        Body
                                                        {selectedReportResult.auth_response_body_truncated && (
                                                            <Badge variant="outline" className="text-xs text-yellow-500 border-yellow-500">Truncated</Badge>
                                                        )}
                                                    </div>
                                                    {selectedReportResult.auth_response_body ? (
                                                        <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap break-all max-h-[300px] overflow-y-auto bg-zinc-900 rounded p-2">
                                                            {(() => {
                                                                try {
                                                                    // Try to pretty-print JSON
                                                                    const parsed = JSON.parse(selectedReportResult.auth_response_body)
                                                                    return JSON.stringify(parsed, null, 2)
                                                                } catch {
                                                                    // Return as-is if not JSON
                                                                    return selectedReportResult.auth_response_body
                                                                }
                                                            })()}
                                                        </pre>
                                                    ) : (
                                                        <div className="text-slate-500 italic text-xs">No response body captured</div>
                                                    )}
                                                </div>
                                            </div>
                                        </div>

                                        {/* Credential Info Summary */}
                                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm pt-2 border-t border-zinc-700">
                                            <div>
                                                <span className="text-muted-foreground text-xs">Credential Type</span>
                                                <div className="font-medium mt-1 font-mono text-xs">{selectedReportResult.credential_type}</div>
                                            </div>
                                            <div>
                                                <span className="text-muted-foreground text-xs">Detected Service</span>
                                                <div className="font-medium mt-1 text-xs">
                                                    {selectedReportResult.detected_service || 'Unknown'}
                                                    {(selectedReportResult.service_detection_score ?? 0) > 0 && (
                                                        <span className="text-muted-foreground ml-1">
                                                            ({selectedReportResult.service_detection_score}%)
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                            <div>
                                                <span className="text-muted-foreground text-xs">Environment</span>
                                                <div className="font-medium mt-1 text-xs">{selectedReportResult.credential_environment || 'N/A'}</div>
                                            </div>
                                            <div>
                                                <span className="text-muted-foreground text-xs">Auth Headers</span>
                                                <div className="font-medium mt-1 font-mono text-xs">
                                                    {selectedReportResult.auth_headers_used?.length || 0} used
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* Discovered Paths */}
                                <div className="rounded-lg border p-4">
                                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                                        <Globe className="h-4 w-4 text-purple-500" />
                                        Discovered Paths ({selectedReportResult.discovered_paths_count} total, {selectedReportResult.hidden_paths_found} hidden)
                                    </h3>
                                    {selectedReportResult.discovered_paths && selectedReportResult.discovered_paths.length > 0 ? (
                                        <div className="rounded border overflow-hidden max-h-[300px] overflow-y-auto">
                                            <table className="w-full text-sm">
                                                <thead className="bg-muted/50 sticky top-0">
                                                    <tr>
                                                        <th className="px-3 py-2 text-left font-medium">Method</th>
                                                        <th className="px-3 py-2 text-left font-medium">Path</th>
                                                        <th className="px-3 py-2 text-center font-medium">Status</th>
                                                        <th className="px-3 py-2 text-center font-medium">Result</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {selectedReportResult.discovered_paths.slice(0, 50).map((path: any, idx: number) => (
                                                        <tr key={idx} className="border-t hover:bg-muted/30">
                                                            <td className="px-3 py-2">
                                                                <Badge variant="outline" className="text-xs">{path.method}</Badge>
                                                            </td>
                                                            <td className="px-3 py-2 font-mono text-xs truncate max-w-[300px]" title={path.path}>
                                                                {path.path}
                                                            </td>
                                                            <td className="px-3 py-2 text-center">{path.status_code}</td>
                                                            <td className="px-3 py-2 text-center">
                                                                {path.success ? (
                                                                    <CheckCircle2 className="h-4 w-4 text-green-500 inline" />
                                                                ) : (
                                                                    <XCircle className="h-4 w-4 text-red-500 inline" />
                                                                )}
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    ) : (
                                        <p className="text-sm text-muted-foreground italic">No paths discovered</p>
                                    )}
                                </div>

                                {/* OSINT Findings */}
                                <div className="rounded-lg border p-4">
                                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                                        <ExternalLink className="h-4 w-4 text-orange-500" />
                                        OSINT Findings ({selectedReportResult.osint_findings?.length || 0} sources)
                                    </h3>
                                    {selectedReportResult.osint_findings && selectedReportResult.osint_findings.length > 0 ? (
                                        <div className="rounded border overflow-hidden max-h-[200px] overflow-y-auto">
                                            <table className="w-full text-sm">
                                                <thead className="bg-muted/50 sticky top-0">
                                                    <tr>
                                                        <th className="px-3 py-2 text-left font-medium">Source</th>
                                                        <th className="px-3 py-2 text-left font-medium">Type</th>
                                                        <th className="px-3 py-2 text-left font-medium">URL</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {selectedReportResult.osint_findings.map((finding: any, idx: number) => (
                                                        <tr key={idx} className="border-t hover:bg-muted/30">
                                                            <td className="px-3 py-2">
                                                                <Badge variant="outline" className="text-xs">{finding.source}</Badge>
                                                            </td>
                                                            <td className="px-3 py-2 text-xs">{finding.type}</td>
                                                            <td className="px-3 py-2">
                                                                <a href={finding.url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-500 hover:underline truncate block max-w-[300px]">
                                                                    {finding.url}
                                                                </a>
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    ) : (
                                        <p className="text-sm text-muted-foreground italic">No OSINT findings</p>
                                    )}
                                </div>

                                {/* Recommendations */}
                                <div className="rounded-lg border p-4">
                                    <h3 className="font-semibold mb-3 flex items-center gap-2">
                                        <AlertTriangle className="h-4 w-4 text-yellow-500" />
                                        Recommendations
                                    </h3>
                                    {selectedReportResult.ai_recommendations && selectedReportResult.ai_recommendations.length > 0 ? (
                                        <ul className="space-y-2">
                                            {selectedReportResult.ai_recommendations.map((rec: string, idx: number) => (
                                                <li key={idx} className="text-sm flex items-start gap-2">
                                                    <span className="text-yellow-500 mt-1">•</span>
                                                    <span>{rec}</span>
                                                </li>
                                            ))}
                                        </ul>
                                    ) : (
                                        <p className="text-sm text-muted-foreground italic">No recommendations available</p>
                                    )}
                                </div>

                                {/* Test Metadata */}
                                <div className="text-xs text-muted-foreground flex flex-wrap gap-4 pt-4 border-t">
                                    <span>Tested: {selectedReportResult.tested_at ? new Date(selectedReportResult.tested_at).toLocaleString() : 'N/A'}</span>
                                    <span>Duration: {selectedReportResult.test_duration_seconds}s</span>
                                    <span>Mode: {selectedReportResult.test_mode}</span>
                                    {selectedReportResult.llm_provider && (
                                        <span>LLM: {selectedReportResult.llm_provider} / {selectedReportResult.llm_model}</span>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Download Modal - outside TabsContent for proper z-index */}
            {downloadModalOpen && selectedReportResult && (
                <div className="fixed inset-0 bg-black/80 z-[60] flex items-center justify-center p-4">
                    <div className="bg-white dark:bg-zinc-900 rounded-lg w-full max-w-md p-6 shadow-2xl border dark:border-zinc-700">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-lg font-semibold flex items-center gap-2">
                                <Download className="h-5 w-5 text-blue-500" />
                                Download Report
                            </h3>
                            <Button variant="ghost" size="sm" onClick={() => setDownloadModalOpen(false)}>
                                <X className="h-4 w-4" />
                            </Button>
                        </div>
                        
                        <div className="space-y-4">
                            <div>
                                <label className="text-sm font-medium mb-1 block">Format</label>
                                <select 
                                    value={downloadFormat}
                                    onChange={(e) => setDownloadFormat(e.target.value as any)}
                                    className="w-full px-3 py-2 rounded border bg-background"
                                >
                                    <option value="pdf">PDF</option>
                                    <option value="json">JSON</option>
                                    <option value="docx">DOCX (Word)</option>
                                    <option value="csv">CSV</option>
                                    <option value="markdown">Markdown</option>
                                </select>
                            </div>
                            
                            <div>
                                <label className="text-sm font-medium mb-1 block">Filename</label>
                                <input 
                                    type="text"
                                    value={downloadFilename}
                                    onChange={(e) => setDownloadFilename(e.target.value)}
                                    placeholder="credential_url_report"
                                    className="w-full px-3 py-2 rounded border bg-background"
                                />
                                <p className="text-xs text-muted-foreground mt-1">
                                    Will be saved as: {downloadFilename || 'credential_url_report'}.{downloadFormat}
                                </p>
                            </div>
                            
                            <div className="flex justify-end gap-2 pt-4">
                                <Button variant="outline" onClick={() => setDownloadModalOpen(false)}>
                                    Cancel
                                </Button>
                                <Button onClick={downloadReport}>
                                    <Download className="h-4 w-4 mr-1" />
                                    Download
                                </Button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}
