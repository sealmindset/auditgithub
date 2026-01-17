"use client"

import { useEffect, useState, useCallback } from "react"
import { useSearchParams } from "next/navigation"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import Link from "next/link"
import { ArrowUpRight } from "lucide-react"

// Hollywood Dashboard Components
import { HeroMetrics } from "@/components/dashboard/HeroMetrics"
import { ThreatRadar } from "@/components/dashboard/ThreatRadar"
import { AIInsightsPanel } from "@/components/dashboard/AIInsightsPanel"
import { FeedbackButton } from "@/components/dashboard/FeedbackButton"
import { ExecutiveSummaryCards } from "@/components/dashboard/ExecutiveSummaryCards"
import { SeverityChart } from "@/components/dashboard/SeverityChart"
import { SecurityOverviewWidget } from "@/components/dashboard/SecurityOverviewWidget"
import { ScanActivityWidget } from "@/components/dashboard/ScanActivityWidget"
import { BackgroundJobsWidget } from "@/components/dashboard/BackgroundJobsWidget"
import { RepositoryHealthWidget } from "@/components/dashboard/RepositoryHealthWidget"

const API_BASE = "http://localhost:8000"

interface HeroMetricsData {
    repositories: number
    criticalFindings: number
    underInvestigation: number
    aiAnalysesToday: number
    trends?: {
        repositories?: { value: number; label: string }
        findings?: { value: number; label: string }
        investigations?: { value: number; label: string }
        aiAnalyses?: { value: number; label: string }
    }
}

interface ThreatRadarData {
    critical: number
    high: number
    medium: number
    secrets: number
    abandoned: number
    staleContributors: number
    overallScore: number
}

interface InsightItem {
    id: string
    type: "finding" | "analysis" | "remediation" | "alert" | "scan"
    title: string
    description: string
    timestamp: Date
    severity?: "critical" | "high" | "medium" | "low"
    link?: string
    repoName?: string
}

export default function DashboardPage() {
    const searchParams = useSearchParams()
    const currentOrg = searchParams.get("org")
    
    // Hollywood dashboard state
    const [heroMetrics, setHeroMetrics] = useState<HeroMetricsData>({
        repositories: 0,
        criticalFindings: 0,
        underInvestigation: 0,
        aiAnalysesToday: 0
    })
    const [threatRadarData, setThreatRadarData] = useState<ThreatRadarData>({
        critical: 0,
        high: 0,
        medium: 0,
        secrets: 0,
        abandoned: 0,
        staleContributors: 0,
        overallScore: 100
    })
    const [aiInsights, setAiInsights] = useState<InsightItem[]>([])

    // Legacy state
    const [recentFindings, setRecentFindings] = useState([])
    const [loading, setLoading] = useState(true)
    
    // Build org query param for API calls
    const orgParam = currentOrg ? `org=${encodeURIComponent(currentOrg)}` : ""

    const fetchHollywoodData = useCallback(async () => {
        try {
            const [heroRes, radarRes, insightsRes] = await Promise.all([
                fetch(`${API_BASE}/analytics/hero-metrics${orgParam ? `?${orgParam}` : ""}`),
                fetch(`${API_BASE}/analytics/threat-radar${orgParam ? `?${orgParam}` : ""}`),
                fetch(`${API_BASE}/analytics/ai-insights?limit=8${orgParam ? `&${orgParam}` : ""}`)
            ])

            if (heroRes.ok) {
                const data = await heroRes.json()
                setHeroMetrics(data)
            }

            if (radarRes.ok) {
                const data = await radarRes.json()
                setThreatRadarData(data)
            }

            if (insightsRes.ok) {
                const data = await insightsRes.json()
                // Convert timestamp strings to Date objects
                setAiInsights(data.map((item: any) => ({
                    ...item,
                    timestamp: new Date(item.timestamp)
                })))
            }
        } catch (error) {
            console.error("Failed to fetch Hollywood dashboard data:", error)
        }
    }, [orgParam])

    const fetchLegacyData = useCallback(async () => {
        try {
            const recentRes = await fetch(`${API_BASE}/analytics/recent-findings${orgParam ? `?${orgParam}` : ""}`)
            if (recentRes.ok) setRecentFindings(await recentRes.json())
        } catch (error) {
            console.error("Failed to fetch recent findings:", error)
        }
    }, [orgParam])

    useEffect(() => {
        const fetchAll = async () => {
            setLoading(true)
            await Promise.all([fetchHollywoodData(), fetchLegacyData()])
            setLoading(false)
        }

        fetchAll()

        // Refresh every 30 seconds
        const interval = setInterval(fetchAll, 30000)
        return () => clearInterval(interval)
    }, [fetchHollywoodData, fetchLegacyData])

    return (
        <div className="flex flex-1 flex-col gap-6 p-6 pt-0">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-3xl font-bold tracking-tight">Security Dashboard</h2>
                    <p className="text-muted-foreground">
                        Real-time security posture and AI-powered insights
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <Badge variant="outline" className="gap-1">
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                        </span>
                        Live
                    </Badge>
                </div>
            </div>

            {/* Hero Metrics */}
            <div className="relative">
                <div className="absolute top-2 right-2 z-10">
                    <FeedbackButton
                        componentId="hero-metrics"
                        componentName="Hero Metrics"
                    />
                </div>
                <HeroMetrics data={heroMetrics} />
            </div>

            {/* Security Overview & Scan Activity Widgets */}
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
                <SecurityOverviewWidget />
                <ScanActivityWidget />
                <BackgroundJobsWidget />
            </div>

            {/* Repository Health Widget - Full Width */}
            <RepositoryHealthWidget />

            {/* Main Content Grid */}
            <div className="grid gap-6 lg:grid-cols-5">
                {/* Threat Radar - Takes 2 columns */}
                <div className="lg:col-span-2">
                    <ThreatRadar
                        data={threatRadarData}
                        investigationCount={heroMetrics.underInvestigation}
                    />
                </div>

                {/* AI Insights Panel - Takes 3 columns */}
                <div className="lg:col-span-3">
                    <AIInsightsPanel
                        insights={aiInsights}
                        maxDisplay={6}
                        onRefresh={fetchHollywoodData}
                        refreshInterval={30000}
                    />
                </div>
            </div>

            {/* Executive Summary Cards - What Matters Now */}
            <ExecutiveSummaryCards />

            {/* Enhanced Severity Distribution Chart */}
            <SeverityChart />

            {/* Recent Critical Findings Table */}
            <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                    <div>
                        <CardTitle>Recent Critical Findings</CardTitle>
                        <CardDescription>
                            Latest security issues requiring immediate attention
                        </CardDescription>
                    </div>
                    <Link href="/findings">
                        <Button size="sm" className="gap-1">
                            View All
                            <ArrowUpRight className="h-4 w-4" />
                        </Button>
                    </Link>
                </CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>ID</TableHead>
                                <TableHead>Title</TableHead>
                                <TableHead>Severity</TableHead>
                                <TableHead>Repository</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead className="text-right">Date</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {recentFindings.length === 0 ? (
                                <TableRow>
                                    <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                                        No critical findings found. Your security posture is looking good!
                                    </TableCell>
                                </TableRow>
                            ) : (
                                recentFindings.map((finding: any) => (
                                    <TableRow key={finding.id} className="group">
                                        <TableCell className="font-medium">
                                            <Link
                                                href={`/findings/${finding.id}`}
                                                className="text-primary hover:underline"
                                            >
                                                {finding.id.substring(0, 8)}...
                                            </Link>
                                        </TableCell>
                                        <TableCell className="max-w-xs truncate">
                                            {finding.title}
                                        </TableCell>
                                        <TableCell>
                                            <Badge
                                                variant={
                                                    finding.severity === "Critical"
                                                        ? "destructive"
                                                        : finding.severity === "High"
                                                            ? "default"
                                                            : "secondary"
                                                }
                                                className={
                                                    finding.severity === "High"
                                                        ? "bg-orange-500 hover:bg-orange-600"
                                                        : ""
                                                }
                                            >
                                                {finding.severity}
                                            </Badge>
                                        </TableCell>
                                        <TableCell>
                                            <Link
                                                href={`/projects/${finding.repo}`}
                                                className="text-primary hover:underline"
                                            >
                                                {finding.repo}
                                            </Link>
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant="outline">{finding.status}</Badge>
                                        </TableCell>
                                        <TableCell className="text-right text-muted-foreground">
                                            {finding.date}
                                        </TableCell>
                                    </TableRow>
                                ))
                            )}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    )
}
