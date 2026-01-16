"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import {
    Bar,
    Line,
    Area,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    ComposedChart,
    AreaChart,
    Cell,
} from "recharts"
import { Shield, TrendingUp, TrendingDown, Calendar, GitBranch } from "lucide-react"
import { FeedbackButton } from "./FeedbackButton"

const API_BASE = "http://localhost:8000"

interface SeverityDataPoint {
    name: string
    count: number
    trend?: number
    color: string
}

interface RepoGrowthPoint {
    year: string
    repos: number
    newRepos: number
    findings: number
}

// Severity order and colors
const SEVERITY_CONFIG: Record<string, { order: number; color: string; gradient: string }> = {
    info: { order: 1, color: "#3b82f6", gradient: "url(#infoGradient)" },
    low: { order: 2, color: "#22c55e", gradient: "url(#lowGradient)" },
    warning: { order: 3, color: "#f59e0b", gradient: "url(#warningGradient)" },
    medium: { order: 4, color: "#eab308", gradient: "url(#mediumGradient)" },
    high: { order: 5, color: "#f97316", gradient: "url(#highGradient)" },
    critical: { order: 6, color: "#ef4444", gradient: "url(#criticalGradient)" },
}

const SeverityTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
        const data = payload[0].payload
        return (
            <div className="bg-card border border-border rounded-lg p-3 shadow-lg">
                <p className="font-semibold text-sm capitalize mb-1">{label}</p>
                <div className="space-y-1">
                    <p className="text-sm">
                        <span className="text-muted-foreground">Count: </span>
                        <span className="font-bold" style={{ color: data.color }}>{data.count}</span>
                    </p>
                    {data.trend !== undefined && data.trend !== 0 && (
                        <p className="text-sm flex items-center gap-1">
                            <span className="text-muted-foreground">7-day trend: </span>
                            <span className={data.trend >= 0 ? "text-red-500" : "text-green-500"}>
                                {data.trend >= 0 ? "+" : ""}{data.trend}%
                            </span>
                            {data.trend >= 0 ? (
                                <TrendingUp className="h-3 w-3 text-red-500" />
                            ) : (
                                <TrendingDown className="h-3 w-3 text-green-500" />
                            )}
                        </p>
                    )}
                </div>
            </div>
        )
    }
    return null
}

const RepoGrowthTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
        return (
            <div className="bg-card border border-border rounded-lg p-3 shadow-lg">
                <p className="font-semibold text-sm mb-2">{label}</p>
                <div className="space-y-1">
                    {payload.map((entry: any, index: number) => (
                        <p key={index} className="text-sm flex items-center gap-2">
                            <span
                                className="w-2 h-2 rounded-full"
                                style={{ backgroundColor: entry.color }}
                            />
                            <span className="text-muted-foreground">{entry.name}: </span>
                            <span className="font-bold">{entry.value.toLocaleString()}</span>
                        </p>
                    ))}
                </div>
            </div>
        )
    }
    return null
}

export function SeverityChart() {
    const [data, setData] = useState<SeverityDataPoint[]>([])
    const [repoGrowth, setRepoGrowth] = useState<RepoGrowthPoint[]>([])
    const [loading, setLoading] = useState(true)
    const [repoInfo, setRepoInfo] = useState({ startYear: 0, endYear: 0, totalRepos: 0, totalYears: 0 })

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [severityRes, repoGrowthRes] = await Promise.all([
                    fetch(`${API_BASE}/analytics/severity-distribution`),
                    fetch(`${API_BASE}/analytics/repo-growth`)
                ])

                if (severityRes.ok) {
                    const rawData = await severityRes.json()

                    // Transform and sort data
                    const transformed = rawData.map((item: any) => {
                        const key = item.name.toLowerCase()
                        const config = SEVERITY_CONFIG[key] || { order: 99, color: "#666", gradient: "" }
                        return {
                            name: item.name,
                            count: item.count,
                            color: config.color,
                            order: config.order,
                            trend: item.trend || 0
                        }
                    })

                    // Sort by severity order
                    transformed.sort((a: any, b: any) => a.order - b.order)
                    setData(transformed)
                }

                if (repoGrowthRes.ok) {
                    const growthData = await repoGrowthRes.json()
                    setRepoGrowth(growthData.timeline || [])
                    setRepoInfo({
                        startYear: growthData.startYear || 0,
                        endYear: growthData.endYear || 0,
                        totalRepos: growthData.totalRepos || 0,
                        totalYears: growthData.totalYears || 0
                    })
                }
            } catch (error) {
                console.error("Failed to fetch severity data:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchData()
        const interval = setInterval(fetchData, 60000)
        return () => clearInterval(interval)
    }, [])

    // Calculate average repos per year
    const avgReposPerYear = repoInfo.totalYears > 0
        ? Math.round(repoInfo.totalRepos / repoInfo.totalYears)
        : 0

    return (
        <Card className="relative overflow-hidden">
            {/* Animated background gradient */}
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-transparent to-red-500/5" />

            <div className="absolute top-2 right-2 z-10">
                <FeedbackButton
                    componentId="severity-chart"
                    componentName="Severity Distribution Chart"
                />
            </div>

            <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                    <div>
                        <CardTitle className="flex items-center gap-2">
                            <Shield className="h-5 w-5 text-blue-500" />
                            Severity Distribution
                        </CardTitle>
                        <CardDescription>Open findings by severity with repository growth</CardDescription>
                    </div>
                    {repoInfo.startYear > 0 && (
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium bg-muted/50">
                            <Calendar className="h-3.5 w-3.5 text-muted-foreground" />
                            <span className="text-muted-foreground">
                                {repoInfo.startYear} - {repoInfo.endYear} ({repoInfo.totalYears} years)
                            </span>
                        </div>
                    )}
                </div>
            </CardHeader>

            <CardContent className="pt-4">
                {loading ? (
                    <div className="h-[420px] flex items-center justify-center">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
                    </div>
                ) : (
                    <div className="space-y-6">
                        {/* Severity Bars */}
                        <ResponsiveContainer width="100%" height={180}>
                            <ComposedChart data={data} margin={{ top: 20, right: 20, left: 0, bottom: 5 }} barCategoryGap={40}>
                                <defs>
                                    {/* Gradients for bars */}
                                    <linearGradient id="infoGradient" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#3b82f6" stopOpacity={1} />
                                        <stop offset="100%" stopColor="#1d4ed8" stopOpacity={0.8} />
                                    </linearGradient>
                                    <linearGradient id="lowGradient" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#22c55e" stopOpacity={1} />
                                        <stop offset="100%" stopColor="#16a34a" stopOpacity={0.8} />
                                    </linearGradient>
                                    <linearGradient id="warningGradient" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#f59e0b" stopOpacity={1} />
                                        <stop offset="100%" stopColor="#d97706" stopOpacity={0.8} />
                                    </linearGradient>
                                    <linearGradient id="mediumGradient" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#eab308" stopOpacity={1} />
                                        <stop offset="100%" stopColor="#ca8a04" stopOpacity={0.8} />
                                    </linearGradient>
                                    <linearGradient id="highGradient" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#f97316" stopOpacity={1} />
                                        <stop offset="100%" stopColor="#ea580c" stopOpacity={0.8} />
                                    </linearGradient>
                                    <linearGradient id="criticalGradient" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#ef4444" stopOpacity={1} />
                                        <stop offset="100%" stopColor="#dc2626" stopOpacity={0.8} />
                                    </linearGradient>
                                    {/* Glow filter for bars */}
                                    <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
                                        <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                                        <feMerge>
                                            <feMergeNode in="coloredBlur" />
                                            <feMergeNode in="SourceGraphic" />
                                        </feMerge>
                                    </filter>
                                </defs>

                                <XAxis
                                    dataKey="name"
                                    stroke="#888888"
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    tick={{ fill: '#888888' }}
                                />
                                <YAxis
                                    stroke="#888888"
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    tick={{ fill: '#888888' }}
                                />
                                <Tooltip content={<SeverityTooltip />} />

                                {/* Bars with dynamic colors - no barSize to let them fill available space */}
                                <Bar
                                    dataKey="count"
                                    radius={[8, 8, 0, 0]}
                                >
                                    {data.map((entry, index) => {
                                        const key = entry.name.toLowerCase()
                                        const config = SEVERITY_CONFIG[key]
                                        return (
                                            <Cell
                                                key={`cell-${index}`}
                                                fill={config?.gradient || entry.color}
                                                filter={key === 'critical' || key === 'high' ? 'url(#glow)' : undefined}
                                            />
                                        )
                                    })}
                                </Bar>
                            </ComposedChart>
                        </ResponsiveContainer>

                        {/* Severity Legend */}
                        <div className="flex flex-wrap justify-center gap-4 pb-4 border-b border-border/50">
                            {data.map((item) => (
                                <div key={item.name} className="flex items-center gap-2">
                                    <div
                                        className="w-3 h-3 rounded-sm"
                                        style={{ backgroundColor: item.color }}
                                    />
                                    <span className="text-xs text-muted-foreground capitalize">
                                        {item.name}
                                    </span>
                                    <span className="text-xs font-semibold" style={{ color: item.color }}>
                                        {item.count.toLocaleString()}
                                    </span>
                                </div>
                            ))}
                        </div>

                        {/* Repository Growth Over Years */}
                        {repoGrowth.length > 0 && (
                            <div>
                                <div className="flex items-center justify-between mb-3">
                                    <h4 className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                                        <GitBranch className="h-4 w-4" />
                                        Repository Growth Over Time
                                    </h4>
                                    <div className="flex items-center gap-4 text-xs">
                                        <div className="flex items-center gap-1.5">
                                            <div className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
                                            <span className="text-muted-foreground">Repos: </span>
                                            <span className="font-semibold">{repoInfo.totalRepos.toLocaleString()}</span>
                                        </div>
                                        <div className="flex items-center gap-1.5">
                                            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                                            <span className="text-muted-foreground">Avg/year: </span>
                                            <span className="font-semibold text-emerald-500">{avgReposPerYear}</span>
                                        </div>
                                    </div>
                                </div>

                                <ResponsiveContainer width="100%" height={160}>
                                    <ComposedChart data={repoGrowth} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                                        <defs>
                                            <linearGradient id="repoGradient" x1="0" y1="0" x2="0" y2="1">
                                                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                                                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                                            </linearGradient>
                                            <linearGradient id="newRepoGradient" x1="0" y1="0" x2="0" y2="1">
                                                <stop offset="0%" stopColor="#10b981" stopOpacity={1} />
                                                <stop offset="100%" stopColor="#059669" stopOpacity={0.8} />
                                            </linearGradient>
                                        </defs>
                                        <XAxis
                                            dataKey="year"
                                            stroke="#888888"
                                            fontSize={10}
                                            tickLine={false}
                                            axisLine={false}
                                            tick={{ fill: '#888888' }}
                                        />
                                        <YAxis
                                            yAxisId="left"
                                            stroke="#888888"
                                            fontSize={10}
                                            tickLine={false}
                                            axisLine={false}
                                            tick={{ fill: '#888888' }}
                                            tickFormatter={(value) => value >= 1000 ? `${(value/1000).toFixed(1)}k` : value}
                                        />
                                        <YAxis
                                            yAxisId="right"
                                            orientation="right"
                                            stroke="#888888"
                                            fontSize={10}
                                            tickLine={false}
                                            axisLine={false}
                                            tick={{ fill: '#10b981' }}
                                        />
                                        <Tooltip content={<RepoGrowthTooltip />} />

                                        {/* Area for cumulative repos */}
                                        <Area
                                            yAxisId="left"
                                            type="monotone"
                                            dataKey="repos"
                                            name="Total Repos"
                                            stroke="#06b6d4"
                                            strokeWidth={2}
                                            fill="url(#repoGradient)"
                                        />

                                        {/* Line for cumulative repos trend */}
                                        <Line
                                            yAxisId="left"
                                            type="monotone"
                                            dataKey="repos"
                                            name="Repo Trend"
                                            stroke="#06b6d4"
                                            strokeWidth={3}
                                            dot={{ fill: '#06b6d4', strokeWidth: 2, r: 4 }}
                                            activeDot={{ r: 6, strokeWidth: 2, fill: '#06b6d4' }}
                                        />

                                        {/* Bars for new repos per year */}
                                        <Bar
                                            yAxisId="right"
                                            dataKey="newRepos"
                                            name="New Repos"
                                            fill="url(#newRepoGradient)"
                                            radius={[4, 4, 0, 0]}
                                            maxBarSize={40}
                                            opacity={0.8}
                                        />
                                    </ComposedChart>
                                </ResponsiveContainer>

                                {/* Year Legend */}
                                <div className="flex justify-center gap-6 mt-3 text-xs">
                                    <div className="flex items-center gap-1.5">
                                        <div className="w-8 h-1 rounded bg-cyan-500" />
                                        <span className="text-muted-foreground">Cumulative Repos</span>
                                    </div>
                                    <div className="flex items-center gap-1.5">
                                        <div className="w-3 h-3 rounded-sm bg-emerald-500" />
                                        <span className="text-muted-foreground">New Repos/Year</span>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </CardContent>
        </Card>
    )
}
