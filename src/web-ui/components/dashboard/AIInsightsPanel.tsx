"use client"

import { useEffect, useRef, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import Link from "next/link"
import {
    Zap,
    Search,
    AlertTriangle,
    CheckCircle,
    Target,
    Bot,
    ShieldAlert,
    FileCode,
    Users
} from "lucide-react"

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

interface AIInsightsPanelProps {
    insights: InsightItem[]
    maxDisplay?: number
    refreshInterval?: number
    onRefresh?: () => void
}

function getInsightIcon(type: string) {
    const icons: Record<string, React.ReactNode> = {
        finding: <ShieldAlert className="h-4 w-4" />,
        analysis: <Search className="h-4 w-4" />,
        remediation: <CheckCircle className="h-4 w-4" />,
        alert: <AlertTriangle className="h-4 w-4" />,
        scan: <FileCode className="h-4 w-4" />
    }
    return icons[type] || <Bot className="h-4 w-4" />
}

function getInsightColor(type: string, severity?: string): string {
    if (severity === "critical") return "text-red-500 bg-red-500/10 border-red-500/20"
    if (severity === "high") return "text-orange-500 bg-orange-500/10 border-orange-500/20"

    const colors: Record<string, string> = {
        finding: "text-red-400 bg-red-500/10 border-red-500/20",
        analysis: "text-blue-400 bg-blue-500/10 border-blue-500/20",
        remediation: "text-green-400 bg-green-500/10 border-green-500/20",
        alert: "text-amber-400 bg-amber-500/10 border-amber-500/20",
        scan: "text-purple-400 bg-purple-500/10 border-purple-500/20"
    }
    return colors[type] || "text-slate-400 bg-slate-500/10 border-slate-500/20"
}

function formatTimeAgo(date: Date): string {
    const now = new Date()
    const seconds = Math.floor((now.getTime() - date.getTime()) / 1000)

    if (seconds < 60) return "Just now"
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} hour${Math.floor(seconds / 3600) > 1 ? "s" : ""} ago`
    return `${Math.floor(seconds / 86400)} day${Math.floor(seconds / 86400) > 1 ? "s" : ""} ago`
}

function InsightRow({ insight, isNew }: { insight: InsightItem; isNew: boolean }) {
    const colorClass = getInsightColor(insight.type, insight.severity)

    const content = (
        <div
            className={cn(
                "group flex items-start gap-3 p-3 rounded-lg border transition-all duration-300",
                colorClass,
                isNew && "animate-in slide-in-from-top-2 fade-in-0",
                insight.link && "cursor-pointer hover:scale-[1.01] hover:shadow-md"
            )}
        >
            <div className={cn(
                "rounded-full p-2 shrink-0",
                colorClass.split(" ")[1] // Use the bg color
            )}>
                {getInsightIcon(insight.type)}
            </div>
            <div className="flex-1 min-w-0 space-y-1">
                <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-muted-foreground">
                        {formatTimeAgo(insight.timestamp)}
                    </span>
                    {insight.severity && (
                        <Badge
                            variant="outline"
                            className={cn(
                                "text-[10px] px-1.5 py-0",
                                insight.severity === "critical" && "border-red-500 text-red-500",
                                insight.severity === "high" && "border-orange-500 text-orange-500"
                            )}
                        >
                            {insight.severity}
                        </Badge>
                    )}
                </div>
                <p className="text-sm font-medium leading-tight truncate">
                    {insight.title}
                </p>
                <p className="text-xs text-muted-foreground truncate">
                    {insight.description}
                    {insight.repoName && (
                        <span className="text-primary ml-1">({insight.repoName})</span>
                    )}
                </p>
            </div>
            {insight.link && (
                <div className="opacity-0 group-hover:opacity-100 transition-opacity text-xs text-primary shrink-0">
                    View
                </div>
            )}
        </div>
    )

    if (insight.link) {
        return (
            <Link href={insight.link} className="block">
                {content}
            </Link>
        )
    }

    return content
}

export function AIInsightsPanel({
    insights,
    maxDisplay = 6,
    refreshInterval = 30000,
    onRefresh
}: AIInsightsPanelProps) {
    const [displayedInsights, setDisplayedInsights] = useState<InsightItem[]>([])
    const [newIds, setNewIds] = useState<Set<string>>(new Set())
    const prevInsightsRef = useRef<string[]>([])

    useEffect(() => {
        // Track which items are new
        const prevIds = new Set(prevInsightsRef.current)
        const currentIds = insights.slice(0, maxDisplay).map(i => i.id)
        const newItems = currentIds.filter(id => !prevIds.has(id))

        setNewIds(new Set(newItems))
        setDisplayedInsights(insights.slice(0, maxDisplay))
        prevInsightsRef.current = currentIds

        // Clear "new" status after animation
        const timer = setTimeout(() => {
            setNewIds(new Set())
        }, 1000)

        return () => clearTimeout(timer)
    }, [insights, maxDisplay])

    // Refresh polling
    useEffect(() => {
        if (!onRefresh) return

        const interval = setInterval(onRefresh, refreshInterval)
        return () => clearInterval(interval)
    }, [onRefresh, refreshInterval])

    return (
        <Card className="h-full flex flex-col">
            <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Bot className="h-5 w-5 text-purple-500" />
                        <CardTitle className="text-lg font-semibold">
                            AI Security Insights
                        </CardTitle>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="flex items-center gap-1.5">
                            <span className="relative flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                            </span>
                            <span className="text-xs text-muted-foreground">Live</span>
                        </div>
                    </div>
                </div>
            </CardHeader>
            <CardContent className="flex-1 overflow-hidden">
                <div className="space-y-2 h-full overflow-y-auto pr-1">
                    {displayedInsights.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-full text-muted-foreground py-8">
                            <Bot className="h-8 w-8 mb-2 opacity-50" />
                            <p className="text-sm">No recent AI activity</p>
                            <p className="text-xs">Insights will appear here as they're generated</p>
                        </div>
                    ) : (
                        displayedInsights.map((insight) => (
                            <InsightRow
                                key={insight.id}
                                insight={insight}
                                isNew={newIds.has(insight.id)}
                            />
                        ))
                    )}
                </div>
            </CardContent>
        </Card>
    )
}
