"use client"

import { AnimatedCounter } from "./AnimatedCounter"
import { cn } from "@/lib/utils"
import {
    Search,
    ShieldAlert,
    AlertTriangle,
    Bot,
    TrendingUp,
    TrendingDown,
    Minus
} from "lucide-react"

interface MetricCardProps {
    icon: React.ReactNode
    label: string
    value: number
    subLabel: string
    trend?: {
        value: number
        label: string
        direction: "up" | "down" | "neutral"
        isPositive?: boolean // Whether "up" is good (e.g., repos scanned) or bad (e.g., findings)
    }
    accentColor?: string
    pulse?: boolean
}

function MetricCard({
    icon,
    label,
    value,
    subLabel,
    trend,
    accentColor = "text-primary",
    pulse = false
}: MetricCardProps) {
    const getTrendIcon = () => {
        if (!trend) return null
        switch (trend.direction) {
            case "up":
                return <TrendingUp className="h-3 w-3" />
            case "down":
                return <TrendingDown className="h-3 w-3" />
            default:
                return <Minus className="h-3 w-3" />
        }
    }

    const getTrendColor = () => {
        if (!trend) return ""
        if (trend.direction === "neutral") return "text-muted-foreground"
        // If isPositive is defined, use it; otherwise assume down is good (fewer findings)
        const isGood = trend.isPositive !== undefined
            ? (trend.direction === "up" && trend.isPositive) || (trend.direction === "down" && !trend.isPositive)
            : trend.direction === "down"
        return isGood ? "text-green-500" : "text-red-500"
    }

    return (
        <div className="relative group">
            <div className={cn(
                "rounded-xl border bg-card p-6 shadow-sm transition-all duration-300",
                "hover:shadow-lg hover:scale-[1.02] hover:border-primary/50",
                "bg-gradient-to-br from-card to-card/80"
            )}>
                {/* Accent glow on hover */}
                <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />

                <div className="relative flex items-start justify-between">
                    <div className="space-y-2">
                        <p className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
                            {label}
                        </p>
                        <div className={cn("text-4xl font-bold tracking-tight", accentColor)}>
                            <AnimatedCounter value={value} duration={1500} />
                        </div>
                        <p className="text-xs text-muted-foreground">
                            {subLabel}
                        </p>
                    </div>
                    <div className={cn(
                        "rounded-full p-3 bg-muted/50",
                        pulse && "animate-pulse"
                    )}>
                        {icon}
                    </div>
                </div>

                {trend && (
                    <div className={cn(
                        "mt-4 pt-4 border-t flex items-center gap-1.5 text-xs font-medium",
                        getTrendColor()
                    )}>
                        {getTrendIcon()}
                        <span>{trend.value > 0 ? "+" : ""}{trend.value}</span>
                        <span className="text-muted-foreground">{trend.label}</span>
                    </div>
                )}
            </div>
        </div>
    )
}

interface HeroMetricsProps {
    data: {
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
}

export function HeroMetrics({ data }: HeroMetricsProps) {
    return (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <MetricCard
                icon={<Search className="h-6 w-6 text-blue-500" />}
                label="Repositories"
                value={data.repositories}
                subLabel="Monitored"
                trend={data.trends?.repositories ? {
                    value: data.trends.repositories.value,
                    label: data.trends.repositories.label,
                    direction: data.trends.repositories.value > 0 ? "up" : data.trends.repositories.value < 0 ? "down" : "neutral",
                    isPositive: true
                } : undefined}
                accentColor="text-blue-500"
            />
            <MetricCard
                icon={<ShieldAlert className="h-6 w-6 text-red-500" />}
                label="Critical"
                value={data.criticalFindings}
                subLabel="Findings"
                trend={data.trends?.findings ? {
                    value: data.trends.findings.value,
                    label: data.trends.findings.label,
                    direction: data.trends.findings.value > 0 ? "up" : data.trends.findings.value < 0 ? "down" : "neutral",
                    isPositive: false
                } : undefined}
                accentColor="text-red-500"
            />
            <MetricCard
                icon={<AlertTriangle className="h-6 w-6 text-amber-500" />}
                label="Under"
                value={data.underInvestigation}
                subLabel="Investigation"
                trend={data.trends?.investigations ? {
                    value: data.trends.investigations.value,
                    label: data.trends.investigations.label,
                    direction: data.trends.investigations.value > 0 ? "up" : data.trends.investigations.value < 0 ? "down" : "neutral",
                    isPositive: true
                } : undefined}
                accentColor="text-amber-500"
                pulse={data.underInvestigation > 0}
            />
            <MetricCard
                icon={<Bot className="h-6 w-6 text-purple-500" />}
                label="AI Analyses"
                value={data.aiAnalysesToday}
                subLabel="Today"
                trend={data.trends?.aiAnalyses ? {
                    value: data.trends.aiAnalyses.value,
                    label: data.trends.aiAnalyses.label,
                    direction: data.trends.aiAnalyses.value > 0 ? "up" : data.trends.aiAnalyses.value < 0 ? "down" : "neutral",
                    isPositive: true
                } : undefined}
                accentColor="text-purple-500"
            />
        </div>
    )
}
