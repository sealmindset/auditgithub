"use client"

import { useState } from "react"
import { cn } from "@/lib/utils"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import Link from "next/link"
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip"

interface RepoRisk {
    id: string
    name: string
    riskScore: number
    riskLevel: "critical" | "high" | "medium" | "low"
    criticalFindings: number
    highFindings: number
    secretsCount: number
    isArchived: boolean
    isAbandoned: boolean
}

interface RiskHeatmapProps {
    repos: RepoRisk[]
    maxDisplay?: number
}

function getRiskColor(level: string, isHovered: boolean = false): string {
    const colors: Record<string, { base: string; hover: string }> = {
        critical: {
            base: "bg-red-500/80",
            hover: "bg-red-500"
        },
        high: {
            base: "bg-orange-500/80",
            hover: "bg-orange-500"
        },
        medium: {
            base: "bg-yellow-500/70",
            hover: "bg-yellow-500"
        },
        low: {
            base: "bg-green-500/60",
            hover: "bg-green-500"
        }
    }
    const color = colors[level] || colors.low
    return isHovered ? color.hover : color.base
}

function getRiskGlow(level: string): string {
    const glows: Record<string, string> = {
        critical: "shadow-red-500/50",
        high: "shadow-orange-500/50",
        medium: "shadow-yellow-500/30",
        low: "shadow-green-500/20"
    }
    return glows[level] || ""
}

export function RiskHeatmap({ repos, maxDisplay = 50 }: RiskHeatmapProps) {
    const [hoveredRepo, setHoveredRepo] = useState<string | null>(null)

    // Sort by risk score descending and limit
    const sortedRepos = [...repos]
        .sort((a, b) => b.riskScore - a.riskScore)
        .slice(0, maxDisplay)

    // Calculate grid dimensions (aim for ~10 columns)
    const cols = 10
    const rows = Math.ceil(sortedRepos.length / cols)

    // Count by risk level
    const counts = sortedRepos.reduce((acc, repo) => {
        acc[repo.riskLevel] = (acc[repo.riskLevel] || 0) + 1
        return acc
    }, {} as Record<string, number>)

    return (
        <Card className="h-full">
            <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                    <CardTitle className="text-lg font-semibold">
                        Repository Risk Heatmap
                    </CardTitle>
                    <div className="flex items-center gap-3 text-xs">
                        <div className="flex items-center gap-1.5">
                            <div className="w-3 h-3 rounded-sm bg-red-500" />
                            <span className="text-muted-foreground">Critical ({counts.critical || 0})</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <div className="w-3 h-3 rounded-sm bg-orange-500" />
                            <span className="text-muted-foreground">High ({counts.high || 0})</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <div className="w-3 h-3 rounded-sm bg-yellow-500" />
                            <span className="text-muted-foreground">Medium ({counts.medium || 0})</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <div className="w-3 h-3 rounded-sm bg-green-500" />
                            <span className="text-muted-foreground">Low ({counts.low || 0})</span>
                        </div>
                    </div>
                </div>
            </CardHeader>
            <CardContent>
                <TooltipProvider delayDuration={100}>
                    <div
                        className="grid gap-1.5"
                        style={{
                            gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`
                        }}
                    >
                        {sortedRepos.map((repo, index) => {
                            const isHovered = hoveredRepo === repo.id
                            return (
                                <Tooltip key={repo.id}>
                                    <TooltipTrigger asChild>
                                        <Link
                                            href={`/projects/${repo.id}`}
                                            className={cn(
                                                "aspect-square rounded-md transition-all duration-200 cursor-pointer",
                                                getRiskColor(repo.riskLevel, isHovered),
                                                isHovered && `shadow-lg ${getRiskGlow(repo.riskLevel)} scale-110 z-10`,
                                                "hover:scale-110 hover:shadow-lg hover:z-10",
                                                // Stagger animation on load
                                                "animate-in fade-in-0 zoom-in-50",
                                            )}
                                            style={{
                                                animationDelay: `${index * 20}ms`,
                                                animationDuration: "300ms",
                                                animationFillMode: "backwards"
                                            }}
                                            onMouseEnter={() => setHoveredRepo(repo.id)}
                                            onMouseLeave={() => setHoveredRepo(null)}
                                        />
                                    </TooltipTrigger>
                                    <TooltipContent
                                        side="top"
                                        className="max-w-xs"
                                    >
                                        <div className="space-y-2">
                                            <div className="flex items-center justify-between gap-4">
                                                <span className="font-semibold truncate">{repo.name}</span>
                                                <Badge
                                                    variant="outline"
                                                    className={cn(
                                                        "text-xs",
                                                        repo.riskLevel === "critical" && "border-red-500 text-red-500",
                                                        repo.riskLevel === "high" && "border-orange-500 text-orange-500",
                                                        repo.riskLevel === "medium" && "border-yellow-500 text-yellow-500",
                                                        repo.riskLevel === "low" && "border-green-500 text-green-500"
                                                    )}
                                                >
                                                    Risk: {repo.riskScore}
                                                </Badge>
                                            </div>
                                            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
                                                {repo.criticalFindings > 0 && (
                                                    <span className="text-red-400">
                                                        {repo.criticalFindings} critical
                                                    </span>
                                                )}
                                                {repo.highFindings > 0 && (
                                                    <span className="text-orange-400">
                                                        {repo.highFindings} high
                                                    </span>
                                                )}
                                                {repo.secretsCount > 0 && (
                                                    <span className="text-purple-400">
                                                        {repo.secretsCount} secrets
                                                    </span>
                                                )}
                                                {repo.isArchived && (
                                                    <span className="text-slate-400">Archived</span>
                                                )}
                                                {repo.isAbandoned && (
                                                    <span className="text-slate-400">Abandoned</span>
                                                )}
                                            </div>
                                            <div className="text-xs text-primary pt-1 border-t">
                                                Click to view details
                                            </div>
                                        </div>
                                    </TooltipContent>
                                </Tooltip>
                            )
                        })}
                    </div>
                </TooltipProvider>

                {repos.length === 0 && (
                    <div className="flex items-center justify-center h-32 text-muted-foreground">
                        No repository risk data available
                    </div>
                )}
            </CardContent>
        </Card>
    )
}
