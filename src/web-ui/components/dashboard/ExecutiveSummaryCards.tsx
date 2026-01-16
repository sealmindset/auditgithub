"use client"

import { useEffect, useState } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import Link from "next/link"
import {
    AlertOctagon,
    TrendingUp,
    TrendingDown,
    Target,
    ArrowRight,
    Shield,
    GitBranch,
    Scan,
    Key
} from "lucide-react"
import { FeedbackButton } from "./FeedbackButton"

const API_BASE = "http://localhost:8000"

interface ImmediateAction {
    title: string
    count: number
    description: string
    severity: "critical" | "high" | "medium"
    link: string
}

interface TrendItem {
    label: string
    value: string
    direction: "up" | "down" | "neutral"
    isGood: boolean
}

interface ExecutiveSummaryData {
    immediateActions: ImmediateAction[]
    trends: TrendItem[]
    posture: {
        grade: string
        score: number
        summary: string
    }
}

function getGradeColor(grade: string): string {
    if (grade.startsWith("A")) return "text-green-500"
    if (grade.startsWith("B")) return "text-lime-500"
    if (grade.startsWith("C")) return "text-yellow-500"
    if (grade.startsWith("D")) return "text-orange-500"
    return "text-red-500"
}

function getGradeBgColor(grade: string): string {
    if (grade.startsWith("A")) return "bg-green-500/10 border-green-500/30"
    if (grade.startsWith("B")) return "bg-lime-500/10 border-lime-500/30"
    if (grade.startsWith("C")) return "bg-yellow-500/10 border-yellow-500/30"
    if (grade.startsWith("D")) return "bg-orange-500/10 border-orange-500/30"
    return "bg-red-500/10 border-red-500/30"
}

export function ExecutiveSummaryCards() {
    const [data, setData] = useState<ExecutiveSummaryData | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await fetch(`${API_BASE}/analytics/executive-summary`)
                if (response.ok) {
                    setData(await response.json())
                }
            } catch (error) {
                console.error("Failed to fetch executive summary:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchData()
        const interval = setInterval(fetchData, 60000) // Refresh every minute
        return () => clearInterval(interval)
    }, [])

    if (loading || !data) {
        return (
            <div className="grid gap-6 md:grid-cols-3">
                {[1, 2, 3].map((i) => (
                    <Card key={i} className="animate-pulse">
                        <CardContent className="p-6 h-48 bg-muted/20" />
                    </Card>
                ))}
            </div>
        )
    }

    return (
        <div className="grid gap-6 md:grid-cols-3">
            {/* Immediate Action Card */}
            <Card className="relative overflow-hidden border-red-500/30 bg-gradient-to-br from-red-500/5 to-transparent">
                <div className="absolute top-2 right-2">
                    <FeedbackButton
                        componentId="executive-immediate-action"
                        componentName="Immediate Action Card"
                    />
                </div>
                <CardContent className="p-6">
                    <div className="flex items-center gap-2 mb-4">
                        <div className="p-2 rounded-lg bg-red-500/20">
                            <AlertOctagon className="h-5 w-5 text-red-500" />
                        </div>
                        <div>
                            <h3 className="font-semibold text-sm">IMMEDIATE ACTION</h3>
                            <p className="text-xs text-muted-foreground">Requires attention now</p>
                        </div>
                    </div>

                    <div className="space-y-3">
                        {data.immediateActions.slice(0, 3).map((action, index) => (
                            <div
                                key={index}
                                className={cn(
                                    "flex items-start gap-2 p-2 rounded-md",
                                    action.severity === "critical" && "bg-red-500/10",
                                    action.severity === "high" && "bg-orange-500/10",
                                    action.severity === "medium" && "bg-yellow-500/10"
                                )}
                            >
                                {action.title.toLowerCase().includes("secret") ? (
                                    <Key className="h-4 w-4 mt-0.5 text-red-400 shrink-0" />
                                ) : action.title.toLowerCase().includes("repo") ? (
                                    <GitBranch className="h-4 w-4 mt-0.5 text-orange-400 shrink-0" />
                                ) : (
                                    <Shield className="h-4 w-4 mt-0.5 text-yellow-400 shrink-0" />
                                )}
                                <div className="min-w-0 flex-1">
                                    <p className="text-sm font-medium leading-tight">
                                        {action.count} {action.title}
                                    </p>
                                    <p className="text-xs text-muted-foreground truncate">
                                        {action.description}
                                    </p>
                                </div>
                            </div>
                        ))}
                    </div>

                    <Link href="/findings?severity=critical" className="block mt-4">
                        <Button variant="outline" size="sm" className="w-full gap-2 border-red-500/30 hover:bg-red-500/10">
                            View All Actions
                            <ArrowRight className="h-4 w-4" />
                        </Button>
                    </Link>
                </CardContent>
            </Card>

            {/* This Week Trends Card */}
            <Card className="relative overflow-hidden border-blue-500/30 bg-gradient-to-br from-blue-500/5 to-transparent">
                <div className="absolute top-2 right-2">
                    <FeedbackButton
                        componentId="executive-weekly-trends"
                        componentName="Weekly Trends Card"
                    />
                </div>
                <CardContent className="p-6">
                    <div className="flex items-center gap-2 mb-4">
                        <div className="p-2 rounded-lg bg-blue-500/20">
                            <TrendingUp className="h-5 w-5 text-blue-500" />
                        </div>
                        <div>
                            <h3 className="font-semibold text-sm">THIS WEEK</h3>
                            <p className="text-xs text-muted-foreground">Trends & progress</p>
                        </div>
                    </div>

                    <div className="space-y-3">
                        {data.trends.map((trend, index) => (
                            <div
                                key={index}
                                className="flex items-center justify-between p-2 rounded-md bg-muted/30"
                            >
                                <div className="flex items-center gap-2">
                                    {trend.direction === "up" ? (
                                        <TrendingUp className={cn(
                                            "h-4 w-4",
                                            trend.isGood ? "text-green-500" : "text-red-500"
                                        )} />
                                    ) : trend.direction === "down" ? (
                                        <TrendingDown className={cn(
                                            "h-4 w-4",
                                            trend.isGood ? "text-green-500" : "text-red-500"
                                        )} />
                                    ) : (
                                        <Scan className="h-4 w-4 text-blue-500" />
                                    )}
                                    <span className="text-sm">{trend.label}</span>
                                </div>
                                <span className={cn(
                                    "text-sm font-semibold",
                                    trend.isGood ? "text-green-500" : trend.direction !== "neutral" ? "text-red-500" : "text-blue-500"
                                )}>
                                    {trend.value}
                                </span>
                            </div>
                        ))}
                    </div>

                    <Link href="/analytics" className="block mt-4">
                        <Button variant="outline" size="sm" className="w-full gap-2 border-blue-500/30 hover:bg-blue-500/10">
                            View Analytics
                            <ArrowRight className="h-4 w-4" />
                        </Button>
                    </Link>
                </CardContent>
            </Card>

            {/* Security Posture Card */}
            <Card className={cn(
                "relative overflow-hidden",
                getGradeBgColor(data.posture.grade)
            )}>
                <div className="absolute top-2 right-2">
                    <FeedbackButton
                        componentId="executive-security-posture"
                        componentName="Security Posture Card"
                    />
                </div>
                <CardContent className="p-6">
                    <div className="flex items-center gap-2 mb-4">
                        <div className={cn(
                            "p-2 rounded-lg",
                            data.posture.grade.startsWith("A") || data.posture.grade.startsWith("B")
                                ? "bg-green-500/20"
                                : data.posture.grade.startsWith("C")
                                    ? "bg-yellow-500/20"
                                    : "bg-red-500/20"
                        )}>
                            <Target className={cn(
                                "h-5 w-5",
                                getGradeColor(data.posture.grade)
                            )} />
                        </div>
                        <div>
                            <h3 className="font-semibold text-sm">SECURITY POSTURE</h3>
                            <p className="text-xs text-muted-foreground">Overall assessment</p>
                        </div>
                    </div>

                    <div className="flex items-center justify-center my-6">
                        <div className={cn(
                            "relative w-24 h-24 rounded-full border-4 flex items-center justify-center",
                            getGradeBgColor(data.posture.grade)
                        )}>
                            <div className="text-center">
                                <span className={cn(
                                    "text-4xl font-bold",
                                    getGradeColor(data.posture.grade)
                                )}>
                                    {data.posture.grade}
                                </span>
                                <p className="text-xs text-muted-foreground">{data.posture.score}%</p>
                            </div>
                        </div>
                    </div>

                    <p className="text-sm text-center text-muted-foreground mb-4 italic">
                        "{data.posture.summary}"
                    </p>

                    <Link href="/reports" className="block">
                        <Button variant="outline" size="sm" className={cn(
                            "w-full gap-2",
                            data.posture.grade.startsWith("A") || data.posture.grade.startsWith("B")
                                ? "border-green-500/30 hover:bg-green-500/10"
                                : data.posture.grade.startsWith("C")
                                    ? "border-yellow-500/30 hover:bg-yellow-500/10"
                                    : "border-red-500/30 hover:bg-red-500/10"
                        )}>
                            Full Report
                            <ArrowRight className="h-4 w-4" />
                        </Button>
                    </Link>
                </CardContent>
            </Card>
        </div>
    )
}
