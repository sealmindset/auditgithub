"use client"

import { useState, useEffect, useCallback } from "react"
import { format, formatDistanceToNow } from "date-fns"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import {
    Loader2,
    Play,
    CheckCircle2,
    XCircle,
    Clock,
    RefreshCw,
    Zap,
    Calendar,
    Timer,
    GitBranch,
    AlertTriangle
} from "lucide-react"
import { cn } from "@/lib/utils"
import { API_BASE, apiFetch } from "@/lib/api"

interface TodayScan {
    schedule_id: string
    repository_id: string
    repository_name: string
    organization_name: string | null
    scheduled_time: string | null
    started_at: string | null
    completed_at: string | null
    status: "scheduled" | "running" | "completed" | "failed"
    frequency: string
    time_window: string
    progress_percent: number | null
    error_message: string | null
    duration_seconds: number | null
    findings_count: number | null
}

interface TodayScansData {
    scans: TodayScan[]
    total_scheduled: number
    total_running: number
    total_completed: number
    total_failed: number
    current_time: string
}

interface TodayScansResponse {
    scans: TodayScan[]
    total_scheduled: number
    total_running: number
    total_completed: number
    total_failed: number
    current_time: string
}

// Animated progress bar for running scans
function AnimatedProgress({ value }: { value: number }) {
    return (
        <div className="relative w-full">
            <Progress value={value} className="h-2" />
            <div
                className="absolute top-0 left-0 h-2 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer"
                style={{ width: '100%' }}
            />
        </div>
    )
}

// Status badge with appropriate styling
function StatusBadge({ status }: { status: string }) {
    const config = {
        scheduled: {
            icon: Clock,
            label: "Scheduled",
            className: "bg-info-soft text-info-text dark:bg-info-soft/30 border-info-line"
        },
        running: {
            icon: Loader2,
            label: "Running",
            className: "bg-warning-soft text-warning-text dark:bg-warning-soft/30 border-warning-line animate-pulse"
        },
        completed: {
            icon: CheckCircle2,
            label: "Completed",
            className: "bg-success-soft text-success-text dark:bg-success-soft/30 border-success-line"
        },
        failed: {
            icon: XCircle,
            label: "Failed",
            className: "bg-danger-soft text-danger-text dark:bg-danger-soft/30 border-danger-line"
        }
    }

    const { icon: Icon, label, className } = config[status as keyof typeof config] || config.scheduled

    return (
        <Badge variant="outline" className={cn("gap-1.5 font-medium", className)}>
            <Icon className={cn("h-3.5 w-3.5", status === "running" && "animate-spin")} />
            {label}
        </Badge>
    )
}

// Single scan card
function ScanCard({ scan, onTrigger }: { scan: TodayScan; onTrigger: (repoId: string) => void }) {
    const isRunning = scan.status === "running"
    const isScheduled = scan.status === "scheduled"
    const isCompleted = scan.status === "completed"
    const isFailed = scan.status === "failed"

    const scheduledTime = scan.scheduled_time ? new Date(scan.scheduled_time) : null
    const startedAt = scan.started_at ? new Date(scan.started_at) : null

    return (
        <div
            className={cn(
                "group relative rounded-lg border p-4 transition-all duration-200",
                "hover:shadow-md hover:border-primary/30",
                isRunning && "border-warning/50 bg-warning-soft/50 dark:bg-warning-soft/20",
                isCompleted && "border-success/30 bg-success-soft/30 dark:bg-success-soft/10",
                isFailed && "border-danger/30 bg-danger-soft/30 dark:bg-danger-soft/10",
                isScheduled && "border-info/30 bg-info-soft/30 dark:bg-info-soft/10"
            )}
        >
            {/* Running indicator pulse */}
            {isRunning && (
                <div className="absolute -top-1 -right-1 h-3 w-3">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-warning opacity-75" />
                    <span className="relative inline-flex h-3 w-3 rounded-full bg-warning" />
                </div>
            )}

            <div className="flex items-start justify-between gap-4">
                {/* Left: Repo info */}
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                        <GitBranch className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                        <h4 className="font-semibold truncate">{scan.repository_name}</h4>
                    </div>
                    {scan.organization_name && (
                        <p className="text-sm text-muted-foreground truncate">{scan.organization_name}</p>
                    )}

                    {/* Time info */}
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                        {isScheduled && scheduledTime && (
                            <span className="flex items-center gap-1">
                                <Calendar className="h-3 w-3" />
                                {format(scheduledTime, "h:mm a")}
                            </span>
                        )}
                        {(isRunning || isCompleted || isFailed) && startedAt && (
                            <span className="flex items-center gap-1">
                                <Timer className="h-3 w-3" />
                                Started {formatDistanceToNow(startedAt, { addSuffix: true })}
                            </span>
                        )}
                        <span className="flex items-center gap-1">
                            <Zap className="h-3 w-3" />
                            {scan.frequency}
                        </span>
                    </div>

                    {/* Progress bar for running scans */}
                    {isRunning && scan.progress_percent !== null && (
                        <div className="mt-3">
                            <div className="flex items-center justify-between text-xs mb-1">
                                <span className="text-muted-foreground">Scanning...</span>
                                <span className="font-medium">{scan.progress_percent}%</span>
                            </div>
                            <AnimatedProgress value={scan.progress_percent} />
                        </div>
                    )}

                    {/* Error message for failed scans */}
                    {isFailed && scan.error_message && (
                        <div className="mt-2 flex items-start gap-1.5 text-xs text-danger-text">
                            <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
                            <span className="line-clamp-2">{scan.error_message}</span>
                        </div>
                    )}
                </div>

                {/* Right: Status and actions */}
                <div className="flex flex-col items-end gap-2">
                    <StatusBadge status={scan.status} />

                    {/* Trigger button for scheduled scans */}
                    {isScheduled && (
                        <TooltipProvider>
                            <Tooltip>
                                <TooltipTrigger asChild>
                                    <Button
                                        size="sm"
                                        variant="outline"
                                        className="h-8 px-3 opacity-0 group-hover:opacity-100 transition-opacity"
                                        onClick={() => onTrigger(scan.repository_id)}
                                    >
                                        <Play className="h-3.5 w-3.5 mr-1" />
                                        Run Now
                                    </Button>
                                </TooltipTrigger>
                                <TooltipContent>
                                    <p>Start scan immediately</p>
                                </TooltipContent>
                            </Tooltip>
                        </TooltipProvider>
                    )}

                    {/* Findings count for completed scans */}
                    {isCompleted && scan.findings_count !== null && (
                        <span className="text-xs text-muted-foreground">
                            {scan.findings_count} findings
                        </span>
                    )}
                </div>
            </div>
        </div>
    )
}

// Empty state
function EmptyState() {
    return (
        <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="rounded-full bg-muted p-4 mb-4">
                <Calendar className="h-8 w-8 text-muted-foreground" />
            </div>
            <h3 className="font-semibold text-lg mb-1">No scans for today</h3>
            <p className="text-sm text-muted-foreground max-w-sm">
                There are no scans scheduled for today. Check the Activity Graph to see upcoming scan distribution.
            </p>
        </div>
    )
}

// Stats card
function StatsCard({ icon: Icon, label, value, color }: {
    icon: React.ElementType
    label: string
    value: number
    color: string
}) {
    return (
        <div className={cn(
            "flex items-center gap-3 rounded-lg border p-4",
            color
        )}>
            <div className="rounded-full p-2 bg-background/80">
                <Icon className="h-5 w-5" />
            </div>
            <div>
                <p className="text-2xl font-bold">{value}</p>
                <p className="text-xs text-muted-foreground">{label}</p>
            </div>
        </div>
    )
}

export function TodayScansPanel() {
    const [data, setData] = useState<TodayScansData | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    const [triggeringRepo, setTriggeringRepo] = useState<string | null>(null)

    const fetchData = useCallback(async () => {
        try {
            const res = await apiFetch(`${API_BASE}/schedules/today`, {
                credentials: "include"
            })
            if (!res.ok) throw new Error("Failed to fetch today's scans")
            const json: TodayScansResponse = await res.json()
            setData(json)
            setError(null)
        } catch (err) {
            setError(err instanceof Error ? err.message : "An error occurred")
        } finally {
            setLoading(false)
        }
    }, [])

    // Initial fetch
    useEffect(() => {
        fetchData()
    }, [fetchData])

    // Auto-refresh every 10 seconds when there are running scans
    useEffect(() => {
        if (!data?.total_running) return

        const interval = setInterval(fetchData, 10000)
        return () => clearInterval(interval)
    }, [data?.total_running, fetchData])

    const handleTriggerScan = async (repoId: string) => {
        setTriggeringRepo(repoId)
        try {
            const res = await apiFetch(`${API_BASE}/schedules/${repoId}/trigger`, {
                method: "POST",
                credentials: "include"
            })
            if (!res.ok) throw new Error("Failed to trigger scan")
            // Refresh data after triggering
            await fetchData()
        } catch (err) {
            console.error("Failed to trigger scan:", err)
        } finally {
            setTriggeringRepo(null)
        }
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center py-12">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        )
    }

    if (error) {
        return (
            <div className="flex flex-col items-center justify-center py-12 text-center">
                <XCircle className="h-8 w-8 text-danger-text mb-2" />
                <p className="text-sm text-muted-foreground">{error}</p>
                <Button variant="outline" size="sm" className="mt-4" onClick={fetchData}>
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Retry
                </Button>
            </div>
        )
    }

    if (!data) return null

    const hasScans = data.scans.length > 0

    return (
        <div className="space-y-6">
            {/* Header with stats */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-xl font-semibold">Today's Scans</h2>
                    <p className="text-sm text-muted-foreground">
                        {format(new Date(data.current_time), "EEEE, MMMM d, yyyy")}
                    </p>
                </div>
                <Button variant="outline" size="sm" onClick={fetchData}>
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                </Button>
            </div>

            {/* Stats cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatsCard
                    icon={Clock}
                    label="Scheduled"
                    value={data.total_scheduled}
                    color="border-info-line bg-info-soft/50 dark:bg-info-soft/20"
                />
                <StatsCard
                    icon={Loader2}
                    label="Running"
                    value={data.total_running}
                    color="border-warning-line bg-warning-soft/50 dark:bg-warning-soft/20"
                />
                <StatsCard
                    icon={CheckCircle2}
                    label="Completed"
                    value={data.total_completed}
                    color="border-success-line bg-success-soft/50 dark:bg-success-soft/20"
                />
                <StatsCard
                    icon={XCircle}
                    label="Failed"
                    value={data.total_failed}
                    color="border-danger-line bg-danger-soft/50 dark:bg-danger-soft/20"
                />
            </div>

            {/* Scans list */}
            {hasScans ? (
                <div className="space-y-3">
                    {data.scans.map((scan) => (
                        <ScanCard
                            key={scan.schedule_id}
                            scan={scan}
                            onTrigger={handleTriggerScan}
                        />
                    ))}
                </div>
            ) : (
                <EmptyState />
            )}

            {/* Auto-refresh indicator */}
            {data.total_running > 0 && (
                <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    Auto-refreshing every 10 seconds
                </div>
            )}
        </div>
    )
}
