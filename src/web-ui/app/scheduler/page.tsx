"use client"

import { useEffect, useState, useCallback, useRef, useMemo } from "react"
import { SchedulerCalendar, ScheduleUpdateData } from "@/components/SchedulerCalendar"
import { RepositoryScheduleTable, RepositoryScheduleInfo } from "@/components/RepositoryScheduleTable"
import { OrganizationSelector } from "@/components/OrganizationSelector"
import { Loader2 } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"

const API_BASE = "http://localhost:8000"

// Schedule type from API
interface Schedule {
    id: string
    repository_id: string
    repository_name: string
    schedule_type: "ai" | "manual"
    frequency: "daily" | "weekly" | "bi-weekly" | "monthly"
    day_of_week: number | null
    time_window: "morning" | "afternoon" | "evening" | "night"
    scan_arguments: Record<string, unknown> | null
    next_scheduled_at: string | null
    is_locked: boolean
    ai_confidence: number | null
    locked_by_email?: string | null
    locked_at?: string | null
}

interface ScheduleListResponse {
    schedules: Schedule[]
    total: number
}

interface RepositoryScheduleListResponse {
    repositories: RepositoryScheduleInfo[]
    total: number
}

export default function SchedulerPage() {
    const [schedules, setSchedules] = useState<Schedule[]>([])
    const [repositories, setRepositories] = useState<RepositoryScheduleInfo[]>([])
    const [loading, setLoading] = useState(true)
    const [reposLoading, setReposLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    const { toast } = useToast()

    // Store previous state for rollback
    const previousSchedulesRef = useRef<Schedule[]>([])

    // Calculate schedule statistics
    const stats = useMemo(() => {
        const total = schedules.length
        const aiManaged = schedules.filter(s => s.schedule_type === "ai").length
        const locked = schedules.filter(s => s.is_locked).length
        return { total, aiManaged, locked }
    }, [schedules])

    // Fetch schedules on mount
    const fetchSchedules = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/schedules`, {
                credentials: 'include'
            })
            if (res.ok) {
                const data: ScheduleListResponse = await res.json()
                setSchedules(data.schedules || [])
            } else {
                // Handle non-OK response
                console.error("Failed to fetch schedules:", res.status)
                setError("Failed to load schedules")
            }
        } catch (err) {
            console.error("Failed to fetch schedules:", err)
            setError("Unable to connect to the API")
        } finally {
            setLoading(false)
        }
    }, [])

    // Fetch repositories with schedule info
    const fetchRepositories = useCallback(async () => {
        try {
            setReposLoading(true)
            const res = await fetch(`${API_BASE}/schedules/repositories`, {
                credentials: 'include'
            })
            if (res.ok) {
                const data: RepositoryScheduleListResponse = await res.json()
                setRepositories(data.repositories || [])
            } else {
                console.error("Failed to fetch repositories:", res.status)
            }
        } catch (err) {
            console.error("Failed to fetch repositories:", err)
        } finally {
            setReposLoading(false)
        }
    }, [])

    useEffect(() => {
        fetchSchedules()
        fetchRepositories()
    }, [fetchSchedules, fetchRepositories])

    // Handle schedule update from calendar drag-and-drop with optimistic UI
    const handleScheduleUpdate = useCallback(async (data: ScheduleUpdateData) => {
        // Store previous state for potential rollback
        previousSchedulesRef.current = [...schedules]

        // Optimistic update: immediately update local state
        setSchedules((prev) =>
            prev.map((schedule) => {
                if (schedule.repository_id === data.repoId) {
                    return {
                        ...schedule,
                        day_of_week: data.day_of_week,
                        time_window: data.time_window,
                        // Mark as manual since user overrode
                        schedule_type: "manual" as const,
                    }
                }
                return schedule
            })
        )

        try {
            const res = await fetch(`${API_BASE}/schedules/${data.repoId}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                credentials: 'include',
                body: JSON.stringify({
                    frequency: data.frequency,
                    day_of_week: data.day_of_week,
                    time_window: data.time_window,
                    override_reason: data.override_reason,
                }),
            })

            if (!res.ok) {
                throw new Error("Failed to update schedule")
            }

            // Show success toast
            toast({
                title: "Schedule updated",
                description: "The scan has been rescheduled successfully.",
            })

            // Refetch to get accurate server state (including next_scheduled_at)
            await fetchSchedules()
        } catch (err) {
            // Rollback to previous state on error
            setSchedules(previousSchedulesRef.current)

            // Show error toast
            toast({
                variant: "destructive",
                title: "Failed to update schedule",
                description: err instanceof Error ? err.message : "An unexpected error occurred",
            })

            // Re-throw so the dialog can handle it
            throw err
        }
    }, [schedules, fetchSchedules, toast])

    // Handle lock schedule with optimistic UI
    const handleLockSchedule = useCallback(async (repoId: string, reason: string) => {
        // Store previous state for potential rollback
        previousSchedulesRef.current = [...schedules]

        // Optimistic update: immediately update local state
        setSchedules((prev) =>
            prev.map((schedule) => {
                if (schedule.repository_id === repoId) {
                    return {
                        ...schedule,
                        is_locked: true,
                        schedule_type: "manual" as const,
                    }
                }
                return schedule
            })
        )

        try {
            const res = await fetch(`${API_BASE}/schedules/${repoId}/lock`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: 'include',
                body: JSON.stringify({ reason }),
            })

            if (!res.ok) {
                throw new Error("Failed to lock schedule")
            }

            // Show success toast
            toast({
                title: "Schedule locked",
                description: "The schedule has been locked and will not be modified by AI.",
            })

            // Refetch to get accurate server state
            await fetchSchedules()
        } catch (err) {
            // Rollback to previous state on error
            setSchedules(previousSchedulesRef.current)

            // Show error toast
            toast({
                variant: "destructive",
                title: "Failed to lock schedule",
                description: err instanceof Error ? err.message : "An unexpected error occurred",
            })

            // Re-throw so the dialog can handle it
            throw err
        }
    }, [schedules, fetchSchedules, toast])

    // Handle unlock schedule with optimistic UI
    const handleUnlockSchedule = useCallback(async (repoId: string) => {
        // Store previous state for potential rollback
        previousSchedulesRef.current = [...schedules]

        // Optimistic update: immediately update local state
        setSchedules((prev) =>
            prev.map((schedule) => {
                if (schedule.repository_id === repoId) {
                    return {
                        ...schedule,
                        is_locked: false,
                        schedule_type: "ai" as const,
                        locked_by_email: null,
                        locked_at: null,
                    }
                }
                return schedule
            })
        )

        try {
            const res = await fetch(`${API_BASE}/schedules/${repoId}/lock`, {
                method: "DELETE",
                credentials: 'include',
            })

            if (!res.ok) {
                throw new Error("Failed to unlock schedule")
            }

            // Show success toast
            toast({
                title: "Schedule unlocked",
                description: "The schedule has been returned to AI management.",
            })

            // Refetch to get accurate server state
            await fetchSchedules()
        } catch (err) {
            // Rollback to previous state on error
            setSchedules(previousSchedulesRef.current)

            // Show error toast
            toast({
                variant: "destructive",
                title: "Failed to unlock schedule",
                description: err instanceof Error ? err.message : "An unexpected error occurred",
            })

            // Re-throw so the dialog can handle it
            throw err
        }
    }, [schedules, fetchSchedules, toast])

    // Handle update scanners with optimistic UI
    const handleUpdateScanners = useCallback(async (repoId: string, scanners: string[] | null) => {
        // Find the schedule to get current settings
        const schedule = schedules.find((s) => s.repository_id === repoId)
        if (!schedule) return

        // Store previous state for potential rollback
        previousSchedulesRef.current = [...schedules]

        // Compute new scan_arguments
        const newScanArguments = scanners && scanners.length > 0
            ? { scanners: scanners.join(",") }
            : null

        // Optimistic update: immediately update local state
        setSchedules((prev) =>
            prev.map((s) => {
                if (s.repository_id === repoId) {
                    return {
                        ...s,
                        scan_arguments: newScanArguments,
                    }
                }
                return s
            })
        )

        try {
            const res = await fetch(`${API_BASE}/schedules/${repoId}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                credentials: 'include',
                body: JSON.stringify({
                    frequency: schedule.frequency,
                    day_of_week: schedule.day_of_week,
                    time_window: schedule.time_window,
                    scan_arguments: newScanArguments,
                    override_reason: "Updated scanner configuration",
                }),
            })

            if (!res.ok) {
                throw new Error("Failed to update scanners")
            }

            // Show success toast
            toast({
                title: "Scanner config updated",
                description: scanners && scanners.length > 0
                    ? `${scanners.length} scanner${scanners.length !== 1 ? "s" : ""} selected.`
                    : "Using all scanners (default).",
            })

            // Refetch to get accurate server state
            await fetchSchedules()
        } catch (err) {
            // Rollback to previous state on error
            setSchedules(previousSchedulesRef.current)

            // Show error toast
            toast({
                variant: "destructive",
                title: "Failed to update scanners",
                description: err instanceof Error ? err.message : "An unexpected error occurred",
            })

            // Re-throw so the dialog can handle it
            throw err
        }
    }, [schedules, fetchSchedules, toast])

    // Handle creating a new schedule for a repository
    const handleCreateSchedule = useCallback((repoId: string) => {
        // TODO: Open schedule creation dialog
        toast({
            title: "Create schedule",
            description: `Schedule creation for repository ${repoId} will be available in the next update.`,
        })
    }, [toast])

    // Handle editing an existing schedule
    const handleEditSchedule = useCallback((repoId: string) => {
        // TODO: Open schedule edit dialog
        toast({
            title: "Edit schedule",
            description: `Schedule editing for repository ${repoId} will be available in the next update.`,
        })
    }, [toast])

    // Handle triggering an immediate scan
    const handleTriggerScan = useCallback(async (repoId: string) => {
        try {
            const res = await fetch(`${API_BASE}/scans`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: 'include',
                body: JSON.stringify({
                    repository_id: repoId,
                    scan_type: "full",
                }),
            })

            if (!res.ok) {
                throw new Error("Failed to trigger scan")
            }

            toast({
                title: "Scan triggered",
                description: "The scan has been queued and will start shortly.",
            })

            // Refresh repositories to update last_scanned_at
            await fetchRepositories()
        } catch (err) {
            toast({
                variant: "destructive",
                title: "Failed to trigger scan",
                description: err instanceof Error ? err.message : "An unexpected error occurred",
            })
        }
    }, [fetchRepositories, toast])

    if (loading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    if (error) {
        return (
            <div className="flex flex-1 flex-col gap-6 p-6">
                <div className="flex items-start justify-between">
                    <div>
                        <h1 className="text-3xl font-bold tracking-tight">Scan Scheduler</h1>
                        <p className="text-muted-foreground">
                            AI-powered scan scheduling with manual override support.
                        </p>
                    </div>
                    <OrganizationSelector />
                </div>
                <div className="flex flex-col items-center justify-center h-96 border border-dashed rounded-lg">
                    <p className="text-destructive">{error}</p>
                    <p className="text-muted-foreground text-sm mt-2">
                        Make sure the API server is running at {API_BASE}
                    </p>
                </div>
            </div>
        )
    }

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Scan Scheduler</h1>
                    <p className="text-muted-foreground">
                        AI-powered scan scheduling with manual override support.
                    </p>
                </div>
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2">
                        <Badge variant="outline">{stats.total} total</Badge>
                        <Badge variant="outline">{stats.aiManaged} AI-managed</Badge>
                        <Badge variant="outline">{stats.locked} locked</Badge>
                    </div>
                    <OrganizationSelector />
                </div>
            </div>
            <SchedulerCalendar
                schedules={schedules}
                onScheduleUpdate={handleScheduleUpdate}
                onScheduleLock={handleLockSchedule}
                onScheduleUnlock={handleUnlockSchedule}
                onUpdateScanners={handleUpdateScanners}
            />

            <Separator className="my-2" />

            {/* Repository Schedule Table */}
            <div>
                <h2 className="text-xl font-semibold mb-4">Repository Schedules</h2>
                <p className="text-muted-foreground text-sm mb-4">
                    View and manage scan schedules for all repositories. Create schedules for unscheduled repos or modify existing ones.
                </p>
                <RepositoryScheduleTable
                    repositories={repositories}
                    onCreateSchedule={handleCreateSchedule}
                    onEditSchedule={handleEditSchedule}
                    onTriggerScan={handleTriggerScan}
                    isLoading={reposLoading}
                />
            </div>
        </div>
    )
}
