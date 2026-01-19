"use client"

import { useEffect, useState, useCallback, useRef, useMemo } from "react"
import { SchedulerCalendar, ScheduleUpdateData } from "@/components/SchedulerCalendar"
import { RepositoryScheduleTable, RepositoryScheduleInfo } from "@/components/RepositoryScheduleTable"
import { ScheduleCreateDialog } from "@/components/ScheduleCreateDialog"
import { ScheduleEditDialog } from "@/components/ScheduleEditDialog"
import { OrganizationSelector } from "@/components/OrganizationSelector"
import { Loader2, Bot, RefreshCw, Wand2, CalendarDays, BarChart3, Table2, Radar } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/components/ui/use-toast"
import { Badge } from "@/components/ui/badge"
import { ScanActivityGraph } from "@/components/ScanActivityGraph"
import { TodayScansPanel } from "@/components/TodayScansPanel"

const API_BASE = "http://localhost:8000"

// Schedule type from API
interface Schedule {
    id: string
    repository_id: string
    repository_name: string
    schedule_type: "ai" | "manual"
    frequency: "daily" | "weekly" | "bi-weekly" | "monthly" | "annually"
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
    const [createDialogOpen, setCreateDialogOpen] = useState(false)
    const [selectedRepoForCreate, setSelectedRepoForCreate] = useState<{id: string, name: string} | null>(null)
    const [editDialogOpen, setEditDialogOpen] = useState(false)
    const [selectedScheduleForEdit, setSelectedScheduleForEdit] = useState<Schedule | null>(null)
    const [applyingAI, setApplyingAI] = useState(false)
    const [refreshingAI, setRefreshingAI] = useState(false)
    const { toast } = useToast()

    // Store previous state for rollback
    const previousSchedulesRef = useRef<Schedule[]>([])

    // Calculate schedule statistics
    const stats = useMemo(() => {
        const total = schedules.length
        const aiManaged = schedules.filter(s => s.schedule_type === "ai").length
        const locked = schedules.filter(s => s.is_locked).length
        const unscheduled = repositories.filter(r => !r.has_schedule && !r.is_archived).length

        // Debug logging
        console.log('[Stats] Total repos:', repositories.length)
        console.log('[Stats] Archived repos:', repositories.filter(r => r.is_archived).length)
        console.log('[Stats] Active repos:', repositories.filter(r => !r.is_archived).length)
        console.log('[Stats] Repos with schedules:', repositories.filter(r => r.has_schedule).length)
        console.log('[Stats] Unscheduled active repos:', unscheduled)

        return { total, aiManaged, locked, unscheduled }
    }, [schedules, repositories])

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
        // Find the repo name
        const repo = repositories.find(r => r.repository_id === repoId)
        if (repo) {
            setSelectedRepoForCreate({ id: repoId, name: repo.repository_name })
            setCreateDialogOpen(true)
        }
    }, [repositories])

    // Handle schedule created - refresh data
    const handleScheduleCreated = useCallback(async () => {
        toast({
            title: "Schedule created",
            description: "The scan schedule has been created successfully.",
        })
        await Promise.all([fetchSchedules(), fetchRepositories()])
    }, [fetchSchedules, fetchRepositories, toast])

    // Handle editing an existing schedule
    const handleEditSchedule = useCallback((repoId: string) => {
        // Find the schedule for this repository
        const schedule = schedules.find(s => s.repository_id === repoId)
        if (schedule) {
            setSelectedScheduleForEdit(schedule)
            setEditDialogOpen(true)
        } else {
            toast({
                variant: "destructive",
                title: "Schedule not found",
                description: "Could not find the schedule for this repository.",
            })
        }
    }, [schedules, toast])

    // Handle schedule updated - refresh data
    const handleScheduleUpdated = useCallback(async () => {
        toast({
            title: "Schedule updated",
            description: "The scan schedule has been updated successfully.",
        })
        await Promise.all([fetchSchedules(), fetchRepositories()])
    }, [fetchSchedules, fetchRepositories, toast])

    // Handle triggering an immediate scan
    const handleTriggerScan = useCallback(async (repoId: string) => {
        try {
            const res = await fetch(`${API_BASE}/schedules/${repoId}/trigger`, {
                method: "POST",
                credentials: 'include',
            })

            if (!res.ok) {
                const data = await res.json().catch(() => ({}))
                throw new Error(data.detail || "Failed to trigger scan")
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

    // Handle applying AI schedules to all unscheduled repositories
    const handleApplyAISchedules = useCallback(async () => {
        console.log('[AI Schedule] Starting to apply AI schedules...')
        setApplyingAI(true)
        try {
            console.log('[AI Schedule] Fetching:', `${API_BASE}/schedules/batch/apply-ai`)
            const res = await fetch(`${API_BASE}/schedules/batch/apply-ai`, {
                method: "POST",
                credentials: 'include',
            })

            console.log('[AI Schedule] Response status:', res.status)
            if (!res.ok) {
                const data = await res.json().catch(() => ({}))
                console.error('[AI Schedule] Error response:', data)
                throw new Error(data.detail || "Failed to apply AI schedules")
            }

            const result = await res.json()
            console.log('[AI Schedule] Success result:', result)

            // Detailed message based on results
            let message = ""
            let title = ""

            if (result.created === 0 && result.skipped === 0 && result.errors === 0) {
                title = "No changes made"
                message = "No repositories found to schedule. All active repositories already have schedules."
            } else if (result.created === 0 && result.skipped > 0) {
                title = "No schedules created"
                message = `${result.skipped} repositories were skipped (likely archived or already scheduled). No new schedules were created.`
            } else if (result.created > 0) {
                title = "AI schedules applied"
                message = `✓ Created ${result.created} new schedules\n${result.skipped > 0 ? `⊘ Skipped ${result.skipped} repositories\n` : ''}${result.errors > 0 ? `✗ Errors: ${result.errors}` : ''}`
            } else {
                title = "Scheduling completed"
                message = `Created: ${result.created}, Skipped: ${result.skipped}, Errors: ${result.errors}`
            }

            toast({
                title,
                description: message,
            })

            // Refresh data
            await Promise.all([fetchSchedules(), fetchRepositories()])
        } catch (err) {
            console.error('[AI Schedule] Exception:', err)
            toast({
                variant: "destructive",
                title: "Failed to apply AI schedules",
                description: err instanceof Error ? err.message : "An unexpected error occurred",
            })
        } finally {
            setApplyingAI(false)
        }
    }, [fetchSchedules, fetchRepositories, toast])

    // Handle refreshing AI recommendations for existing AI-managed schedules
    const handleRefreshAISchedules = useCallback(async () => {
        setRefreshingAI(true)
        try {
            const res = await fetch(`${API_BASE}/schedules/batch/refresh-ai`, {
                method: "POST",
                credentials: 'include',
            })

            if (!res.ok) {
                const data = await res.json().catch(() => ({}))
                throw new Error(data.detail || "Failed to refresh AI schedules")
            }

            const result = await res.json()
            toast({
                title: "AI schedules refreshed",
                description: `Updated ${result.created} schedules based on latest AI recommendations`,
            })

            // Refresh data
            await Promise.all([fetchSchedules(), fetchRepositories()])
        } catch (err) {
            toast({
                variant: "destructive",
                title: "Failed to refresh AI schedules",
                description: err instanceof Error ? err.message : "An unexpected error occurred",
            })
        } finally {
            setRefreshingAI(false)
        }
    }, [fetchSchedules, fetchRepositories, toast])

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
                        <Badge variant="outline">{stats.total} scheduled</Badge>
                        <Badge variant="outline">{stats.aiManaged} AI-managed</Badge>
                        <Badge variant="outline">{stats.locked} locked</Badge>
                        {stats.unscheduled > 0 && (
                            <Badge variant="secondary" className="bg-amber-100 text-amber-800">
                                {stats.unscheduled} unscheduled
                            </Badge>
                        )}
                    </div>
                    <OrganizationSelector />
                </div>
            </div>

            {/* AI Scheduling Actions */}
            <div className="flex items-center gap-3 p-4 rounded-lg border bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-950/20 dark:to-purple-950/20">
                <Bot className="h-5 w-5 text-blue-500" />
                <div className="flex-1">
                    <p className="text-sm font-medium">AI-Powered Scheduling</p>
                    <p className="text-xs text-muted-foreground">
                        Automatically schedule scans based on repository activity, findings, and risk profile.
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    {stats.unscheduled > 0 && (
                        <Button
                            variant="default"
                            size="sm"
                            onClick={handleApplyAISchedules}
                            disabled={applyingAI || refreshingAI}
                            className="bg-blue-600 hover:bg-blue-700"
                        >
                            {applyingAI ? (
                                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                            ) : (
                                <Wand2 className="h-4 w-4 mr-2" />
                            )}
                            Schedule {stats.unscheduled} Repos
                        </Button>
                    )}
                    {stats.aiManaged > 0 && (
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={handleRefreshAISchedules}
                            disabled={applyingAI || refreshingAI}
                        >
                            {refreshingAI ? (
                                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                            ) : (
                                <RefreshCw className="h-4 w-4 mr-2" />
                            )}
                            Refresh AI Schedules
                        </Button>
                    )}
                    {stats.unscheduled === 0 && stats.aiManaged === 0 && (
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={handleApplyAISchedules}
                            disabled={applyingAI}
                        >
                            {applyingAI ? (
                                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                            ) : (
                                <Wand2 className="h-4 w-4 mr-2" />
                            )}
                            Apply AI Schedules
                        </Button>
                    )}
                </div>
            </div>

            {/* Tabs for Activity Graph, Calendar, Repository Schedules, and Scans */}
            <Tabs defaultValue="activity" className="space-y-4">
                <TabsList>
                    <TabsTrigger value="activity" className="gap-2">
                        <BarChart3 className="h-4 w-4" />
                        Activity Graph
                    </TabsTrigger>
                    <TabsTrigger value="calendar" className="gap-2">
                        <CalendarDays className="h-4 w-4" />
                        Calendar
                    </TabsTrigger>
                    <TabsTrigger value="schedules" className="gap-2">
                        <Table2 className="h-4 w-4" />
                        Repository Schedules
                    </TabsTrigger>
                    <TabsTrigger value="scans" className="gap-2">
                        <Radar className="h-4 w-4" />
                        Scans
                    </TabsTrigger>
                </TabsList>

                <TabsContent value="calendar">
                    <SchedulerCalendar
                        schedules={schedules}
                        onScheduleUpdate={handleScheduleUpdate}
                        onScheduleLock={handleLockSchedule}
                        onScheduleUnlock={handleUnlockSchedule}
                        onUpdateScanners={handleUpdateScanners}
                    />
                </TabsContent>

                <TabsContent value="activity">
                    <div className="rounded-lg border p-6 bg-card">
                        <ScanActivityGraph schedules={schedules} />
                    </div>
                </TabsContent>

                <TabsContent value="schedules">
                    <div className="space-y-4">
                        <div>
                            <h2 className="text-xl font-semibold">Repository Schedules</h2>
                            <p className="text-muted-foreground text-sm mt-1">
                                View and manage scan schedules for all repositories. Create schedules for unscheduled repos or modify existing ones.
                            </p>
                        </div>
                        <RepositoryScheduleTable
                            repositories={repositories}
                            onCreateSchedule={handleCreateSchedule}
                            onEditSchedule={handleEditSchedule}
                            onTriggerScan={handleTriggerScan}
                            isLoading={reposLoading}
                        />
                    </div>
                </TabsContent>

                <TabsContent value="scans">
                    <div className="rounded-lg border p-6 bg-card">
                        <TodayScansPanel />
                    </div>
                </TabsContent>
            </Tabs>

            {/* Schedule Creation Dialog */}
            {selectedRepoForCreate && (
                <ScheduleCreateDialog
                    open={createDialogOpen}
                    onOpenChange={setCreateDialogOpen}
                    repositoryId={selectedRepoForCreate.id}
                    repositoryName={selectedRepoForCreate.name}
                    onScheduleCreated={handleScheduleCreated}
                />
            )}

            {/* Schedule Edit Dialog */}
            <ScheduleEditDialog
                open={editDialogOpen}
                onOpenChange={setEditDialogOpen}
                schedule={selectedScheduleForEdit}
                onScheduleUpdated={handleScheduleUpdated}
            />
        </div>
    )
}
