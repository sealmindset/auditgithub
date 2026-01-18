"use client"

import { useMemo, useState, useCallback } from "react"
import { Calendar, dateFnsLocalizer, View, Views, CalendarProps } from "react-big-calendar"
import withDragAndDrop, { EventInteractionArgs, withDragAndDropProps } from "react-big-calendar/lib/addons/dragAndDrop"
import { format, parse, startOfWeek, getDay, addHours } from "date-fns"
import { enUS } from "date-fns/locale"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Lock, Bot, User, CalendarDays } from "lucide-react"
import { TimeWindowDialog, TimeWindow } from "@/components/TimeWindowDialog"
import { ScheduleOverrideDialog } from "@/components/ScheduleOverrideDialog"

// Import calendar styles - base styles first, then overrides
import "react-big-calendar/lib/css/react-big-calendar.css"
import "react-big-calendar/lib/addons/dragAndDrop/styles.css"
import "@/app/scheduler/calendar.css"

// Schedule type from API
export interface Schedule {
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

// Calendar event type
interface CalendarEvent {
    id: string
    title: string
    start: Date
    end: Date
    resource: Schedule
}

// Create typed drag-and-drop enabled calendar
const DragAndDropCalendar = withDragAndDrop<CalendarEvent>(Calendar as React.ComponentType<CalendarProps<CalendarEvent>>)

// Configure date-fns localizer for react-big-calendar
const locales = {
    "en-US": enUS,
}

const localizer = dateFnsLocalizer({
    format,
    parse,
    startOfWeek,
    getDay,
    locales,
})

// Schedule update data for API
export interface ScheduleUpdateData {
    repoId: string
    frequency: Schedule["frequency"]
    day_of_week: number | null
    time_window: TimeWindow
    override_reason?: string
}

// Pending drop state
interface PendingDrop {
    event: CalendarEvent
    newDate: Date
}

interface SchedulerCalendarProps {
    schedules: Schedule[]
    onScheduleUpdate?: (data: ScheduleUpdateData) => Promise<void>
    onScheduleLock?: (repoId: string, reason: string) => Promise<void>
    onScheduleUnlock?: (repoId: string) => Promise<void>
    onUpdateScanners?: (repoId: string, scanners: string[] | null) => Promise<void>
}

// Time window to hours mapping
const TIME_WINDOW_HOURS: Record<string, number> = {
    morning: 8,
    afternoon: 14,
    evening: 20,
    night: 2,
}

// Time window colors for dot indicators
const TIME_WINDOW_COLORS: Record<string, string> = {
    morning: "bg-yellow-500",
    afternoon: "bg-orange-500",
    evening: "bg-blue-500",
    night: "bg-purple-500",
}

// Transform API schedule to calendar event
const mapScheduleToEvent = (schedule: Schedule): CalendarEvent | null => {
    if (!schedule.next_scheduled_at) return null

    const start = new Date(schedule.next_scheduled_at)
    return {
        id: schedule.id,
        title: schedule.repository_name,
        start,
        end: addHours(start, 2), // 2-hour scan window
        resource: schedule,
    }
}

// Custom event component for styling
function EventComponent({ event }: { event: CalendarEvent }) {
    const schedule = event.resource
    const isAI = schedule.schedule_type === "ai"
    const timeWindowColor = TIME_WINDOW_COLORS[schedule.time_window] || "bg-gray-500"

    return (
        <div className="flex items-center gap-1 p-0.5 text-xs overflow-hidden">
            <span className={`w-2 h-2 rounded-full flex-shrink-0 ${timeWindowColor}`} />
            <span className="truncate flex-1">{event.title}</span>
            {schedule.is_locked && (
                <Lock className="h-3 w-3 flex-shrink-0 text-amber-500" />
            )}
            {isAI && schedule.ai_confidence !== null && (
                <span className="text-[10px] text-blue-400 flex-shrink-0">
                    {Math.round(schedule.ai_confidence * 100)}%
                </span>
            )}
        </div>
    )
}

// Helper: Convert JavaScript day (0=Sunday) to API day_of_week (0=Monday)
const jsDateToApiDayOfWeek = (date: Date): number => {
    const jsDay = date.getDay() // 0=Sunday, 1=Monday, ..., 6=Saturday
    // Convert to API format: 0=Monday, ..., 6=Sunday
    return jsDay === 0 ? 6 : jsDay - 1
}

export function SchedulerCalendar({ schedules, onScheduleUpdate, onScheduleLock, onScheduleUnlock, onUpdateScanners }: SchedulerCalendarProps) {
    const [view, setView] = useState<View>(Views.MONTH)
    const [date, setDate] = useState(new Date())

    // Dialog and pending drop state
    const [dialogOpen, setDialogOpen] = useState(false)
    const [pendingDrop, setPendingDrop] = useState<PendingDrop | null>(null)
    const [isSubmitting, setIsSubmitting] = useState(false)

    // Override dialog state
    const [selectedSchedule, setSelectedSchedule] = useState<Schedule | null>(null)
    const [overrideDialogOpen, setOverrideDialogOpen] = useState(false)
    const [isLockLoading, setIsLockLoading] = useState(false)

    // Handle event drop (drag and drop)
    const handleEventDrop = useCallback(
        ({ event, start }: EventInteractionArgs<CalendarEvent>) => {
            // Store the pending drop and open the dialog
            setPendingDrop({
                event: event as CalendarEvent,
                newDate: start as Date,
            })
            setDialogOpen(true)
        },
        []
    )

    // Handle dialog confirmation
    const handleDialogConfirm = useCallback(
        async (timeWindow: TimeWindow, reason?: string) => {
            if (!pendingDrop || !onScheduleUpdate) return

            const { event, newDate } = pendingDrop
            const schedule = event.resource

            // Calculate day_of_week from new date
            const dayOfWeek = jsDateToApiDayOfWeek(newDate)

            setIsSubmitting(true)
            try {
                // Call the update function
                await onScheduleUpdate({
                    repoId: schedule.repository_id,
                    frequency: schedule.frequency,
                    day_of_week: dayOfWeek,
                    time_window: timeWindow,
                    override_reason: reason,
                })

                // Close dialog and clear pending drop on success
                setDialogOpen(false)
                setPendingDrop(null)
            } finally {
                setIsSubmitting(false)
            }
        },
        [pendingDrop, onScheduleUpdate]
    )

    // Handle dialog cancel
    const handleDialogOpenChange = useCallback((open: boolean) => {
        if (isSubmitting) return // Prevent close while submitting
        setDialogOpen(open)
        if (!open) {
            setPendingDrop(null)
        }
    }, [isSubmitting])

    // Handle event click (opens override dialog)
    const handleSelectEvent = useCallback((event: CalendarEvent) => {
        setSelectedSchedule(event.resource)
        setOverrideDialogOpen(true)
    }, [])

    // Handle override dialog close
    const handleOverrideDialogOpenChange = useCallback((open: boolean) => {
        if (isLockLoading) return // Prevent close while loading
        setOverrideDialogOpen(open)
        if (!open) {
            setSelectedSchedule(null)
        }
    }, [isLockLoading])

    // Handle lock schedule
    const handleLock = useCallback(async (reason: string) => {
        if (!selectedSchedule || !onScheduleLock) return
        setIsLockLoading(true)
        try {
            await onScheduleLock(selectedSchedule.repository_id, reason)
            setOverrideDialogOpen(false)
            setSelectedSchedule(null)
        } finally {
            setIsLockLoading(false)
        }
    }, [selectedSchedule, onScheduleLock])

    // Handle unlock schedule
    const handleUnlock = useCallback(async () => {
        if (!selectedSchedule || !onScheduleUnlock) return
        setIsLockLoading(true)
        try {
            await onScheduleUnlock(selectedSchedule.repository_id)
            setOverrideDialogOpen(false)
            setSelectedSchedule(null)
        } finally {
            setIsLockLoading(false)
        }
    }, [selectedSchedule, onScheduleUnlock])

    // Handle update scanners
    const handleUpdateScanners = useCallback(async (scanners: string[] | null) => {
        if (!selectedSchedule || !onUpdateScanners) return
        await onUpdateScanners(selectedSchedule.repository_id, scanners)
    }, [selectedSchedule, onUpdateScanners])

    // Allow all events to be draggable
    const draggableAccessor = useCallback(() => true, [])

    // Transform schedules to calendar events
    const events = useMemo(() => {
        return schedules
            .map(mapScheduleToEvent)
            .filter((event): event is CalendarEvent => event !== null)
    }, [schedules])

    // Custom event styling based on schedule type
    const eventStyleGetter = useCallback((event: CalendarEvent) => {
        const isAI = event.resource.schedule_type === "ai"
        return {
            style: {
                backgroundColor: isAI ? "rgba(59, 130, 246, 0.2)" : "rgba(168, 85, 247, 0.2)",
                borderLeft: `3px solid ${isAI ? "rgb(59, 130, 246)" : "rgb(168, 85, 247)"}`,
                color: "inherit",
                borderRadius: "4px",
            },
        }
    }, [])

    const handleNavigate = useCallback((newDate: Date) => {
        setDate(newDate)
    }, [])

    const handleViewChange = useCallback((newView: View) => {
        setView(newView)
    }, [])

    // Empty state
    if (schedules.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center h-96 border border-dashed rounded-lg">
                <CalendarDays className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium">No scheduled scans</h3>
                <p className="text-muted-foreground text-sm mt-1">
                    Schedules will appear here once repositories are configured.
                </p>
            </div>
        )
    }

    return (
        <div className="flex flex-col gap-4">
            {/* View toggle and legend */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <Button
                        variant={view === Views.MONTH ? "default" : "outline"}
                        size="sm"
                        onClick={() => setView(Views.MONTH)}
                    >
                        Month
                    </Button>
                    <Button
                        variant={view === Views.WEEK ? "default" : "outline"}
                        size="sm"
                        onClick={() => setView(Views.WEEK)}
                    >
                        Week
                    </Button>
                </div>

                {/* Legend */}
                <div className="flex items-center gap-4 text-sm">
                    <div className="flex items-center gap-1">
                        <Bot className="h-4 w-4 text-blue-500" />
                        <span className="text-muted-foreground">AI Schedule</span>
                    </div>
                    <div className="flex items-center gap-1">
                        <User className="h-4 w-4 text-purple-500" />
                        <span className="text-muted-foreground">Manual</span>
                    </div>
                    <div className="flex items-center gap-1">
                        <Lock className="h-4 w-4 text-amber-500" />
                        <span className="text-muted-foreground">Locked</span>
                    </div>
                </div>
            </div>

            {/* Time window legend */}
            <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span>Time windows:</span>
                <div className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-yellow-500" />
                    <span>Morning</span>
                </div>
                <div className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-orange-500" />
                    <span>Afternoon</span>
                </div>
                <div className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-blue-500" />
                    <span>Evening</span>
                </div>
                <div className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-purple-500" />
                    <span>Night</span>
                </div>
            </div>

            {/* Calendar */}
            <div className="scheduler-calendar h-[600px] border rounded-lg p-2 bg-card">
                <DragAndDropCalendar
                    localizer={localizer}
                    events={events}
                    startAccessor="start"
                    endAccessor="end"
                    view={view}
                    onView={handleViewChange}
                    date={date}
                    onNavigate={handleNavigate}
                    eventPropGetter={eventStyleGetter}
                    components={{
                        event: EventComponent,
                    }}
                    toolbar={true}
                    popup
                    draggableAccessor={draggableAccessor}
                    onEventDrop={handleEventDrop}
                    onSelectEvent={handleSelectEvent}
                    selectable
                />
            </div>

            {/* Time Window Selection Dialog */}
            {pendingDrop && (
                <TimeWindowDialog
                    open={dialogOpen}
                    onOpenChange={handleDialogOpenChange}
                    onConfirm={handleDialogConfirm}
                    eventTitle={pendingDrop.event.title}
                    newDate={pendingDrop.newDate}
                    isLoading={isSubmitting}
                />
            )}

            {/* Schedule Override Dialog */}
            <ScheduleOverrideDialog
                open={overrideDialogOpen}
                onOpenChange={handleOverrideDialogOpenChange}
                schedule={selectedSchedule}
                onLock={handleLock}
                onUnlock={handleUnlock}
                onUpdateScanners={onUpdateScanners ? handleUpdateScanners : undefined}
                isLoading={isLockLoading}
            />
        </div>
    )
}
