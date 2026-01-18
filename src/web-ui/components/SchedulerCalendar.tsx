"use client"

import { useMemo, useState, useCallback } from "react"
import { Calendar, dateFnsLocalizer, View, Views, CalendarProps } from "react-big-calendar"
import withDragAndDrop, { EventInteractionArgs, withDragAndDropProps } from "react-big-calendar/lib/addons/dragAndDrop"
import { format, parse, startOfWeek, getDay, addHours, setMonth, setYear, parseISO, isValid } from "date-fns"
import { enUS } from "date-fns/locale"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Lock, Bot, User, CalendarDays, ChevronLeft, ChevronRight, Search, X } from "lucide-react"
import { TimeWindowDialog, TimeWindow } from "@/components/TimeWindowDialog"
import { ScheduleOverrideDialog } from "@/components/ScheduleOverrideDialog"
import { cn } from "@/lib/utils"

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

// Month names for navigation
const MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
]

// Generate year range (current year -2 to +5)
const currentYear = new Date().getFullYear()
const YEARS = Array.from({ length: 8 }, (_, i) => currentYear - 2 + i)

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

    // Search state
    const [searchQuery, setSearchQuery] = useState("")
    const [searchOpen, setSearchOpen] = useState(false)
    const [dateSearchInput, setDateSearchInput] = useState("")

    // Dialog and pending drop state
    const [dialogOpen, setDialogOpen] = useState(false)
    const [pendingDrop, setPendingDrop] = useState<PendingDrop | null>(null)
    const [isSubmitting, setIsSubmitting] = useState(false)

    // Override dialog state
    const [selectedSchedule, setSelectedSchedule] = useState<Schedule | null>(null)
    const [overrideDialogOpen, setOverrideDialogOpen] = useState(false)
    const [isLockLoading, setIsLockLoading] = useState(false)

    // Filter schedules based on search query
    const filteredSchedules = useMemo(() => {
        if (!searchQuery.trim()) return schedules
        const query = searchQuery.toLowerCase()
        return schedules.filter(s =>
            s.repository_name.toLowerCase().includes(query)
        )
    }, [schedules, searchQuery])

    // Navigation handlers
    const handleMonthChange = useCallback((month: string) => {
        const monthIndex = MONTHS.indexOf(month)
        if (monthIndex !== -1) {
            setDate(prev => setMonth(prev, monthIndex))
        }
    }, [])

    const handleYearChange = useCallback((year: string) => {
        const yearNum = parseInt(year, 10)
        if (!isNaN(yearNum)) {
            setDate(prev => setYear(prev, yearNum))
        }
    }, [])

    const handlePrevMonth = useCallback(() => {
        setDate(prev => {
            const newDate = new Date(prev)
            newDate.setMonth(newDate.getMonth() - 1)
            return newDate
        })
    }, [])

    const handleNextMonth = useCallback(() => {
        setDate(prev => {
            const newDate = new Date(prev)
            newDate.setMonth(newDate.getMonth() + 1)
            return newDate
        })
    }, [])

    const handleToday = useCallback(() => {
        setDate(new Date())
    }, [])

    // Handle date search (accepts formats: YYYY-MM-DD, MM/DD/YYYY, etc.)
    const handleDateSearch = useCallback(() => {
        if (!dateSearchInput.trim()) return

        // Try parsing different date formats
        let parsedDate: Date | null = null

        // Try ISO format first (YYYY-MM-DD)
        const isoDate = parseISO(dateSearchInput)
        if (isValid(isoDate)) {
            parsedDate = isoDate
        } else {
            // Try MM/DD/YYYY or M/D/YYYY
            const parts = dateSearchInput.split(/[\/\-]/)
            if (parts.length === 3) {
                const [p1, p2, p3] = parts.map(p => parseInt(p, 10))
                // Check if it's MM/DD/YYYY or YYYY/MM/DD
                if (p1 > 31) {
                    // YYYY/MM/DD
                    parsedDate = new Date(p1, p2 - 1, p3)
                } else if (p3 > 31) {
                    // MM/DD/YYYY
                    parsedDate = new Date(p3, p1 - 1, p2)
                }
            }
        }

        if (parsedDate && isValid(parsedDate)) {
            setDate(parsedDate)
            setDateSearchInput("")
        }
    }, [dateSearchInput])

    // Handle repo search selection - navigate to the schedule's date
    const handleRepoSelect = useCallback((schedule: Schedule) => {
        if (schedule.next_scheduled_at) {
            setDate(new Date(schedule.next_scheduled_at))
            setSearchQuery("")
            setSearchOpen(false)
        }
    }, [])

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

    // Transform schedules to calendar events (filtered by search)
    const events = useMemo(() => {
        return filteredSchedules
            .map(mapScheduleToEvent)
            .filter((event): event is CalendarEvent => event !== null)
    }, [filteredSchedules])

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
            {/* Navigation and Search Row */}
            <div className="flex items-center justify-between gap-4 flex-wrap">
                {/* Left: Month/Year Navigation */}
                <div className="flex items-center gap-2">
                    <Button variant="outline" size="icon" onClick={handlePrevMonth}>
                        <ChevronLeft className="h-4 w-4" />
                    </Button>

                    <Select value={MONTHS[date.getMonth()]} onValueChange={handleMonthChange}>
                        <SelectTrigger className="w-[130px]">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            {MONTHS.map((month) => (
                                <SelectItem key={month} value={month}>
                                    {month}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>

                    <Select value={date.getFullYear().toString()} onValueChange={handleYearChange}>
                        <SelectTrigger className="w-[90px]">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            {YEARS.map((year) => (
                                <SelectItem key={year} value={year.toString()}>
                                    {year}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>

                    <Button variant="outline" size="icon" onClick={handleNextMonth}>
                        <ChevronRight className="h-4 w-4" />
                    </Button>

                    <Button variant="outline" size="sm" onClick={handleToday}>
                        Today
                    </Button>
                </div>

                {/* Center: Search */}
                <div className="flex items-center gap-2 flex-1 max-w-md">
                    {/* Repo Search */}
                    <Popover open={searchOpen} onOpenChange={setSearchOpen}>
                        <PopoverTrigger asChild>
                            <div className="relative flex-1">
                                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                                <Input
                                    placeholder="Search repositories..."
                                    value={searchQuery}
                                    onChange={(e) => {
                                        setSearchQuery(e.target.value)
                                        setSearchOpen(e.target.value.length > 0)
                                    }}
                                    className="pl-9 pr-8"
                                />
                                {searchQuery && (
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        className="absolute right-1 top-1 h-6 w-6"
                                        onClick={() => {
                                            setSearchQuery("")
                                            setSearchOpen(false)
                                        }}
                                    >
                                        <X className="h-3 w-3" />
                                    </Button>
                                )}
                            </div>
                        </PopoverTrigger>
                        {searchQuery && filteredSchedules.length > 0 && (
                            <PopoverContent className="w-[300px] p-0" align="start">
                                <div className="max-h-[200px] overflow-auto">
                                    {filteredSchedules.slice(0, 10).map((schedule) => (
                                        <button
                                            key={schedule.id}
                                            className="w-full px-3 py-2 text-left hover:bg-accent flex items-center justify-between text-sm"
                                            onClick={() => handleRepoSelect(schedule)}
                                        >
                                            <span className="truncate">{schedule.repository_name}</span>
                                            {schedule.next_scheduled_at && (
                                                <span className="text-xs text-muted-foreground ml-2">
                                                    {format(new Date(schedule.next_scheduled_at), "MMM d")}
                                                </span>
                                            )}
                                        </button>
                                    ))}
                                    {filteredSchedules.length > 10 && (
                                        <div className="px-3 py-2 text-xs text-muted-foreground border-t">
                                            +{filteredSchedules.length - 10} more results
                                        </div>
                                    )}
                                </div>
                            </PopoverContent>
                        )}
                    </Popover>

                    {/* Date Search */}
                    <div className="flex items-center gap-1">
                        <Input
                            placeholder="Go to date (YYYY-MM-DD)"
                            value={dateSearchInput}
                            onChange={(e) => setDateSearchInput(e.target.value)}
                            onKeyDown={(e) => e.key === "Enter" && handleDateSearch()}
                            className="w-[160px]"
                        />
                        <Button variant="outline" size="sm" onClick={handleDateSearch}>
                            Go
                        </Button>
                    </div>
                </div>

                {/* Right: View Toggle */}
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
                    <Button
                        variant={view === Views.AGENDA ? "default" : "outline"}
                        size="sm"
                        onClick={() => setView(Views.AGENDA)}
                    >
                        Agenda
                    </Button>
                </div>
            </div>

            {/* Legend Row */}
            <div className="flex items-center justify-between flex-wrap gap-2">
                {/* Schedule Type Legend */}
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

                {/* Search filter indicator */}
                {searchQuery && (
                    <Badge variant="secondary" className="gap-1">
                        Filtering: {filteredSchedules.length} of {schedules.length} schedules
                        <Button
                            variant="ghost"
                            size="icon"
                            className="h-4 w-4 ml-1"
                            onClick={() => setSearchQuery("")}
                        >
                            <X className="h-3 w-3" />
                        </Button>
                    </Badge>
                )}
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
                    toolbar={false}
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
