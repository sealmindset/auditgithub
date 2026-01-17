"use client"

import { useMemo, useState, useCallback } from "react"
import { Calendar, dateFnsLocalizer, View, Views } from "react-big-calendar"
import { format, parse, startOfWeek, getDay, addHours } from "date-fns"
import { enUS } from "date-fns/locale"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Lock, Bot, User, CalendarDays } from "lucide-react"

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

// Schedule type from API
interface Schedule {
    id: string
    repository_id: string
    repository_name: string
    schedule_type: "ai" | "manual"
    frequency: "daily" | "weekly" | "bi-weekly" | "monthly"
    day_of_week: number | null
    time_window: "morning" | "afternoon" | "evening" | "night"
    next_scheduled_at: string | null
    is_locked: boolean
    ai_confidence: number | null
}

// Calendar event type
interface CalendarEvent {
    id: string
    title: string
    start: Date
    end: Date
    resource: Schedule
}

interface SchedulerCalendarProps {
    schedules: Schedule[]
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

export function SchedulerCalendar({ schedules }: SchedulerCalendarProps) {
    const [view, setView] = useState<View>(Views.MONTH)
    const [date, setDate] = useState(new Date())

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
                <Calendar
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
                />
            </div>
        </div>
    )
}
