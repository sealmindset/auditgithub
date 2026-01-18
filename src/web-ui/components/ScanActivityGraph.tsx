"use client"

import { useMemo, useState, useEffect } from "react"
import { format, startOfYear, endOfYear, eachDayOfInterval, getDay, startOfWeek, addDays, isSameDay, parseISO } from "date-fns"
import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { cn } from "@/lib/utils"

interface Schedule {
    id: string
    repository_id: string
    repository_name: string
    schedule_type: "ai" | "manual"
    frequency: "daily" | "weekly" | "bi-weekly" | "monthly" | "annually"
    day_of_week: number | null
    time_window: "morning" | "afternoon" | "evening" | "night"
    next_scheduled_at: string | null
    is_locked: boolean
    ai_confidence: number | null
}

interface ScanActivityGraphProps {
    schedules: Schedule[]
    year?: number
}

// Generate all scheduled scan dates for a year based on schedule configurations
function generateScheduledDates(schedules: Schedule[], year: number): Map<string, { count: number; repos: string[] }> {
    const dateMap = new Map<string, { count: number; repos: string[] }>()
    const startDate = startOfYear(new Date(year, 0, 1))
    const endDate = endOfYear(new Date(year, 0, 1))

    for (const schedule of schedules) {
        const dates = getScheduledDatesForYear(schedule, startDate, endDate)
        for (const date of dates) {
            const key = format(date, "yyyy-MM-dd")
            const existing = dateMap.get(key) || { count: 0, repos: [] }
            existing.count++
            existing.repos.push(schedule.repository_name)
            dateMap.set(key, existing)
        }
    }

    return dateMap
}

function getScheduledDatesForYear(schedule: Schedule, startDate: Date, endDate: Date): Date[] {
    const dates: Date[] = []
    const { frequency, day_of_week, next_scheduled_at } = schedule

    // Use next_scheduled_at as a starting reference if available
    let currentDate = next_scheduled_at ? parseISO(next_scheduled_at) : startDate

    // Adjust to start of year if before
    if (currentDate < startDate) {
        currentDate = startDate
    }

    // Generate dates based on frequency
    while (currentDate <= endDate) {
        // For weekly/bi-weekly, respect day_of_week
        if ((frequency === "weekly" || frequency === "bi-weekly") && day_of_week !== null) {
            // Find next occurrence of that day
            while (getDay(currentDate) !== (day_of_week + 1) % 7 && currentDate <= endDate) {
                currentDate = addDays(currentDate, 1)
            }
        }

        if (currentDate <= endDate && currentDate >= startDate) {
            dates.push(new Date(currentDate))
        }

        // Advance based on frequency
        switch (frequency) {
            case "daily":
                currentDate = addDays(currentDate, 1)
                break
            case "weekly":
                currentDate = addDays(currentDate, 7)
                break
            case "bi-weekly":
                currentDate = addDays(currentDate, 14)
                break
            case "monthly":
                currentDate = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, currentDate.getDate())
                break
            case "annually":
                currentDate = new Date(currentDate.getFullYear() + 1, currentDate.getMonth(), currentDate.getDate())
                break
            default:
                currentDate = addDays(currentDate, 7)
        }
    }

    return dates
}

function getIntensityLevel(count: number, maxCount: number): number {
    if (count === 0) return 0
    if (maxCount === 0) return 0
    const ratio = count / maxCount
    if (ratio <= 0.25) return 1
    if (ratio <= 0.5) return 2
    if (ratio <= 0.75) return 3
    return 4
}

const INTENSITY_COLORS = [
    "bg-neutral-200 dark:bg-neutral-800 hover:bg-neutral-300 dark:hover:bg-neutral-700",  // 0: no scans - visible gray
    "bg-green-200 hover:bg-green-300 dark:bg-green-900 dark:hover:bg-green-800",    // 1: low
    "bg-green-400 hover:bg-green-500 dark:bg-green-700 dark:hover:bg-green-600",    // 2: medium-low
    "bg-green-500 hover:bg-green-600 dark:bg-green-600 dark:hover:bg-green-500",    // 3: medium-high
    "bg-green-600 hover:bg-green-700 dark:bg-green-500 dark:hover:bg-green-400",    // 4: high
]

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

// WOPR-style pulsating animation keyframes
const woprStyles = `
@keyframes wopr-pulse {
    0%, 100% {
        opacity: 0.6;
        transform: scale(0.95);
    }
    50% {
        opacity: 1;
        transform: scale(1);
    }
}

@keyframes wopr-flash {
    0%, 85%, 100% {
        opacity: 0.85;
        transform: scale(1);
        filter: brightness(1);
    }
    90%, 95% {
        opacity: 1;
        transform: scale(1.1);
        filter: brightness(1.4);
    }
}

@keyframes wopr-critical-flash {
    0%, 80%, 100% {
        opacity: 0.9;
        transform: scale(1);
        box-shadow: 0 0 0 0 var(--glow-color, rgba(239, 68, 68, 0));
    }
    88%, 92% {
        opacity: 1;
        transform: scale(1.15);
        box-shadow: 0 0 8px 2px var(--glow-color, rgba(239, 68, 68, 0.6));
    }
}

.wopr-dot {
    animation: wopr-pulse var(--pulse-duration, 3s) ease-in-out infinite;
    animation-delay: var(--pulse-delay, 0s);
}

.wopr-dot-active {
    animation: wopr-pulse var(--pulse-duration, 2.5s) ease-in-out infinite;
    animation-delay: var(--pulse-delay, 0s);
}

.wopr-dot-critical {
    animation: wopr-flash var(--flash-duration, 4s) ease-in-out infinite;
    animation-delay: var(--flash-delay, 0s);
}

.wopr-dot-critical-red {
    animation: wopr-critical-flash var(--flash-duration, 4s) ease-in-out infinite;
    animation-delay: var(--flash-delay, 0s);
    background-color: var(--critical-bg, rgb(239, 68, 68)) !important;
}
`

export function ScanActivityGraph({ schedules, year: initialYear }: ScanActivityGraphProps) {
    const currentYear = new Date().getFullYear()
    const [selectedYear, setSelectedYear] = useState(initialYear || currentYear)

    // Inject WOPR animation styles
    useEffect(() => {
        const styleId = 'wopr-pulse-styles'
        if (!document.getElementById(styleId)) {
            const styleElement = document.createElement('style')
            styleElement.id = styleId
            styleElement.textContent = woprStyles
            document.head.appendChild(styleElement)
        }
        return () => {
            // Cleanup on unmount (optional, but keeps DOM clean)
            const existingStyle = document.getElementById(styleId)
            if (existingStyle) {
                existingStyle.remove()
            }
        }
    }, [])

    // Generate the calendar grid
    const calendarData = useMemo(() => {
        const startDate = startOfYear(new Date(selectedYear, 0, 1))
        const endDate = endOfYear(new Date(selectedYear, 0, 1))

        // Get all days in the year
        const allDays = eachDayOfInterval({ start: startDate, end: endDate })

        // Generate scheduled dates
        const scheduledDates = generateScheduledDates(schedules, selectedYear)

        // Find max count for intensity calculation
        let maxCount = 0
        scheduledDates.forEach(({ count }) => {
            if (count > maxCount) maxCount = count
        })

        // Build weeks array (53 weeks max)
        const weeks: { date: Date; count: number; repos: string[] }[][] = []

        // Start from the first Sunday of the year (or before)
        let currentWeekStart = startOfWeek(startDate, { weekStartsOn: 0 })

        // Continue until we've passed the end of the year (ensure we include the last week containing Dec 31)
        while (currentWeekStart.getFullYear() <= selectedYear) {
            const week: { date: Date; count: number; repos: string[] }[] = []
            let hasValidDay = false

            for (let i = 0; i < 7; i++) {
                const day = addDays(currentWeekStart, i)
                const key = format(day, "yyyy-MM-dd")
                const data = scheduledDates.get(key) || { count: 0, repos: [] }

                // Only include days within the selected year
                if (day.getFullYear() === selectedYear) {
                    week.push({ date: day, ...data })
                    hasValidDay = true
                } else {
                    week.push({ date: day, count: -1, repos: [] }) // -1 = outside year
                }
            }

            // Only add weeks that have at least one day in the selected year
            if (hasValidDay) {
                weeks.push(week)
            }
            currentWeekStart = addDays(currentWeekStart, 7)

            // Safety check to prevent infinite loop
            if (weeks.length > 54) break
        }

        // Calculate stats
        let totalScans = 0
        let daysWithScans = 0
        scheduledDates.forEach(({ count }) => {
            totalScans += count
            if (count > 0) daysWithScans++
        })

        // Find top 10 unique count thresholds for critical highlighting
        const uniqueCounts = [...new Set(
            Array.from(scheduledDates.values())
                .map(d => d.count)
                .filter(c => c > 0)
        )].sort((a, b) => b - a)
        const top10Thresholds = uniqueCounts.slice(0, 10)

        return { weeks, maxCount, totalScans, daysWithScans, scheduledDates, top10Thresholds }
    }, [schedules, selectedYear])

    // Get month labels with their position - only show alternating months for condensed view
    const monthLabels = useMemo(() => {
        const labels: { month: string; weekIndex: number }[] = []
        let lastMonth = -1
        // Only show these months: Jan(0), Mar(2), May(4), Jul(6), Sep(8), Nov(10)
        const showMonths = [0, 2, 4, 6, 8, 10]

        calendarData.weeks.forEach((week, weekIndex) => {
            // Find first valid day in the week
            const firstValidDay = week.find(d => d.count >= 0)
            if (firstValidDay) {
                const month = firstValidDay.date.getMonth()
                if (month !== lastMonth && showMonths.includes(month)) {
                    labels.push({ month: MONTHS[month], weekIndex })
                    lastMonth = month
                }
            }
        })

        return labels
    }, [calendarData.weeks])

    // Calculate frequency distribution
    const frequencyDistribution = useMemo(() => {
        const dist: Record<string, number> = {
            daily: 0,
            weekly: 0,
            "bi-weekly": 0,
            monthly: 0,
            annually: 0,
        }
        schedules.forEach(s => {
            dist[s.frequency] = (dist[s.frequency] || 0) + 1
        })
        return dist
    }, [schedules])

    const availableYears = [currentYear - 1, currentYear, currentYear + 1]

    return (
        <div className="space-y-4">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <h3 className="text-lg font-semibold">Scan Activity</h3>
                    <Select value={selectedYear.toString()} onValueChange={(v) => setSelectedYear(parseInt(v))}>
                        <SelectTrigger className="w-[100px]">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            {availableYears.map(y => (
                                <SelectItem key={y} value={y.toString()}>{y}</SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                </div>
                <div className="flex items-center gap-4 text-sm text-muted-foreground">
                    <span>{calendarData.totalScans.toLocaleString()} scheduled scans</span>
                    <span>{calendarData.daysWithScans} days with scans</span>
                </div>
            </div>

            {/* Contribution Graph */}
            <div className="overflow-x-auto">
                <div className="inline-block">
                    {/* Month labels */}
                    <div className="relative mb-1 ml-8 h-4" style={{ width: `${calendarData.weeks.length * 12}px` }}>
                        {monthLabels.map(({ month, weekIndex }, i) => (
                            <div
                                key={`${month}-${i}`}
                                className="absolute text-xs text-muted-foreground"
                                style={{
                                    left: `${weekIndex * 12}px`,
                                }}
                            >
                                {month}
                            </div>
                        ))}
                    </div>

                    {/* Grid */}
                    <div className="flex">
                        {/* Day labels */}
                        <div className="flex flex-col gap-[2px] mr-2 text-xs text-muted-foreground">
                            <div className="h-[10px]"></div>
                            <div className="h-[10px] flex items-center">Mon</div>
                            <div className="h-[10px]"></div>
                            <div className="h-[10px] flex items-center">Wed</div>
                            <div className="h-[10px]"></div>
                            <div className="h-[10px] flex items-center">Fri</div>
                            <div className="h-[10px]"></div>
                        </div>

                        {/* Weeks */}
                        <TooltipProvider delayDuration={100}>
                            <div className="flex gap-[2px]">
                                {calendarData.weeks.map((week, weekIndex) => (
                                    <div key={weekIndex} className="flex flex-col gap-[2px]">
                                        {week.map((day, dayIndex) => {
                                            if (day.count < 0) {
                                                // Outside year - render empty
                                                return <div key={dayIndex} className="w-[10px] h-[10px]" />
                                            }

                                            const intensity = getIntensityLevel(day.count, calendarData.maxCount)
                                            const isToday = isSameDay(day.date, new Date())
                                            const hasActivity = day.count > 0
                                            const isCritical = intensity === 4 // Highest intensity

                                            // Check if this day is in the top 10 critical
                                            const criticalRank = calendarData.top10Thresholds.indexOf(day.count)
                                            const isTop10Critical = criticalRank !== -1 && day.count > 0

                                            // Color gradient for top 10: purple (#8B5CF6) -> red (#EF4444) -> pale yellow (#FDE68A)
                                            // Rank 0 = purple, Rank 4-5 = red, Rank 9 = pale yellow
                                            const getCriticalColor = (rank: number) => {
                                                if (rank === 0) return { bg: 'rgb(139, 92, 246)', glow: 'rgba(139, 92, 246, 0.7)' } // Purple
                                                if (rank === 1) return { bg: 'rgb(167, 76, 194)', glow: 'rgba(167, 76, 194, 0.6)' } // Purple-red
                                                if (rank === 2) return { bg: 'rgb(194, 60, 142)', glow: 'rgba(194, 60, 142, 0.6)' } // Magenta
                                                if (rank === 3) return { bg: 'rgb(220, 56, 100)', glow: 'rgba(220, 56, 100, 0.6)' } // Red-magenta
                                                if (rank === 4) return { bg: 'rgb(239, 68, 68)', glow: 'rgba(239, 68, 68, 0.6)' }  // Red
                                                if (rank === 5) return { bg: 'rgb(245, 101, 58)', glow: 'rgba(245, 101, 58, 0.5)' } // Red-orange
                                                if (rank === 6) return { bg: 'rgb(251, 134, 48)', glow: 'rgba(251, 134, 48, 0.5)' } // Orange
                                                if (rank === 7) return { bg: 'rgb(252, 165, 60)', glow: 'rgba(252, 165, 60, 0.4)' } // Orange-yellow
                                                if (rank === 8) return { bg: 'rgb(253, 196, 90)', glow: 'rgba(253, 196, 90, 0.4)' } // Yellow
                                                return { bg: 'rgb(253, 230, 138)', glow: 'rgba(253, 230, 138, 0.3)' } // Pale yellow
                                            }

                                            const criticalColors = isTop10Critical ? getCriticalColor(criticalRank) : null

                                            // For critical dots: random flash timing (no cascade)
                                            // For others: staggered wave effect
                                            const baseDelay = (weekIndex * 0.05 + dayIndex * 0.15) % 8
                                            const pulseDuration = 2.5 + (intensity * 0.5)

                                            // Random delay for critical dots (seeded by position for consistency)
                                            const randomFlashDelay = ((weekIndex * 7 + dayIndex) * 1.618) % 6
                                            const randomFlashDuration = 3 + (((weekIndex + dayIndex) * 2.71) % 3)

                                            return (
                                                <Tooltip key={dayIndex}>
                                                    <TooltipTrigger asChild>
                                                        <div
                                                            className={cn(
                                                                "w-[10px] h-[10px] rounded-sm cursor-pointer",
                                                                !isTop10Critical && INTENSITY_COLORS[intensity],
                                                                isToday && "ring-1 ring-blue-500",
                                                                isTop10Critical ? "wopr-dot-critical-red" : isCritical ? "wopr-dot-critical" : hasActivity ? "wopr-dot-active" : "wopr-dot"
                                                            )}
                                                            style={isTop10Critical ? {
                                                                '--flash-delay': `${randomFlashDelay}s`,
                                                                '--flash-duration': `${randomFlashDuration}s`,
                                                                '--critical-bg': criticalColors?.bg,
                                                                '--glow-color': criticalColors?.glow,
                                                            } as React.CSSProperties : isCritical ? {
                                                                '--flash-delay': `${randomFlashDelay}s`,
                                                                '--flash-duration': `${randomFlashDuration}s`,
                                                            } as React.CSSProperties : {
                                                                '--pulse-delay': `${baseDelay}s`,
                                                                '--pulse-duration': `${pulseDuration}s`,
                                                            } as React.CSSProperties}
                                                        />
                                                    </TooltipTrigger>
                                                    <TooltipContent side="top" className="max-w-xs">
                                                        <div className="text-xs">
                                                            <p className="font-medium">
                                                                {day.count === 0
                                                                    ? "No scans scheduled"
                                                                    : `${day.count} scan${day.count !== 1 ? "s" : ""} scheduled`
                                                                }
                                                            </p>
                                                            <p className="text-muted-foreground">
                                                                {format(day.date, "EEEE, MMMM d, yyyy")}
                                                            </p>
                                                            {day.repos.length > 0 && (
                                                                <div className="mt-1 max-h-20 overflow-y-auto">
                                                                    {day.repos.slice(0, 5).map((repo, i) => (
                                                                        <p key={i} className="text-muted-foreground truncate">
                                                                            • {repo}
                                                                        </p>
                                                                    ))}
                                                                    {day.repos.length > 5 && (
                                                                        <p className="text-muted-foreground">
                                                                            ...and {day.repos.length - 5} more
                                                                        </p>
                                                                    )}
                                                                </div>
                                                            )}
                                                        </div>
                                                    </TooltipContent>
                                                </Tooltip>
                                            )
                                        })}
                                    </div>
                                ))}
                            </div>
                        </TooltipProvider>
                    </div>

                    {/* Legend */}
                    <div className="flex items-center justify-end gap-2 mt-2 text-xs text-muted-foreground">
                        <span>Less</span>
                        {INTENSITY_COLORS.map((color, i) => {
                            const isCritical = i === 4
                            return (
                                <div
                                    key={i}
                                    className={cn(
                                        "w-[10px] h-[10px] rounded-sm",
                                        color,
                                        isCritical ? "wopr-dot-critical" : i > 0 ? "wopr-dot-active" : "wopr-dot"
                                    )}
                                    style={isCritical ? {
                                        '--flash-delay': '0.5s',
                                        '--flash-duration': '3s',
                                    } as React.CSSProperties : {
                                        '--pulse-delay': `${i * 0.3}s`,
                                        '--pulse-duration': `${3 - i * 0.3}s`,
                                    } as React.CSSProperties}
                                />
                            )
                        })}
                        <span>More</span>
                        <span className="ml-4">|</span>
                        <span className="ml-1">Top 10:</span>
                        {/* Top 10 gradient: purple -> red -> pale yellow */}
                        {[
                            { bg: 'rgb(139, 92, 246)', glow: 'rgba(139, 92, 246, 0.7)' },   // 1st - Purple
                            { bg: 'rgb(239, 68, 68)', glow: 'rgba(239, 68, 68, 0.6)' },     // ~5th - Red
                            { bg: 'rgb(253, 230, 138)', glow: 'rgba(253, 230, 138, 0.3)' }, // 10th - Pale yellow
                        ].map((colors, i) => (
                            <div
                                key={`critical-${i}`}
                                className="w-[10px] h-[10px] rounded-sm wopr-dot-critical-red"
                                style={{
                                    '--flash-delay': `${i * 0.4}s`,
                                    '--flash-duration': '3s',
                                    '--critical-bg': colors.bg,
                                    '--glow-color': colors.glow,
                                } as React.CSSProperties}
                            />
                        ))}
                    </div>
                </div>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 pt-4 border-t">
                <div className="text-center">
                    <p className="text-2xl font-bold">{frequencyDistribution.daily}</p>
                    <p className="text-xs text-muted-foreground">Daily</p>
                </div>
                <div className="text-center">
                    <p className="text-2xl font-bold">{frequencyDistribution.weekly}</p>
                    <p className="text-xs text-muted-foreground">Weekly</p>
                </div>
                <div className="text-center">
                    <p className="text-2xl font-bold">{frequencyDistribution["bi-weekly"]}</p>
                    <p className="text-xs text-muted-foreground">Bi-weekly</p>
                </div>
                <div className="text-center">
                    <p className="text-2xl font-bold">{frequencyDistribution.monthly}</p>
                    <p className="text-xs text-muted-foreground">Monthly</p>
                </div>
                <div className="text-center">
                    <p className="text-2xl font-bold">{frequencyDistribution.annually}</p>
                    <p className="text-xs text-muted-foreground">Annually</p>
                </div>
            </div>
        </div>
    )
}
