"use client"

import { Widget } from "@/components/dashboard/Widget"
import { useWidgetData } from "@/hooks/useWidgetData"
import { ScanActivityGraph } from "@/components/ScanActivityGraph"
import { CalendarDays } from "lucide-react"

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

interface ScheduleResponse {
    schedules: Schedule[]
    total: number
}

export function ScanScheduleGraphWidget() {
    const { data, loading, error, refetch } = useWidgetData<ScheduleResponse>(
        "/schedules",
        { refreshInterval: 60000 }
    )

    const schedules = data?.schedules || []

    return (
        <Widget
            title="Scan Activity"
            subtitle="Scheduled scan distribution"
            loading={loading}
            error={error}
            onRetry={refetch}
            className="h-full"
        >
            {schedules.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                    <CalendarDays className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No schedules configured</p>
                </div>
            ) : (
                <div className="overflow-hidden">
                    <ScanActivityGraph schedules={schedules} />
                </div>
            )}
        </Widget>
    )
}
