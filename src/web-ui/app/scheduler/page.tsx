"use client"

import { useEffect, useState } from "react"
import { SchedulerCalendar } from "@/components/SchedulerCalendar"
import { Loader2 } from "lucide-react"

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
    next_scheduled_at: string | null
    is_locked: boolean
    ai_confidence: number | null
}

interface ScheduleListResponse {
    schedules: Schedule[]
    total: number
}

export default function SchedulerPage() {
    const [schedules, setSchedules] = useState<Schedule[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        const fetchSchedules = async () => {
            try {
                const res = await fetch(`${API_BASE}/schedules`)
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
        }

        fetchSchedules()
    }, [])

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
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Scan Scheduler</h1>
                    <p className="text-muted-foreground">
                        AI-powered scan scheduling with manual override support.
                    </p>
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
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Scan Scheduler</h1>
                <p className="text-muted-foreground">
                    AI-powered scan scheduling with manual override support.
                </p>
            </div>
            <SchedulerCalendar schedules={schedules} />
        </div>
    )
}
