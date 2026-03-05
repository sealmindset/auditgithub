"use client"

import { useState, useEffect } from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Loader2, AlertCircle, Lock, Unlock } from "lucide-react"
import { API_BASE, apiFetch } from "@/lib/api"

interface Schedule {
  id: string
  repository_id: string
  repository_name: string
  schedule_type: "ai" | "manual"
  frequency: "daily" | "weekly" | "bi-weekly" | "monthly" | "annually"
  day_of_week: number | null
  time_window: "morning" | "afternoon" | "evening" | "night"
  is_locked: boolean
}

interface ScheduleEditDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  schedule: Schedule | null
  onScheduleUpdated: () => void
}

const FREQUENCIES = [
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
  { value: "bi-weekly", label: "Bi-weekly" },
  { value: "monthly", label: "Monthly" },
  { value: "annually", label: "Annually" },
]

const TIME_WINDOWS = [
  { value: "morning", label: "Morning (6-12)", description: "Best for teams in early timezones" },
  { value: "afternoon", label: "Afternoon (12-18)", description: "Good for business hours" },
  { value: "evening", label: "Evening (18-24)", description: "After work hours" },
  { value: "night", label: "Night (0-6)", description: "Minimal disruption (recommended)" },
]

const DAYS = [
  { value: "0", label: "Monday" },
  { value: "1", label: "Tuesday" },
  { value: "2", label: "Wednesday" },
  { value: "3", label: "Thursday" },
  { value: "4", label: "Friday" },
  { value: "5", label: "Saturday" },
  { value: "6", label: "Sunday" },
]

export function ScheduleEditDialog({
  open,
  onOpenChange,
  schedule,
  onScheduleUpdated,
}: ScheduleEditDialogProps) {
  const [frequency, setFrequency] = useState("weekly")
  const [dayOfWeek, setDayOfWeek] = useState<string | undefined>(undefined)
  const [timeWindow, setTimeWindow] = useState("night")
  const [overrideReason, setOverrideReason] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Reset form when schedule changes
  useEffect(() => {
    if (schedule) {
      setFrequency(schedule.frequency)
      setDayOfWeek(schedule.day_of_week !== null ? String(schedule.day_of_week) : undefined)
      setTimeWindow(schedule.time_window)
      setOverrideReason("")
      setError(null)
    }
  }, [schedule])

  const handleSubmit = async () => {
    if (!schedule) return

    setIsLoading(true)
    setError(null)

    try {
      const res = await apiFetch(`${API_BASE}/schedules/${schedule.repository_id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          frequency,
          day_of_week: dayOfWeek ? parseInt(dayOfWeek) : null,
          time_window: timeWindow,
          override_reason: overrideReason || "Manual schedule update",
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.detail || "Failed to update schedule")
      }

      onScheduleUpdated()
      onOpenChange(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred")
    } finally {
      setIsLoading(false)
    }
  }

  const showDayOfWeek = frequency === "weekly" || frequency === "bi-weekly"

  if (!schedule) return null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Edit Scan Schedule</DialogTitle>
          <DialogDescription>
            Modify the scan schedule for <strong>{schedule.repository_name}</strong>
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 py-4">
          {/* Lock Status Indicator */}
          {schedule.is_locked && (
            <div className="flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 dark:bg-amber-950/20 p-3 text-sm">
              <Lock className="h-4 w-4 text-amber-600" />
              <span className="text-amber-700 dark:text-amber-400">
                This schedule is locked. Changes will keep the lock active.
              </span>
            </div>
          )}

          {/* Current Type Display */}
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Current Type:</span>
            <span className="font-medium">
              {schedule.schedule_type === "ai" ? "AI Managed" : "Manual"}
            </span>
          </div>

          {/* Frequency */}
          <div className="space-y-2">
            <Label htmlFor="frequency">Scan Frequency</Label>
            <Select value={frequency} onValueChange={setFrequency}>
              <SelectTrigger id="frequency">
                <SelectValue placeholder="Select frequency" />
              </SelectTrigger>
              <SelectContent>
                {FREQUENCIES.map((f) => (
                  <SelectItem key={f.value} value={f.value}>
                    {f.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Day of Week (for weekly/bi-weekly) */}
          {showDayOfWeek && (
            <div className="space-y-2">
              <Label htmlFor="day">Day of Week</Label>
              <Select value={dayOfWeek} onValueChange={setDayOfWeek}>
                <SelectTrigger id="day">
                  <SelectValue placeholder="Select day" />
                </SelectTrigger>
                <SelectContent>
                  {DAYS.map((d) => (
                    <SelectItem key={d.value} value={d.value}>
                      {d.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {/* Time Window */}
          <div className="space-y-2">
            <Label htmlFor="time">Time Window</Label>
            <Select value={timeWindow} onValueChange={setTimeWindow}>
              <SelectTrigger id="time">
                <SelectValue placeholder="Select time window" />
              </SelectTrigger>
              <SelectContent>
                {TIME_WINDOWS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    <div className="flex flex-col">
                      <span>{t.label}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {TIME_WINDOWS.find((t) => t.value === timeWindow)?.description}
            </p>
          </div>

          {/* Override Reason */}
          <div className="space-y-2">
            <Label htmlFor="reason">Override Reason (Optional)</Label>
            <Input
              id="reason"
              placeholder="Why are you changing this schedule?"
              value={overrideReason}
              onChange={(e) => setOverrideReason(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              This will be recorded in the schedule history for audit purposes.
            </p>
          </div>

          {/* Error Display */}
          {error && (
            <div className="flex items-center gap-2 text-sm text-destructive">
              <AlertCircle className="h-4 w-4" />
              {error}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={isLoading}>
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : (
              "Save Changes"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
