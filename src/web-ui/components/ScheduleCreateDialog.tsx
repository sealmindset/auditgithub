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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Loader2, Bot, User, Sparkles, AlertCircle } from "lucide-react"
import { cn } from "@/lib/utils"

const API_BASE = "http://localhost:8000"

interface AIRecommendation {
  frequency: string
  time_window: string
  day_of_week: number | null
  confidence: number
  reasoning: string
  factors_considered: string[]
}

interface ScheduleCreateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  repositoryId: string
  repositoryName: string
  onScheduleCreated: () => void
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

export function ScheduleCreateDialog({
  open,
  onOpenChange,
  repositoryId,
  repositoryName,
  onScheduleCreated,
}: ScheduleCreateDialogProps) {
  const [mode, setMode] = useState<"ai" | "manual">("ai")
  const [frequency, setFrequency] = useState("weekly")
  const [dayOfWeek, setDayOfWeek] = useState<string | undefined>(undefined)
  const [timeWindow, setTimeWindow] = useState("night")
  const [isLoading, setIsLoading] = useState(false)
  const [isLoadingRecommendation, setIsLoadingRecommendation] = useState(false)
  const [recommendation, setRecommendation] = useState<AIRecommendation | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Fetch AI recommendation when dialog opens
  useEffect(() => {
    if (open && repositoryId) {
      fetchRecommendation()
    }
  }, [open, repositoryId])

  // Apply AI recommendation when mode changes to AI
  useEffect(() => {
    if (mode === "ai" && recommendation) {
      setFrequency(recommendation.frequency)
      setTimeWindow(recommendation.time_window)
      // Apply recommended day of week (derived from last commit date)
      if (recommendation.day_of_week !== null) {
        setDayOfWeek(recommendation.day_of_week.toString())
      }
    }
  }, [mode, recommendation])

  const fetchRecommendation = async () => {
    setIsLoadingRecommendation(true)
    setError(null)

    try {
      const res = await fetch(`${API_BASE}/schedules/${repositoryId}/recommend`, {
        credentials: "include",
      })

      if (res.ok) {
        const data: AIRecommendation = await res.json()
        setRecommendation(data)

        // Apply recommendation if in AI mode
        if (mode === "ai") {
          setFrequency(data.frequency)
          setTimeWindow(data.time_window)
          // Apply recommended day of week (derived from last commit date)
          if (data.day_of_week !== null) {
            setDayOfWeek(data.day_of_week.toString())
          }
        }
      } else {
        console.error("Failed to fetch recommendation")
      }
    } catch (err) {
      console.error("Error fetching recommendation:", err)
    } finally {
      setIsLoadingRecommendation(false)
    }
  }

  const handleSubmit = async () => {
    setIsLoading(true)
    setError(null)

    try {
      const res = await fetch(`${API_BASE}/schedules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          repository_id: repositoryId,
          frequency,
          day_of_week: dayOfWeek ? parseInt(dayOfWeek) : null,
          time_window: timeWindow,
          schedule_type: mode,
          use_ai_recommendation: mode === "ai",
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.detail || "Failed to create schedule")
      }

      onScheduleCreated()
      onOpenChange(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred")
    } finally {
      setIsLoading(false)
    }
  }

  const showDayOfWeek = frequency === "weekly" || frequency === "bi-weekly"

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Create Scan Schedule</DialogTitle>
          <DialogDescription>
            Configure a scan schedule for <strong>{repositoryName}</strong>
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 py-4">
          {/* Mode Selection */}
          <div className="space-y-3">
            <Label>Schedule Type</Label>
            <RadioGroup
              value={mode}
              onValueChange={(v) => setMode(v as "ai" | "manual")}
              className="grid grid-cols-2 gap-4"
            >
              <div>
                <RadioGroupItem
                  value="ai"
                  id="mode-ai"
                  className="peer sr-only"
                />
                <Label
                  htmlFor="mode-ai"
                  className={cn(
                    "flex flex-col items-center justify-between rounded-md border-2 border-muted bg-popover p-4 hover:bg-accent hover:text-accent-foreground cursor-pointer",
                    "peer-data-[state=checked]:border-blue-500 [&:has([data-state=checked])]:border-blue-500"
                  )}
                >
                  <Bot className="mb-2 h-6 w-6 text-blue-500" />
                  <span className="text-sm font-medium">AI Recommended</span>
                  <span className="text-xs text-muted-foreground text-center mt-1">
                    Let AI optimize based on activity
                  </span>
                </Label>
              </div>
              <div>
                <RadioGroupItem
                  value="manual"
                  id="mode-manual"
                  className="peer sr-only"
                />
                <Label
                  htmlFor="mode-manual"
                  className={cn(
                    "flex flex-col items-center justify-between rounded-md border-2 border-muted bg-popover p-4 hover:bg-accent hover:text-accent-foreground cursor-pointer",
                    "peer-data-[state=checked]:border-purple-500 [&:has([data-state=checked])]:border-purple-500"
                  )}
                >
                  <User className="mb-2 h-6 w-6 text-purple-500" />
                  <span className="text-sm font-medium">Manual</span>
                  <span className="text-xs text-muted-foreground text-center mt-1">
                    Configure your own schedule
                  </span>
                </Label>
              </div>
            </RadioGroup>
          </div>

          {/* AI Recommendation Display */}
          {mode === "ai" && (
            <div className="rounded-lg border bg-blue-50 dark:bg-blue-950/20 p-4">
              {isLoadingRecommendation ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Analyzing repository patterns...
                </div>
              ) : recommendation ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-blue-500" />
                    <span className="text-sm font-medium">AI Recommendation</span>
                    <span className="text-xs text-muted-foreground">
                      ({Math.round(recommendation.confidence * 100)}% confidence)
                    </span>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {recommendation.reasoning}
                    {recommendation.day_of_week !== null && (recommendation.frequency === "weekly" || recommendation.frequency === "bi-weekly") && (
                      <span className="block mt-1">
                        Scan day: <strong>{DAYS.find(d => d.value === recommendation.day_of_week?.toString())?.label}</strong> (based on last commit activity)
                      </span>
                    )}
                  </p>
                  {recommendation.factors_considered.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {recommendation.factors_considered.map((factor) => (
                        <span
                          key={factor}
                          className="text-xs bg-blue-100 dark:bg-blue-900 px-2 py-0.5 rounded"
                        >
                          {factor.replace(/_/g, " ")}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">
                  Unable to load AI recommendation. Using defaults.
                </div>
              )}
            </div>
          )}

          {/* Frequency */}
          <div className="space-y-2">
            <Label htmlFor="frequency">Scan Frequency</Label>
            <Select
              value={frequency}
              onValueChange={setFrequency}
              disabled={mode === "ai" && isLoadingRecommendation}
            >
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
              <Select
                value={dayOfWeek}
                onValueChange={setDayOfWeek}
                disabled={mode === "ai" && isLoadingRecommendation}
              >
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
            <Select
              value={timeWindow}
              onValueChange={setTimeWindow}
              disabled={mode === "ai" && isLoadingRecommendation}
            >
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
                Creating...
              </>
            ) : (
              "Create Schedule"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
