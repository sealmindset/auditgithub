"use client"

import { useState } from "react"
import { Widget } from "@/components/dashboard/Widget"
import { useWidgetData } from "@/hooks/useWidgetData"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  CheckCircle2,
  XCircle,
  Clock,
  Play,
  Loader2,
  Calendar,
  Cog,
  Shield,
  Database
} from "lucide-react"
import { formatDistanceToNow, format } from "date-fns"
import { useToast } from "@/components/ui/use-toast"
import { cn } from "@/lib/utils"

const API_BASE = "http://localhost:8000"

interface JobStatus {
  description: string
  cron: string
  enabled: boolean
  last_run: string | null
  last_status: "success" | "error" | "never_run"
  last_error: string | null
  run_count: number
  error_count: number
}

interface SchedulerStatus {
  enabled: boolean
  running: boolean
  jobs: Record<string, JobStatus>
}

interface NextRun {
  job_name: string
  description: string
  next_run: string | null
}

interface NextRunsResponse {
  jobs: NextRun[]
}

const statusConfig = {
  success: { icon: CheckCircle2, color: "text-green-500", label: "Success" },
  error: { icon: XCircle, color: "text-red-500", label: "Failed" },
  never_run: { icon: Clock, color: "text-muted-foreground", label: "Never run" }
}

const jobIcons: Record<string, typeof Cog> = {
  annealing: Shield,
  scan: Play,
  backup: Database,
  scan_new_repos: Calendar
}

export function BackgroundJobsWidget() {
  const [triggering, setTriggering] = useState<string | null>(null)
  const { toast } = useToast()

  const { data: status, loading: statusLoading, error: statusError, refetch } =
    useWidgetData<SchedulerStatus>("/scheduler/status", { refreshInterval: 60000 })

  const { data: nextRuns } =
    useWidgetData<NextRunsResponse>("/scheduler/next-runs", { refreshInterval: 60000 })

  const handleTrigger = async (jobName: string) => {
    setTriggering(jobName)
    try {
      const res = await fetch(`${API_BASE}/scheduler/jobs/${jobName}/trigger`, {
        method: "POST",
        credentials: "include"
      })

      if (!res.ok) {
        throw new Error("Failed to trigger job")
      }

      toast({
        title: "Job triggered",
        description: `${jobName} has been started.`
      })

      // Refresh status
      refetch()
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Failed to trigger job",
        description: err instanceof Error ? err.message : "Unknown error"
      })
    } finally {
      setTriggering(null)
    }
  }

  const jobs = status?.jobs || {}
  const nextRunsMap = new Map(
    (nextRuns?.jobs || []).map(j => [j.job_name, j.next_run])
  )

  return (
    <Widget
      title="Background Jobs"
      subtitle={status?.running ? "Scheduler active" : "Scheduler stopped"}
      loading={statusLoading}
      error={statusError}
      onRetry={refetch}
      action={
        <Badge variant={status?.running ? "default" : "secondary"}>
          {status?.running ? "Active" : "Stopped"}
        </Badge>
      }
    >
      {Object.keys(jobs).length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <Cog className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p>No jobs configured</p>
        </div>
      ) : (
        <div className="space-y-3">
          {Object.entries(jobs).map(([name, job]) => {
            const config = statusConfig[job.last_status] || statusConfig.never_run
            const StatusIcon = config.icon
            const JobIcon = jobIcons[name] || Cog
            const nextRun = nextRunsMap.get(name)

            return (
              <div
                key={name}
                className="flex items-center justify-between p-3 rounded-lg border"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className={cn(
                    "p-2 rounded-md",
                    job.enabled ? "bg-primary/10" : "bg-muted"
                  )}>
                    <JobIcon className={cn(
                      "h-4 w-4",
                      job.enabled ? "text-primary" : "text-muted-foreground"
                    )} />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium truncate">{job.description}</p>
                      {!job.enabled && (
                        <Badge variant="outline" className="text-xs">Disabled</Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <StatusIcon className={cn("h-3 w-3", config.color)} />
                      <span>
                        {job.last_run
                          ? formatDistanceToNow(new Date(job.last_run), { addSuffix: true })
                          : "Never run"}
                      </span>
                      {job.enabled && nextRun && (
                        <>
                          <span>•</span>
                          <span>Next: {format(new Date(nextRun), "MMM d, h:mm a")}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="text-right text-xs text-muted-foreground">
                    <div>{job.run_count} runs</div>
                    {job.error_count > 0 && (
                      <div className="text-red-500">{job.error_count} errors</div>
                    )}
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    disabled={!job.enabled || triggering === name}
                    onClick={() => handleTrigger(name)}
                    title="Trigger job manually"
                  >
                    {triggering === name ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Play className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </Widget>
  )
}
