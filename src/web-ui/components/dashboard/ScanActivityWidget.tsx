"use client"

import { Widget } from "@/components/dashboard/Widget"
import { useWidgetData } from "@/hooks/useWidgetData"
import { Badge } from "@/components/ui/badge"
import { CheckCircle2, XCircle, Clock, Loader2, Play } from "lucide-react"
import { formatDistanceToNow } from "date-fns"
import { cn } from "@/lib/utils"

interface ScanActivity {
  id: string
  repository_name: string
  scan_type: "full" | "incremental" | "validation"
  status: "queued" | "running" | "completed" | "failed"
  findings_count: number
  new_findings_count: number
  created_at: string
  completed_at: string | null
  duration_seconds: number | null
  triggered_by: string
}

const statusConfig = {
  completed: { icon: CheckCircle2, color: "text-green-500", bg: "bg-green-500/10" },
  failed: { icon: XCircle, color: "text-red-500", bg: "bg-red-500/10" },
  running: { icon: Loader2, color: "text-blue-500", bg: "bg-blue-500/10", animate: true },
  queued: { icon: Clock, color: "text-yellow-500", bg: "bg-yellow-500/10" }
}

const scanTypeLabels: Record<string, string> = {
  full: "Full",
  incremental: "Incr",
  validation: "Valid"
}

function formatDuration(seconds: number | null): string {
  if (!seconds) return "-"
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
}

export function ScanActivityWidget() {
  const { data, loading, error, refetch } = useWidgetData<ScanActivity[]>(
    "/analytics/recent-scans",
    { refreshInterval: 30000 }
  )

  const scans = data || []

  return (
    <Widget
      title="Recent Scans"
      subtitle="Last 10 scan activities"
      loading={loading}
      error={error}
      onRetry={refetch}
    >
      {scans.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <Play className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p>No scan activity yet</p>
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map((scan) => {
            const config = statusConfig[scan.status] || statusConfig.queued
            const StatusIcon = config.icon
            return (
              <div
                key={scan.id}
                className={cn("flex items-center justify-between p-2 rounded-lg", config.bg)}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <StatusIcon
                    className={cn(
                      "h-4 w-4 flex-shrink-0",
                      config.color,
                      "animate" in config && config.animate ? "animate-spin" : ""
                    )}
                  />
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate">
                      {scan.repository_name}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <Badge variant="outline" className="text-xs">
                    {scanTypeLabels[scan.scan_type] || scan.scan_type}
                  </Badge>
                  {scan.status === "completed" && scan.new_findings_count > 0 && (
                    <Badge variant="destructive" className="text-xs">
                      +{scan.new_findings_count}
                    </Badge>
                  )}
                  <span className="text-xs text-muted-foreground w-12 text-right">
                    {formatDuration(scan.duration_seconds)}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </Widget>
  )
}
