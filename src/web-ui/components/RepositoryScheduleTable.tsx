"use client"

import { useState, useMemo } from "react"
import { formatDistanceToNow, format } from "date-fns"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Calendar,
  Clock,
  Play,
  Settings2,
  Plus,
  Lock,
  Bot,
  User,
  GitCommit,
  Scan,
  AlertCircle,
  Archive,
} from "lucide-react"
import { cn } from "@/lib/utils"

export interface RepositoryScheduleInfo {
  repository_id: string
  repository_name: string
  pushed_at: string | null
  last_scanned_at: string | null
  is_archived: boolean
  has_schedule: boolean
  schedule_id: string | null
  schedule_type: "ai" | "manual" | null
  frequency: "daily" | "weekly" | "bi-weekly" | "monthly" | null
  day_of_week: number | null
  time_window: "morning" | "afternoon" | "evening" | "night" | null
  next_scheduled_at: string | null
  last_executed_at: string | null
  last_execution_status: string | null
  is_locked: boolean
  ai_confidence: number | null
}

interface RepositoryScheduleTableProps {
  repositories: RepositoryScheduleInfo[]
  onCreateSchedule?: (repoId: string) => void
  onEditSchedule?: (repoId: string) => void
  onTriggerScan?: (repoId: string) => void
  isLoading?: boolean
}

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

const TIME_WINDOW_LABELS: Record<string, string> = {
  morning: "Morning (6-12)",
  afternoon: "Afternoon (12-18)",
  evening: "Evening (18-24)",
  night: "Night (0-6)",
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "Never"
  try {
    const date = new Date(dateStr)
    return formatDistanceToNow(date, { addSuffix: true })
  } catch {
    return "Invalid date"
  }
}

function formatNextScan(dateStr: string | null): string {
  if (!dateStr) return "-"
  try {
    const date = new Date(dateStr)
    return format(date, "MMM d, h:mm a")
  } catch {
    return "Invalid"
  }
}

function ScheduleStatusBadge({ repo }: { repo: RepositoryScheduleInfo }) {
  if (!repo.has_schedule) {
    return (
      <Badge variant="outline" className="gap-1 text-muted-foreground">
        <AlertCircle className="h-3 w-3" />
        Unscheduled
      </Badge>
    )
  }

  const isAI = repo.schedule_type === "ai"

  return (
    <div className="flex items-center gap-2">
      <Badge
        variant="outline"
        className={cn(
          "gap-1",
          isAI ? "border-blue-500 text-blue-600" : "border-purple-500 text-purple-600"
        )}
      >
        {isAI ? <Bot className="h-3 w-3" /> : <User className="h-3 w-3" />}
        {isAI ? "AI" : "Manual"}
      </Badge>
      {repo.is_locked && (
        <Lock className="h-3.5 w-3.5 text-amber-500" />
      )}
    </div>
  )
}

function FrequencyDisplay({ repo }: { repo: RepositoryScheduleInfo }) {
  if (!repo.has_schedule || !repo.frequency) {
    return <span className="text-muted-foreground">-</span>
  }

  const day = repo.day_of_week !== null ? DAYS[repo.day_of_week] : ""
  const time = repo.time_window ? TIME_WINDOW_LABELS[repo.time_window]?.split(" ")[0] : ""

  let freqLabel = repo.frequency.charAt(0).toUpperCase() + repo.frequency.slice(1)
  if (repo.frequency === "bi-weekly") freqLabel = "Bi-weekly"

  return (
    <div className="text-sm">
      <span className="font-medium">{freqLabel}</span>
      {day && <span className="text-muted-foreground"> ({day})</span>}
      {time && <span className="text-muted-foreground ml-1">{time}</span>}
    </div>
  )
}

export function RepositoryScheduleTable({
  repositories,
  onCreateSchedule,
  onEditSchedule,
  onTriggerScan,
  isLoading = false,
}: RepositoryScheduleTableProps) {
  const [filter, setFilter] = useState<"all" | "scheduled" | "unscheduled">("all")

  const filteredRepos = useMemo(() => {
    if (filter === "all") return repositories
    if (filter === "scheduled") return repositories.filter(r => r.has_schedule)
    return repositories.filter(r => !r.has_schedule)
  }, [repositories, filter])

  const scheduledCount = repositories.filter(r => r.has_schedule).length
  const unscheduledCount = repositories.filter(r => !r.has_schedule).length

  if (repositories.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 border border-dashed rounded-lg">
        <Calendar className="h-12 w-12 text-muted-foreground mb-4" />
        <h3 className="text-lg font-medium">No repositories found</h3>
        <p className="text-muted-foreground text-sm mt-1">
          Sync your repositories to get started with scheduling.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Filter tabs */}
      <Tabs value={filter} onValueChange={(v) => setFilter(v as typeof filter)}>
        <TabsList>
          <TabsTrigger value="all" className="gap-2">
            All
            <Badge variant="secondary" className="ml-1">{repositories.length}</Badge>
          </TabsTrigger>
          <TabsTrigger value="scheduled" className="gap-2">
            Scheduled
            <Badge variant="secondary" className="ml-1">{scheduledCount}</Badge>
          </TabsTrigger>
          <TabsTrigger value="unscheduled" className="gap-2">
            Unscheduled
            <Badge variant="secondary" className="ml-1">{unscheduledCount}</Badge>
          </TabsTrigger>
        </TabsList>
      </Tabs>

      {/* Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Repository</TableHead>
              <TableHead>
                <div className="flex items-center gap-1">
                  <GitCommit className="h-3.5 w-3.5" />
                  Last Commit
                </div>
              </TableHead>
              <TableHead>
                <div className="flex items-center gap-1">
                  <Scan className="h-3.5 w-3.5" />
                  Last Scan
                </div>
              </TableHead>
              <TableHead>Schedule</TableHead>
              <TableHead>Frequency</TableHead>
              <TableHead>
                <div className="flex items-center gap-1">
                  <Clock className="h-3.5 w-3.5" />
                  Next Scan
                </div>
              </TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredRepos.map((repo) => (
              <TableRow key={repo.repository_id} className={repo.is_archived ? "opacity-60" : ""}>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{repo.repository_name}</span>
                    {repo.is_archived && (
                      <Badge variant="outline" className="text-xs">
                        <Archive className="h-3 w-3 mr-1" />
                        Archived
                      </Badge>
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {formatDate(repo.pushed_at)}
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {formatDate(repo.last_scanned_at)}
                </TableCell>
                <TableCell>
                  <ScheduleStatusBadge repo={repo} />
                </TableCell>
                <TableCell>
                  <FrequencyDisplay repo={repo} />
                </TableCell>
                <TableCell>
                  {repo.has_schedule ? (
                    <span className="text-sm">{formatNextScan(repo.next_scheduled_at)}</span>
                  ) : (
                    <span className="text-muted-foreground">-</span>
                  )}
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex items-center justify-end gap-1">
                    {repo.has_schedule ? (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onEditSchedule?.(repo.repository_id)}
                          disabled={!onEditSchedule}
                        >
                          <Settings2 className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onTriggerScan?.(repo.repository_id)}
                          disabled={!onTriggerScan}
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                      </>
                    ) : (
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-1"
                        onClick={() => onCreateSchedule?.(repo.repository_id)}
                        disabled={!onCreateSchedule}
                      >
                        <Plus className="h-4 w-4" />
                        Schedule
                      </Button>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}
