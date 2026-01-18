"use client"

import { formatDistanceToNow, format } from "date-fns"
import { ColumnDef } from "@tanstack/react-table"
import { DataTable } from "@/components/data-table"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
  Loader2,
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
  frequency: "daily" | "weekly" | "bi-weekly" | "monthly" | "annually" | null
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

const FREQUENCY_ORDER: Record<string, number> = {
  daily: 1,
  weekly: 2,
  "bi-weekly": 3,
  monthly: 4,
  annually: 5,
}

function getDaysSince(date: string | null): number | null {
  if (!date) return null
  const now = new Date()
  const pastDate = new Date(date)
  const diffTime = Math.abs(now.getTime() - pastDate.getTime())
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
  return diffDays
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

function getCommitAgeBadge(days: number | null) {
  if (days === null) {
    return (
      <Badge variant="secondary">
        <Clock className="h-3 w-3 mr-1" />
        No data
      </Badge>
    )
  }

  if (days < 31) {
    return (
      <Badge className="bg-green-500 hover:bg-green-600">
        <Clock className="h-3 w-3 mr-1" />
        {days}d ago
      </Badge>
    )
  } else if (days < 365) {
    return (
      <Badge className="bg-yellow-500 hover:bg-yellow-600">
        <Clock className="h-3 w-3 mr-1" />
        {days}d ago
      </Badge>
    )
  } else {
    const years = Math.floor(days / 365)
    return (
      <Badge variant="destructive">
        <Clock className="h-3 w-3 mr-1" />
        {years}y ago
      </Badge>
    )
  }
}

function getScanAgeBadge(days: number | null) {
  if (days === null) {
    return (
      <Badge variant="secondary">
        <Scan className="h-3 w-3 mr-1" />
        Never scanned
      </Badge>
    )
  }

  if (days < 7) {
    return (
      <Badge className="bg-green-500 hover:bg-green-600">
        <Scan className="h-3 w-3 mr-1" />
        {days}d ago
      </Badge>
    )
  } else if (days < 30) {
    return (
      <Badge className="bg-yellow-500 hover:bg-yellow-600">
        <Scan className="h-3 w-3 mr-1" />
        {days}d ago
      </Badge>
    )
  } else if (days < 365) {
    return (
      <Badge variant="destructive">
        <Scan className="h-3 w-3 mr-1" />
        {days}d ago
      </Badge>
    )
  } else {
    const years = Math.floor(days / 365)
    return (
      <Badge variant="destructive">
        <Scan className="h-3 w-3 mr-1" />
        {years}y ago
      </Badge>
    )
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
  if (repo.frequency === "annually") freqLabel = "Annually"

  return (
    <div className="text-sm">
      <span className="font-medium">{freqLabel}</span>
      {day && <span className="text-muted-foreground"> ({day})</span>}
      {time && <span className="text-muted-foreground ml-1">{time}</span>}
    </div>
  )
}

// Create column definitions
function createColumns(
  onCreateSchedule?: (repoId: string) => void,
  onEditSchedule?: (repoId: string) => void,
  onTriggerScan?: (repoId: string) => void
): ColumnDef<RepositoryScheduleInfo>[] {
  return [
    {
      accessorKey: "repository_name",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Repository" />
      ),
      cell: ({ row }) => {
        const isArchived = row.original.is_archived
        return (
          <div className="flex items-center gap-2">
            <span className="font-medium">{row.getValue("repository_name")}</span>
            {isArchived && (
              <Badge variant="secondary" className="text-xs">
                <Archive className="h-3 w-3 mr-1" />
                Archived
              </Badge>
            )}
          </div>
        )
      },
    },
    {
      accessorKey: "pushed_at",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Last Commit" />
      ),
      cell: ({ row }) => {
        const days = getDaysSince(row.getValue("pushed_at") as string | null)
        return getCommitAgeBadge(days)
      },
      sortingFn: (rowA, rowB) => {
        const dateA = rowA.original.pushed_at
        const dateB = rowB.original.pushed_at
        if (!dateA && !dateB) return 0
        if (!dateA) return 1
        if (!dateB) return -1
        return new Date(dateA).getTime() - new Date(dateB).getTime()
      },
    },
    {
      accessorKey: "last_scanned_at",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Last Scan" />
      ),
      cell: ({ row }) => {
        const days = getDaysSince(row.getValue("last_scanned_at") as string | null)
        return getScanAgeBadge(days)
      },
      sortingFn: (rowA, rowB) => {
        const dateA = rowA.original.last_scanned_at
        const dateB = rowB.original.last_scanned_at
        if (!dateA && !dateB) return 0
        if (!dateA) return 1
        if (!dateB) return -1
        return new Date(dateA).getTime() - new Date(dateB).getTime()
      },
    },
    {
      accessorKey: "schedule_status",
      id: "schedule_status",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Schedule" />
      ),
      accessorFn: (row) => {
        if (!row.has_schedule) return "Unscheduled"
        if (row.is_locked) return "Locked"
        return row.schedule_type === "ai" ? "AI" : "Manual"
      },
      cell: ({ row }) => <ScheduleStatusBadge repo={row.original} />,
      filterFn: (row, id, value) => {
        if (!value || !Array.isArray(value) || value.length === 0) return true
        const status = row.getValue(id) as string
        return value.includes(status)
      },
    },
    {
      accessorKey: "frequency",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Frequency" />
      ),
      cell: ({ row }) => <FrequencyDisplay repo={row.original} />,
      accessorFn: (row) => row.frequency || "none",
      sortingFn: (rowA, rowB) => {
        const freqA = rowA.original.frequency ? FREQUENCY_ORDER[rowA.original.frequency] || 99 : 99
        const freqB = rowB.original.frequency ? FREQUENCY_ORDER[rowB.original.frequency] || 99 : 99
        return freqA - freqB
      },
      filterFn: (row, id, value) => {
        if (!value || !Array.isArray(value) || value.length === 0) return true
        const freq = row.getValue(id) as string
        return value.includes(freq)
      },
    },
    {
      accessorKey: "next_scheduled_at",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Next Scan" />
      ),
      cell: ({ row }) => {
        const repo = row.original
        if (repo.has_schedule) {
          return <span className="text-sm">{formatNextScan(repo.next_scheduled_at)}</span>
        }
        return <span className="text-muted-foreground">-</span>
      },
      sortingFn: (rowA, rowB) => {
        const dateA = rowA.original.next_scheduled_at
        const dateB = rowB.original.next_scheduled_at
        if (!dateA && !dateB) return 0
        if (!dateA) return 1
        if (!dateB) return -1
        return new Date(dateA).getTime() - new Date(dateB).getTime()
      },
    },
    {
      id: "actions",
      header: () => <div className="text-right">Actions</div>,
      cell: ({ row }) => {
        const repo = row.original
        return (
          <div className="flex items-center justify-end gap-1">
            {repo.has_schedule ? (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onEditSchedule?.(repo.repository_id)}
                  disabled={!onEditSchedule}
                  title="Edit schedule"
                >
                  <Settings2 className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onTriggerScan?.(repo.repository_id)}
                  disabled={!onTriggerScan}
                  title="Run scan now"
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
        )
      },
    },
  ]
}

export function RepositoryScheduleTable({
  repositories,
  onCreateSchedule,
  onEditSchedule,
  onTriggerScan,
  isLoading = false,
}: RepositoryScheduleTableProps) {
  // Create columns with handlers
  const columns = createColumns(onCreateSchedule, onEditSchedule, onTriggerScan)

  if (repositories.length === 0 && !isLoading) {
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

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 border border-dashed rounded-lg">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <DataTable
      columns={columns}
      data={repositories}
      searchKey="repository_name"
      searchPlaceholder={`Search ${repositories.length.toLocaleString()} repositories...`}
      tableId="schedules"
      enableGrouping={true}
      initialPageSize={25}
    />
  )
}
