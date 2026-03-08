"use client"

import { useEffect, useState } from "react"
import { apiFetch, API_BASE } from "@/lib/api"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  FileText,
  Activity,
  Layers,
  Bot,
  Hash,
  Coins,
  AlertTriangle,
  Loader2,
  AlertCircle,
  Clock,
  TrendingUp,
} from "lucide-react"

interface Prompt {
  id: string
  name: string
  slug: string
  model: string
  category: string
  is_active: boolean
  usage_count?: number
}

interface AuditLogEntry {
  id: string
  action: string
  prompt_id: string
  prompt_slug: string
  version: number | null
  user_id: string | null
  user_email: string | null
  created_at: string
}

interface PromptAnalyticsOverview {
  total_prompts: number
  active_prompts: number
  total_versions: number
  total_agents: number
  total_calls: number
  total_tokens: number
  versions_today: number
  error_rate: number
  category_breakdown: Record<string, number>
  provider_breakdown: Record<string, number>
  model_breakdown: Record<string, number>
  top_prompts: Prompt[]
  recent_changes: AuditLogEntry[]
}

const categoryColors: Record<string, string> = {
  system: "bg-purple-500/15 text-purple-700 dark:text-purple-400 border-purple-500/30",
  user: "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30",
  template: "bg-green-500/15 text-green-700 dark:text-green-400 border-green-500/30",
  agent: "bg-orange-500/15 text-orange-700 dark:text-orange-400 border-orange-500/30",
  skill: "bg-cyan-500/15 text-cyan-700 dark:text-cyan-400 border-cyan-500/30",
  mcp: "bg-pink-500/15 text-pink-700 dark:text-pink-400 border-pink-500/30",
}

const categoryBarColors: Record<string, string> = {
  system: "bg-purple-500",
  user: "bg-blue-500",
  template: "bg-green-500",
  agent: "bg-orange-500",
  skill: "bg-cyan-500",
  mcp: "bg-pink-500",
}

function StyledBar({
  label,
  value,
  maxValue,
  barColor,
}: {
  label: string
  value: number
  maxValue: number
  barColor?: string
}) {
  const pct = maxValue > 0 ? (value / maxValue) * 100 : 0
  return (
    <div className="flex items-center gap-3">
      <span className="text-sm w-24 truncate text-right text-muted-foreground">
        {label}
      </span>
      <div className="flex-1 h-6 rounded-md bg-muted overflow-hidden relative">
        <div
          className={`h-full rounded-md transition-all duration-500 ${barColor ?? "bg-primary"}`}
          style={{ width: `${Math.max(pct, 2)}%` }}
        />
      </div>
      <span className="text-sm font-medium w-12 text-right tabular-nums">
        {value}
      </span>
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
  description,
}: {
  icon: React.ReactNode
  label: string
  value: string | number
  description?: string
}) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted">
            {icon}
          </div>
          <div className="min-w-0">
            <p className="text-sm text-muted-foreground">{label}</p>
            <p className="text-2xl font-bold tracking-tight">{value}</p>
            {description && (
              <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export default function PromptAnalyticsPage() {
  const [data, setData] = useState<PromptAnalyticsOverview | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchAnalytics() {
      try {
        setLoading(true)
        const res = await apiFetch(`${API_BASE}/prompts/analytics/overview`)
        if (!res.ok) throw new Error(`Failed to fetch analytics: ${res.status}`)
        const json = await res.json()
        setData(json)
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error")
      } finally {
        setLoading(false)
      }
    }
    fetchAnalytics()
  }, [])

  if (loading) {
    return (
      <div className="container mx-auto py-12 flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <span className="ml-3 text-muted-foreground">Loading analytics...</span>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="container mx-auto py-12">
        <div className="flex items-center gap-2 rounded-lg border border-destructive/50 bg-destructive/10 p-4">
          <AlertCircle className="h-5 w-5 text-destructive" />
          <p className="text-destructive">{error ?? "Failed to load analytics data."}</p>
        </div>
      </div>
    )
  }

  const categoryMax = Math.max(...Object.values(data.category_breakdown), 1)
  const providerMax = Math.max(...Object.values(data.provider_breakdown), 1)
  const modelMax = Math.max(...Object.values(data.model_breakdown), 1)

  function formatNumber(n: number): string {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
    return n.toLocaleString()
  }

  function formatTimestamp(ts: string): string {
    try {
      const d = new Date(ts)
      return d.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    } catch {
      return ts
    }
  }

  return (
    <div className="container mx-auto py-6 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Prompt Analytics</h1>
        <p className="text-muted-foreground mt-1">
          Usage metrics and insights across all managed prompts.
        </p>
      </div>

      <Separator />

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <StatCard
          icon={<FileText className="h-5 w-5 text-muted-foreground" />}
          label="Total Prompts"
          value={data.total_prompts}
        />
        <StatCard
          icon={<Activity className="h-5 w-5 text-green-500" />}
          label="Active"
          value={data.active_prompts}
        />
        <StatCard
          icon={<Layers className="h-5 w-5 text-muted-foreground" />}
          label="Versions"
          value={data.total_versions}
          description={`${data.versions_today} today`}
        />
        <StatCard
          icon={<Bot className="h-5 w-5 text-muted-foreground" />}
          label="Agents"
          value={data.total_agents}
        />
        <StatCard
          icon={<Hash className="h-5 w-5 text-muted-foreground" />}
          label="Total Calls"
          value={formatNumber(data.total_calls)}
        />
        <StatCard
          icon={<Coins className="h-5 w-5 text-muted-foreground" />}
          label="Total Tokens"
          value={formatNumber(data.total_tokens)}
        />
        <StatCard
          icon={<AlertTriangle className="h-5 w-5 text-red-500" />}
          label="Error Rate"
          value={`${(data.error_rate * 100).toFixed(1)}%`}
        />
      </div>

      {/* Breakdowns Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Category Breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Category Breakdown</CardTitle>
            <CardDescription>Prompts by category</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(data.category_breakdown).length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No data</p>
            ) : (
              Object.entries(data.category_breakdown)
                .sort(([, a], [, b]) => b - a)
                .map(([cat, count]) => (
                  <StyledBar
                    key={cat}
                    label={cat}
                    value={count}
                    maxValue={categoryMax}
                    barColor={categoryBarColors[cat] ?? "bg-primary"}
                  />
                ))
            )}
          </CardContent>
        </Card>

        {/* Provider Breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Provider Breakdown</CardTitle>
            <CardDescription>Prompts by provider</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(data.provider_breakdown).length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No data</p>
            ) : (
              Object.entries(data.provider_breakdown)
                .sort(([, a], [, b]) => b - a)
                .map(([provider, count]) => (
                  <StyledBar
                    key={provider}
                    label={provider}
                    value={count}
                    maxValue={providerMax}
                    barColor="bg-primary"
                  />
                ))
            )}
          </CardContent>
        </Card>

        {/* Model Breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Model Breakdown</CardTitle>
            <CardDescription>LLM models in use</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(data.model_breakdown).length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No data</p>
            ) : (
              Object.entries(data.model_breakdown)
                .sort(([, a], [, b]) => b - a)
                .map(([model, count]) => (
                  <div
                    key={model}
                    className="flex items-center justify-between rounded-md border px-3 py-2"
                  >
                    <span className="text-sm font-mono truncate">{model}</span>
                    <Badge variant="secondary" className="ml-2 tabular-nums">
                      {count}
                    </Badge>
                  </div>
                ))
            )}
          </CardContent>
        </Card>
      </div>

      {/* Bottom Row: Top Prompts + Recent Changes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Prompts */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="h-4 w-4" />
              Top Prompts
            </CardTitle>
            <CardDescription>Most-used prompts by usage count</CardDescription>
          </CardHeader>
          <CardContent>
            {data.top_prompts.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No data</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Model</TableHead>
                    <TableHead className="text-right">Usage</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.top_prompts.slice(0, 5).map((prompt) => (
                    <TableRow key={prompt.slug}>
                      <TableCell>
                        <a
                          href={`/prompts/${prompt.slug}`}
                          className="font-medium hover:underline"
                        >
                          {prompt.name}
                        </a>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={
                            categoryColors[prompt.category] ??
                            "bg-muted text-muted-foreground"
                          }
                        >
                          {prompt.category}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs font-mono text-muted-foreground">
                          {prompt.model}
                        </span>
                      </TableCell>
                      <TableCell className="text-right tabular-nums font-medium">
                        {(prompt.usage_count ?? 0).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Recent Changes */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Clock className="h-4 w-4" />
              Recent Changes
            </CardTitle>
            <CardDescription>Latest audit log entries</CardDescription>
          </CardHeader>
          <CardContent>
            {data.recent_changes.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">
                No recent changes
              </p>
            ) : (
              <div className="space-y-3">
                {data.recent_changes.map((entry) => (
                  <div
                    key={entry.id}
                    className="flex items-start justify-between gap-3 rounded-md border px-4 py-3"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge variant="outline" className="text-xs">
                          {entry.action}
                        </Badge>
                        <a
                          href={`/prompts/${entry.prompt_slug}`}
                          className="text-sm font-medium hover:underline truncate"
                        >
                          {entry.prompt_slug}
                        </a>
                        {entry.version !== null && (
                          <span className="text-xs text-muted-foreground">
                            v{entry.version}
                          </span>
                        )}
                      </div>
                      {entry.user_email && (
                        <p className="text-xs text-muted-foreground mt-1">
                          by {entry.user_email}
                        </p>
                      )}
                    </div>
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="text-xs text-muted-foreground whitespace-nowrap">
                            {formatTimestamp(entry.created_at)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{entry.created_at}</TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
