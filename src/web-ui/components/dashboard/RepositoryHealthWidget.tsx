"use client"

import { Widget } from "@/components/dashboard/Widget"
import { useWidgetData } from "@/hooks/useWidgetData"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import {
  GitBranch,
  AlertTriangle,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Archive,
  Clock
} from "lucide-react"
import { formatDistanceToNow } from "date-fns"
import { cn } from "@/lib/utils"

interface RepoRiskItem {
  id: string
  name: string
  riskScore: number
  riskLevel: "critical" | "high" | "medium" | "low"
  criticalFindings: number
  highFindings: number
  secretsCount: number
  isArchived: boolean
  isAbandoned: boolean
}

const riskLevelConfig = {
  critical: {
    icon: ShieldAlert,
    color: "text-red-500",
    bg: "bg-red-500",
    badgeVariant: "destructive" as const
  },
  high: {
    icon: AlertTriangle,
    color: "text-orange-500",
    bg: "bg-orange-500",
    badgeVariant: "default" as const
  },
  medium: {
    icon: Shield,
    color: "text-yellow-500",
    bg: "bg-yellow-500",
    badgeVariant: "secondary" as const
  },
  low: {
    icon: ShieldCheck,
    color: "text-green-500",
    bg: "bg-green-500",
    badgeVariant: "outline" as const
  }
}

function RiskProgressBar({ score }: { score: number }) {
  const getColor = (score: number) => {
    if (score >= 75) return "bg-red-500"
    if (score >= 50) return "bg-orange-500"
    if (score >= 25) return "bg-yellow-500"
    return "bg-green-500"
  }

  return (
    <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
      <div
        className={cn("h-full rounded-full transition-all", getColor(score))}
        style={{ width: `${Math.min(score, 100)}%` }}
      />
    </div>
  )
}

function RepoHealthCard({ repo }: { repo: RepoRiskItem }) {
  const config = riskLevelConfig[repo.riskLevel] || riskLevelConfig.low
  const RiskIcon = config.icon

  return (
    <div className="flex items-center gap-3 p-3 rounded-lg border hover:bg-muted/50 transition-colors">
      <div className={cn("p-2 rounded-md bg-muted")}>
        <GitBranch className="h-4 w-4 text-muted-foreground" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <p className="text-sm font-medium truncate">{repo.name}</p>
          {repo.isArchived && (
            <Archive className="h-3 w-3 text-muted-foreground" />
          )}
          {repo.isAbandoned && (
            <Clock className="h-3 w-3 text-yellow-500" title="Abandoned" />
          )}
        </div>
        <RiskProgressBar score={repo.riskScore} />
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        {repo.criticalFindings > 0 && (
          <Badge variant="destructive" className="text-xs">
            {repo.criticalFindings} crit
          </Badge>
        )}
        {repo.highFindings > 0 && (
          <Badge variant="secondary" className="text-xs bg-orange-500/10 text-orange-600">
            {repo.highFindings} high
          </Badge>
        )}
        {repo.secretsCount > 0 && (
          <Badge variant="outline" className="text-xs text-purple-600 border-purple-300">
            {repo.secretsCount} secrets
          </Badge>
        )}
        <div className="flex items-center gap-1 min-w-[60px] justify-end">
          <RiskIcon className={cn("h-4 w-4", config.color)} />
          <span className={cn("text-sm font-semibold", config.color)}>
            {repo.riskScore}
          </span>
        </div>
      </div>
    </div>
  )
}

export function RepositoryHealthWidget() {
  const { data, loading, error, refetch } = useWidgetData<RepoRiskItem[]>(
    "/analytics/risk-heatmap?limit=8",
    { refreshInterval: 60000 }
  )

  const repos = data || []

  // Calculate summary stats
  const criticalCount = repos.filter(r => r.riskLevel === "critical").length
  const highCount = repos.filter(r => r.riskLevel === "high").length
  const healthyCount = repos.filter(r => r.riskLevel === "low").length

  return (
    <Widget
      title="Repository Health"
      subtitle={`${repos.length} repositories • ${criticalCount} critical, ${highCount} high risk`}
      loading={loading}
      error={error}
      onRetry={refetch}
      action={
        healthyCount > 0 ? (
          <Badge variant="outline" className="text-green-600 border-green-300">
            {healthyCount} healthy
          </Badge>
        ) : null
      }
    >
      {repos.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <GitBranch className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p>No repositories found</p>
        </div>
      ) : (
        <div className="space-y-2">
          {repos.map((repo) => (
            <RepoHealthCard key={repo.id} repo={repo} />
          ))}
        </div>
      )}
    </Widget>
  )
}
