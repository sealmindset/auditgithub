"use client"

import { Widget } from "@/components/dashboard/Widget"
import { useWidgetData } from "@/hooks/useWidgetData"
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts"
import { TrendingUp, TrendingDown, Minus, Shield, AlertTriangle, AlertCircle, Info } from "lucide-react"
import { cn } from "@/lib/utils"

interface ThreatRadarData {
  critical: number
  high: number
  medium: number
  secrets: number
  abandoned: number
  staleContributors: number
  overallScore: number
}

interface SeverityItem {
  name: string
  count: number
  trend: number
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
  Info: "#3b82f6"
}

const SEVERITY_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  Critical: AlertTriangle,
  High: AlertCircle,
  Medium: Info,
  Low: Shield,
  Info: Info
}

function TrendBadge({ trend }: { trend: number }) {
  const isPositive = trend > 0
  const isNegative = trend < 0
  const isGood = isNegative // Fewer findings is good

  return (
    <span className={cn(
      "inline-flex items-center gap-0.5 text-xs font-medium px-1.5 py-0.5 rounded",
      isGood ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400" :
      isPositive ? "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" :
      "bg-muted text-muted-foreground"
    )}>
      {isPositive ? <TrendingUp className="h-3 w-3" /> :
       isNegative ? <TrendingDown className="h-3 w-3" /> :
       <Minus className="h-3 w-3" />}
      {Math.abs(trend)}%
    </span>
  )
}

function SeverityRow({ item }: { item: SeverityItem }) {
  const Icon = SEVERITY_ICONS[item.name] || Info
  const color = SEVERITY_COLORS[item.name] || "#6b7280"

  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex items-center gap-2">
        <div
          className="w-3 h-3 rounded-full"
          style={{ backgroundColor: color }}
        />
        <Icon className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">{item.name}</span>
      </div>
      <div className="flex items-center gap-3">
        <span className="text-sm font-semibold tabular-nums">{item.count}</span>
        <TrendBadge trend={item.trend} />
      </div>
    </div>
  )
}

export function SecurityOverviewWidget() {
  const { data: threatData, loading: threatLoading, error: threatError } =
    useWidgetData<ThreatRadarData>("/analytics/threat-radar", { refreshInterval: 30000 })

  const { data: severityData, loading: severityLoading, error: severityError } =
    useWidgetData<SeverityItem[]>("/analytics/severity-distribution", { refreshInterval: 30000 })

  const loading = threatLoading || severityLoading
  const error = threatError || severityError

  // Prepare donut chart data
  const chartData = severityData?.filter(s => s.count > 0).map(s => ({
    name: s.name,
    value: s.count,
    color: SEVERITY_COLORS[s.name] || "#6b7280"
  })) || []

  const totalFindings = severityData?.reduce((sum, s) => sum + s.count, 0) || 0
  const overallScore = threatData?.overallScore || 0

  // Score color based on value
  const scoreColor = overallScore >= 80 ? "text-green-500" :
                     overallScore >= 60 ? "text-yellow-500" :
                     overallScore >= 40 ? "text-orange-500" : "text-red-500"

  return (
    <Widget
      title="Security Overview"
      subtitle="Open findings by severity"
      loading={loading}
      error={error}
    >
      <div className="grid grid-cols-2 gap-6">
        {/* Donut Chart */}
        <div className="relative">
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={70}
                paddingAngle={2}
                dataKey="value"
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                formatter={(value: number, name: string) => [`${value} findings`, name]}
              />
            </PieChart>
          </ResponsiveContainer>
          {/* Center metric */}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <div className={cn("text-3xl font-bold", scoreColor)}>
                {overallScore}
              </div>
              <div className="text-xs text-muted-foreground">Score</div>
            </div>
          </div>
        </div>

        {/* Severity breakdown */}
        <div className="flex flex-col justify-center">
          <div className="space-y-1 divide-y divide-border">
            {severityData?.filter(s => ["Critical", "High", "Medium"].includes(s.name)).map(item => (
              <SeverityRow key={item.name} item={item} />
            ))}
          </div>
          <div className="mt-4 pt-3 border-t">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Total Open</span>
              <span className="text-lg font-bold">{totalFindings}</span>
            </div>
          </div>
        </div>
      </div>
    </Widget>
  )
}
