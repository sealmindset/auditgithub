"use client"

import { Widget } from "@/components/dashboard/Widget"
import { useWidgetData } from "@/hooks/useWidgetData"
import { Badge } from "@/components/ui/badge"
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from "recharts"
import { TrendingUp, TrendingDown, Minus } from "lucide-react"
import { cn } from "@/lib/utils"

interface TimelinePoint {
  date: string
  critical: number
  high: number
  medium: number
  low: number
  total_open: number
}

interface FindingTrendsData {
  days: number
  timeline: TimelinePoint[]
  current_totals: {
    critical: number
    high: number
    medium: number
    low: number
  }
}

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e"
}

function TrendIndicator({ current, previous }: { current: number; previous: number }) {
  if (previous === 0) return null

  const change = ((current - previous) / previous) * 100
  const isPositive = change > 0
  const isNegative = change < 0
  // For findings, negative (fewer) is good
  const isGood = isNegative

  if (Math.abs(change) < 1) {
    return (
      <span className="inline-flex items-center gap-0.5 text-xs text-muted-foreground">
        <Minus className="h-3 w-3" />
        stable
      </span>
    )
  }

  return (
    <span className={cn(
      "inline-flex items-center gap-0.5 text-xs font-medium",
      isGood ? "text-green-600" : "text-red-600"
    )}>
      {isPositive ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
      {Math.abs(change).toFixed(0)}%
    </span>
  )
}

function SeverityLegendItem({
  severity,
  count,
  color
}: {
  severity: string
  count: number
  color: string
}) {
  return (
    <div className="flex items-center gap-2">
      <div
        className="w-3 h-3 rounded-sm"
        style={{ backgroundColor: color }}
      />
      <span className="text-xs text-muted-foreground capitalize">{severity}</span>
      <span className="text-xs font-semibold">{count}</span>
    </div>
  )
}

export function FindingTrendsWidget() {
  const { data, loading, error, refetch } = useWidgetData<FindingTrendsData>(
    "/analytics/finding-trends?days=30",
    { refreshInterval: 120000 } // 2 minute refresh
  )

  const timeline = data?.timeline || []
  const totals = data?.current_totals || { critical: 0, high: 0, medium: 0, low: 0 }

  // Calculate trend from first half to second half of timeline
  const midpoint = Math.floor(timeline.length / 2)
  const firstHalf = timeline.slice(0, midpoint)
  const secondHalf = timeline.slice(midpoint)

  const firstHalfTotal = firstHalf.reduce((sum, p) => sum + p.critical + p.high + p.medium + p.low, 0)
  const secondHalfTotal = secondHalf.reduce((sum, p) => sum + p.critical + p.high + p.medium + p.low, 0)

  const totalFindings = totals.critical + totals.high + totals.medium + totals.low

  return (
    <Widget
      title="Finding Trends"
      subtitle="New findings by severity (30 days)"
      loading={loading}
      error={error}
      onRetry={refetch}
      action={
        <div className="flex items-center gap-2">
          <Badge variant="outline">{totalFindings} open</Badge>
          <TrendIndicator current={secondHalfTotal} previous={firstHalfTotal} />
        </div>
      }
    >
      {timeline.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <TrendingUp className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p>No finding data available</p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Chart */}
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={timeline}
                margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  className="text-muted-foreground"
                />
                <YAxis
                  tick={{ fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  className="text-muted-foreground"
                  width={30}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--background))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "6px",
                    fontSize: "12px"
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stackId="1"
                  stroke={SEVERITY_COLORS.critical}
                  fill={SEVERITY_COLORS.critical}
                  fillOpacity={0.6}
                  name="Critical"
                />
                <Area
                  type="monotone"
                  dataKey="high"
                  stackId="1"
                  stroke={SEVERITY_COLORS.high}
                  fill={SEVERITY_COLORS.high}
                  fillOpacity={0.6}
                  name="High"
                />
                <Area
                  type="monotone"
                  dataKey="medium"
                  stackId="1"
                  stroke={SEVERITY_COLORS.medium}
                  fill={SEVERITY_COLORS.medium}
                  fillOpacity={0.6}
                  name="Medium"
                />
                <Area
                  type="monotone"
                  dataKey="low"
                  stackId="1"
                  stroke={SEVERITY_COLORS.low}
                  fill={SEVERITY_COLORS.low}
                  fillOpacity={0.6}
                  name="Low"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Legend with current counts */}
          <div className="flex justify-between px-2">
            <SeverityLegendItem severity="critical" count={totals.critical} color={SEVERITY_COLORS.critical} />
            <SeverityLegendItem severity="high" count={totals.high} color={SEVERITY_COLORS.high} />
            <SeverityLegendItem severity="medium" count={totals.medium} color={SEVERITY_COLORS.medium} />
            <SeverityLegendItem severity="low" count={totals.low} color={SEVERITY_COLORS.low} />
          </div>
        </div>
      )}
    </Widget>
  )
}
