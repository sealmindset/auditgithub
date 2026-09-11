"use client"

import * as React from "react"
import Link from "next/link"
import { ArrowRight, Minus, TrendingDown, TrendingUp } from "lucide-react"

import { cn } from "@/lib/utils"
import { Skeleton } from "@/components/ui/skeleton"
import { STATUS_TONE, trendTone, type StatusTone } from "@/lib/severity"

export interface StatTrend {
  /** Signed change over the comparison window. */
  delta: number
  /** What the window was, e.g. "vs last week". */
  label: string
  /** Whether a rise is good news. Findings: false. Repos scanned: true. */
  higherIsBetter?: boolean
}

interface StatCardProps {
  label: string
  value: React.ReactNode
  /** One line under the number. Keep it to three or four words. */
  hint?: string
  icon?: React.ComponentType<{ className?: string }>
  /** Colours the icon tile and the value. */
  tone?: StatusTone
  trend?: StatTrend
  loading?: boolean
  href?: string
  className?: string
}

/**
 * Stat tile.
 *
 * One tile shape for every metric in the product. The number is the loudest
 * thing in it; the label sits above in small caps; the trend sits below a rule
 * so it never competes. Hover raises the shadow only — never the scale — so a
 * row of four tiles cannot shove its neighbours around.
 */
export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = "neutral",
  trend,
  loading = false,
  href,
  className,
}: StatCardProps) {
  const toneClasses = STATUS_TONE[tone]

  const body = (
    <>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-1.5">
          <p className="eyebrow truncate">{label}</p>
          {loading ? (
            <Skeleton className="h-9 w-20" />
          ) : (
            <p
              data-numeric
              className={cn(
                "stat-value",
                tone === "neutral" ? "text-foreground" : toneClasses.text,
              )}
            >
              {value}
            </p>
          )}
          {hint && (
            <p className="truncate text-xs text-muted-foreground">{hint}</p>
          )}
        </div>

        {Icon && (
          <span
            aria-hidden="true"
            className={cn(
              "flex size-9 shrink-0 items-center justify-center rounded-lg border",
              toneClasses.soft,
            )}
          >
            <Icon className="size-4" />
          </span>
        )}
      </div>

      {trend && !loading && <StatTrendRow trend={trend} />}

      {href && (
        <span className="mt-auto inline-flex items-center gap-1 pt-3 text-xs font-medium text-primary-text opacity-0 transition-opacity duration-200 group-hover:opacity-100">
          View
          <ArrowRight className="size-3" aria-hidden="true" />
        </span>
      )}
    </>
  )

  const shell = cn(
    "group flex min-h-[7.5rem] flex-col rounded-xl border bg-card p-5",
    "shadow-xs transition-[box-shadow,border-color] duration-200 ease-out",
    href && "cursor-pointer hover:border-border-strong hover:shadow-md",
    className,
  )

  if (href) {
    return (
      <Link href={href} className={shell} aria-label={`${label}: ${value}`}>
        {body}
      </Link>
    )
  }

  return <div className={shell}>{body}</div>
}

function StatTrendRow({ trend }: { trend: StatTrend }) {
  const { delta, label, higherIsBetter = true } = trend
  const tone = trendTone(delta, higherIsBetter)
  const Icon = delta === 0 ? Minus : delta > 0 ? TrendingUp : TrendingDown

  return (
    <div className="mt-4 flex items-center gap-1.5 border-t pt-3 text-xs font-medium">
      <Icon
        className={cn("size-3.5 shrink-0", STATUS_TONE[tone].text)}
        aria-hidden="true"
      />
      <span className={cn("tabular-nums", STATUS_TONE[tone].text)}>
        {delta > 0 ? "+" : ""}
        {delta}
      </span>
      <span className="truncate text-muted-foreground">{label}</span>
    </div>
  )
}

/** Grid wrapper so every stat row across the app breaks at the same widths. */
export function StatGrid({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      className={cn(
        "grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4",
        className,
      )}
      {...props}
    />
  )
}
