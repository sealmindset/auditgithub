"use client"

import * as React from "react"
import { AlertOctagon, AlertTriangle, Info, ShieldAlert, ShieldCheck } from "lucide-react"

import { cn } from "@/lib/utils"
import {
  SEVERITY_TONE,
  STATUS_TONE,
  type Severity,
  type StatusTone,
  normalizeSeverity,
  severityLabel,
  statusLabel,
  statusTone,
} from "@/lib/severity"

const SEVERITY_ICON: Record<Severity, React.ComponentType<{ className?: string }>> = {
  critical: AlertOctagon,
  high: ShieldAlert,
  medium: AlertTriangle,
  low: ShieldCheck,
  info: Info,
}

interface SeverityBadgeProps extends React.ComponentProps<"span"> {
  severity: string | null | undefined
  /** `soft` (default) for lists; `solid` when one item must dominate. */
  tone?: "soft" | "solid"
  size?: "sm" | "default"
  showIcon?: boolean
  /** Overrides the label — e.g. to append a CVSS score. */
  label?: React.ReactNode
}

/**
 * The single way severity is rendered. Colour is never the only signal: each
 * level carries its own glyph and its own word, so the badge survives both
 * greyscale printing and the ~8% of men with a red/green deficiency.
 */
export function SeverityBadge({
  severity,
  tone = "soft",
  size = "default",
  showIcon = true,
  label,
  className,
  ...props
}: SeverityBadgeProps) {
  const level = normalizeSeverity(severity)
  const Icon = SEVERITY_ICON[level]
  const text = label ?? severityLabel(severity)

  return (
    <span
      data-slot="severity-badge"
      data-severity={level}
      className={cn(
        "inline-flex w-fit shrink-0 items-center gap-1 rounded-md border font-medium whitespace-nowrap",
        size === "sm"
          ? "h-5 px-1.5 text-[0.6875rem]"
          : "h-[1.375rem] px-2 text-xs",
        SEVERITY_TONE[level][tone],
        className,
      )}
      {...props}
    >
      {showIcon && (
        <Icon
          className={size === "sm" ? "size-2.5" : "size-3"}
          aria-hidden="true"
        />
      )}
      {text}
    </span>
  )
}

/** Compact severity marker for dense table cells and legends. */
export function SeverityDot({
  severity,
  className,
  ...props
}: { severity: string | null | undefined } & React.ComponentProps<"span">) {
  const level = normalizeSeverity(severity)
  return (
    <span
      role="img"
      aria-label={`${severityLabel(severity)} severity`}
      className={cn(
        "inline-block size-2 shrink-0 rounded-full",
        SEVERITY_TONE[level].dot,
        className,
      )}
      {...props}
    />
  )
}

interface StatusBadgeProps extends React.ComponentProps<"span"> {
  status: string | null | undefined
  /** Force a tone when the raw string is not in the known vocabulary. */
  tone?: StatusTone
  size?: "sm" | "default"
  /** Leading dot. Off by default; useful for live/running states. */
  showDot?: boolean
  /** Animate the dot. Use only for genuinely in-flight work. */
  pulse?: boolean
  label?: React.ReactNode
}

/** The single way a lifecycle status is rendered. */
export function StatusBadge({
  status,
  tone,
  size = "default",
  showDot = false,
  pulse = false,
  label,
  className,
  ...props
}: StatusBadgeProps) {
  const resolved = tone ?? statusTone(status)

  return (
    <span
      data-slot="status-badge"
      data-status={status ?? "unknown"}
      className={cn(
        "inline-flex w-fit shrink-0 items-center gap-1.5 rounded-md border font-medium whitespace-nowrap",
        size === "sm"
          ? "h-5 px-1.5 text-[0.6875rem]"
          : "h-[1.375rem] px-2 text-xs",
        STATUS_TONE[resolved].soft,
        className,
      )}
      {...props}
    >
      {showDot && (
        <span
          className={cn(
            "size-1.5 shrink-0 rounded-full",
            STATUS_TONE[resolved].dot,
            pulse && "animate-pulse",
          )}
          aria-hidden="true"
        />
      )}
      {label ?? statusLabel(status)}
    </span>
  )
}
