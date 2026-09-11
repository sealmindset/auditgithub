"use client"

import * as React from "react"
import { AlertCircle, RefreshCw } from "lucide-react"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"

interface EmptyStateProps {
  icon?: React.ComponentType<{ className?: string }>
  title: string
  description?: React.ReactNode
  action?: React.ReactNode
  size?: "sm" | "default"
  className?: string
}

/**
 * Empty state.
 *
 * "No data" was previously rendered as a bare grey sentence in a table cell,
 * which reads as a failure. This gives the absence a shape, and — where one
 * exists — the next action.
 */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  size = "default",
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 text-center",
        size === "sm" ? "px-4 py-8" : "px-6 py-14",
        className,
      )}
    >
      {Icon && (
        <span
          aria-hidden="true"
          className="flex size-11 items-center justify-center rounded-xl border bg-muted text-muted-foreground"
        >
          <Icon className="size-5" />
        </span>
      )}
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {description && (
          <p className="mx-auto max-w-sm text-sm leading-relaxed text-muted-foreground">
            {description}
          </p>
        )}
      </div>
      {action && <div className="pt-1">{action}</div>}
    </div>
  )
}

/**
 * Error state. Distinct from empty: something went wrong, and the user can
 * retry. Uses the danger tone plus an explicit word — never colour alone.
 */
export function ErrorState({
  title = "Could not load this",
  message,
  onRetry,
  size = "default",
  className,
}: {
  title?: string
  message?: string
  onRetry?: () => void
  size?: "sm" | "default"
  className?: string
}) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center gap-3 text-center",
        size === "sm" ? "px-4 py-8" : "px-6 py-12",
        className,
      )}
    >
      <span
        aria-hidden="true"
        className="flex size-11 items-center justify-center rounded-xl border border-danger-line bg-danger-soft text-danger-text"
      >
        <AlertCircle className="size-5" />
      </span>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {message && (
          <p className="mx-auto max-w-sm text-sm leading-relaxed text-muted-foreground">
            {message}
          </p>
        )}
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw aria-hidden="true" />
          Try again
        </Button>
      )}
    </div>
  )
}
