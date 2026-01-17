"use client"

import * as React from "react"
import { Card, CardHeader, CardTitle, CardDescription, CardAction, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"
import { AlertCircle, RefreshCw } from "lucide-react"

interface WidgetProps {
  title: string
  subtitle?: string
  action?: React.ReactNode
  loading?: boolean
  error?: string | null
  onRetry?: () => void
  className?: string
  children: React.ReactNode
}

interface WidgetHeaderProps {
  title: string
  subtitle?: string
  action?: React.ReactNode
  className?: string
}

interface WidgetContentProps {
  className?: string
  children: React.ReactNode
}

interface WidgetSkeletonProps {
  className?: string
  lines?: number
}

interface WidgetErrorProps {
  message: string
  onRetry?: () => void
  className?: string
}

/**
 * Widget - Reusable dashboard widget wrapper with consistent styling
 *
 * Provides:
 * - Consistent card styling with header
 * - Loading state with skeleton
 * - Error state with retry button
 * - Composition-based API for flexibility
 */
function Widget({
  title,
  subtitle,
  action,
  loading = false,
  error = null,
  onRetry,
  className,
  children,
}: WidgetProps) {
  return (
    <Card className={cn("relative overflow-hidden", className)}>
      <WidgetHeader title={title} subtitle={subtitle} action={action} />
      <CardContent>
        {loading ? (
          <WidgetSkeleton />
        ) : error ? (
          <WidgetError message={error} onRetry={onRetry} />
        ) : (
          children
        )}
      </CardContent>
    </Card>
  )
}

/**
 * WidgetHeader - Header section with title, optional subtitle, and action slot
 */
function WidgetHeader({ title, subtitle, action, className }: WidgetHeaderProps) {
  return (
    <CardHeader className={cn("pb-2", className)}>
      <div>
        <CardTitle className="text-base font-semibold">{title}</CardTitle>
        {subtitle && (
          <CardDescription className="mt-1">{subtitle}</CardDescription>
        )}
      </div>
      {action && <CardAction>{action}</CardAction>}
    </CardHeader>
  )
}

/**
 * WidgetContent - Content area wrapper (for standalone use)
 */
function WidgetContent({ className, children }: WidgetContentProps) {
  return (
    <div className={cn("", className)}>
      {children}
    </div>
  )
}

/**
 * WidgetSkeleton - Loading state placeholder with animated skeleton lines
 */
function WidgetSkeleton({ className, lines = 3 }: WidgetSkeletonProps) {
  return (
    <div className={cn("space-y-3", className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton
          key={i}
          className={cn(
            "h-4",
            i === lines - 1 ? "w-2/3" : "w-full"
          )}
        />
      ))}
    </div>
  )
}

/**
 * WidgetError - Error state with message and optional retry button
 */
function WidgetError({ message, onRetry, className }: WidgetErrorProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center py-8 text-center",
        className
      )}
    >
      <div className="rounded-full bg-destructive/10 p-3 mb-3">
        <AlertCircle className="h-6 w-6 text-destructive" />
      </div>
      <p className="text-sm text-muted-foreground mb-3">{message}</p>
      {onRetry && (
        <Button
          variant="outline"
          size="sm"
          onClick={onRetry}
          className="gap-2"
        >
          <RefreshCw className="h-4 w-4" />
          Retry
        </Button>
      )}
    </div>
  )
}

export {
  Widget,
  WidgetHeader,
  WidgetContent,
  WidgetSkeleton,
  WidgetError,
}
export type {
  WidgetProps,
  WidgetHeaderProps,
  WidgetContentProps,
  WidgetSkeletonProps,
  WidgetErrorProps,
}
