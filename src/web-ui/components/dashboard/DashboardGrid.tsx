"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

interface DashboardGridProps {
  children: React.ReactNode
  className?: string
}

interface GridItemProps {
  span?: 1 | 2 | 3 | 4
  children: React.ReactNode
  className?: string
}

/**
 * DashboardGrid - Responsive grid layout for dashboard widgets
 *
 * Layout:
 * - Mobile (< 640px): 1 column
 * - Tablet (640px - 1024px): 2 columns
 * - Desktop (> 1024px): 4 columns
 *
 * Use GridItem wrapper to control column span.
 */
function DashboardGrid({ children, className }: DashboardGridProps) {
  return (
    <div
      className={cn(
        "grid gap-6",
        "grid-cols-1 sm:grid-cols-2 lg:grid-cols-4",
        className
      )}
    >
      {children}
    </div>
  )
}

/**
 * GridItem - Wrapper for controlling widget column span
 *
 * @param span - Number of columns to span (1-4), default 1
 */
function GridItem({ span = 1, children, className }: GridItemProps) {
  const spanClasses = {
    1: "",
    2: "sm:col-span-2",
    3: "sm:col-span-2 lg:col-span-3",
    4: "sm:col-span-2 lg:col-span-4",
  }

  return (
    <div className={cn(spanClasses[span], className)}>
      {children}
    </div>
  )
}

export { DashboardGrid, GridItem }
export type { DashboardGridProps, GridItemProps }
