"use client"

import * as React from "react"

import { cn } from "@/lib/utils"

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number
  indeterminate?: boolean
}

function Progress({ className, value = 0, indeterminate, ...props }: ProgressProps) {
  return (
    <div
      className={cn(
        "bg-primary/20 relative h-2 w-full overflow-hidden rounded-full",
        className
      )}
      {...props}
    >
      {indeterminate ? (
        <div className="bg-primary h-full w-1/3 animate-[indeterminate_1.5s_ease-in-out_infinite] absolute" />
      ) : (
        <div
          className="bg-primary h-full transition-all duration-300 ease-in-out"
          style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
        />
      )}
    </div>
  )
}

export { Progress }

