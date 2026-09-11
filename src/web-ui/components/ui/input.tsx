import * as React from "react"

import { cn } from "@/lib/utils"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "h-9 w-full min-w-0 rounded-md border border-input bg-card px-3 py-1 shadow-xs outline-none",
        // 16px on small screens stops iOS zooming the viewport on focus.
        "text-base md:text-sm",
        "placeholder:text-muted-foreground/80",
        "selection:bg-primary selection:text-primary-foreground",
        "transition-[color,box-shadow,border-color] duration-150",
        "hover:border-border-strong",
        "focus-visible:border-ring focus-visible:ring-ring/45 focus-visible:ring-[3px]",
        "disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-muted disabled:opacity-60",
        "file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground",
        "aria-invalid:border-danger aria-invalid:ring-danger/25",
        className,
      )}
      {...props}
    />
  )
}

export { Input }
