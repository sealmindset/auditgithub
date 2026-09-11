import { cn } from "@/lib/utils"

/**
 * Skeleton.
 *
 * A sweeping highlight rather than a pulsing block: it reads as "loading"
 * instead of "broken", and it reserves the exact space the real content will
 * take, so nothing jumps when data lands.
 */
function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      aria-hidden="true"
      className={cn(
        "relative overflow-hidden rounded-md bg-muted",
        "after:absolute after:inset-0 after:-translate-x-full after:animate-shimmer",
        "after:bg-gradient-to-r after:from-transparent after:via-foreground/[0.06] after:to-transparent after:content-['']",
        className,
      )}
      {...props}
    />
  )
}

export { Skeleton }
