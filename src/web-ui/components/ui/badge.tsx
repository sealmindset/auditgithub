import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

/**
 * Badge.
 *
 * `soft` tones (tinted background, saturated text, hairline border) are the
 * default look across the app — they stay legible at 11px in both themes and
 * do not shout when twenty of them sit in one table column. `solid` tones are
 * reserved for the single item on a screen that must dominate.
 */
const badgeVariants = cva(
  [
    "inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden",
    "rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
    "[&>svg]:pointer-events-none [&>svg]:size-3",
    "transition-colors duration-150",
    "focus-visible:ring-ring/50 focus-visible:border-ring focus-visible:ring-[3px]",
    "aria-invalid:border-danger aria-invalid:ring-danger/20",
  ],
  {
    variants: {
      variant: {
        // shadcn-compatible names, retained so existing call sites keep working.
        default:
          "border-transparent bg-primary text-primary-foreground [a&]:hover:bg-primary/90",
        secondary:
          "border-transparent bg-secondary text-secondary-foreground [a&]:hover:bg-secondary/80",
        destructive:
          "border-transparent bg-danger text-danger-foreground [a&]:hover:bg-danger/90",
        outline:
          "border-border bg-transparent text-foreground [a&]:hover:bg-accent [a&]:hover:text-accent-foreground",

        // Soft tones — the house style.
        neutral: "border-border bg-muted text-muted-foreground",
        info: "border-info-line bg-info-soft text-info-text",
        success: "border-success-line bg-success-soft text-success-text",
        warning: "border-warning-line bg-warning-soft text-warning-text",
        danger: "border-danger-line bg-danger-soft text-danger-text",
        ai: "border-ai-line bg-ai-soft text-ai-text",

        // Solid tones.
        "info-solid": "border-transparent bg-info text-info-foreground",
        "success-solid":
          "border-transparent bg-success text-success-foreground",
        "warning-solid":
          "border-transparent bg-warning text-warning-foreground",
        "danger-solid": "border-transparent bg-danger text-danger-foreground",
        "ai-solid": "border-transparent bg-ai text-ai-foreground",
      },
      size: {
        sm: "h-5 px-1.5 text-[0.6875rem] [&>svg]:size-2.5",
        default: "h-[1.375rem] px-2 text-xs",
        lg: "h-6 gap-1.5 px-2.5 text-sm [&>svg]:size-3.5",
      },
      shape: {
        default: "rounded-md",
        pill: "rounded-full",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
      shape: "default",
    },
  },
)

function Badge({
  className,
  variant,
  size,
  shape,
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : "span"

  return (
    <Comp
      data-slot="badge"
      className={cn(badgeVariants({ variant, size, shape }), className)}
      {...props}
    />
  )
}

/** Tone names callers can store in a lookup table. */
export type BadgeTone = NonNullable<VariantProps<typeof badgeVariants>["variant"]>

export { Badge, badgeVariants }
