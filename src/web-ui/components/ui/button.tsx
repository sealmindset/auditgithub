import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import { Loader2 } from "lucide-react"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  [
    "inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 whitespace-nowrap",
    "text-sm font-medium outline-none select-none",
    // Colour and shadow only — never size or position, so hover cannot reflow
    // a row of buttons.
    "transition-[color,background-color,border-color,box-shadow,opacity] duration-150 ease-out",
    "active:translate-y-px",
    "disabled:pointer-events-none disabled:opacity-50",
    "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
    "focus-visible:ring-ring/45 focus-visible:ring-[3px] focus-visible:ring-offset-0",
    "aria-invalid:border-danger aria-invalid:ring-danger/20",
  ],
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground shadow-xs hover:bg-primary/90",
        destructive:
          "bg-danger text-danger-foreground shadow-xs hover:bg-danger/90 focus-visible:ring-danger/40",
        success:
          "bg-success text-success-foreground shadow-xs hover:bg-success/90 focus-visible:ring-success/40",
        outline:
          "border border-border bg-card text-foreground shadow-xs hover:border-border-strong hover:bg-accent hover:text-accent-foreground",
        secondary:
          "bg-secondary text-secondary-foreground shadow-xs hover:bg-secondary/80",
        ghost:
          "text-foreground hover:bg-accent hover:text-accent-foreground",
        link: "text-primary-text underline-offset-4 hover:underline",

        /** Tinted, low-weight affirmative actions. */
        soft: "bg-primary-soft text-primary-text hover:bg-primary-soft/70",
        "soft-danger":
          "bg-danger-soft text-danger-text hover:bg-danger-soft/70 focus-visible:ring-danger/40",
        "soft-ai": "bg-ai-soft text-ai-text hover:bg-ai-soft/70",
      },
      size: {
        xs: "h-7 gap-1 rounded-md px-2 text-xs has-[>svg]:px-1.5 [&_svg:not([class*='size-'])]:size-3.5",
        sm: "h-8 gap-1.5 rounded-md px-3 has-[>svg]:px-2.5",
        default: "h-9 rounded-md px-4 py-2 has-[>svg]:px-3",
        lg: "h-10 rounded-lg px-6 text-sm has-[>svg]:px-4",
        // Icon sizes meet the 44px touch target via the ::after hit area below
        // on coarse pointers.
        icon: "size-9 rounded-md",
        "icon-sm": "size-8 rounded-md",
        "icon-xs": "size-7 rounded-md [&_svg:not([class*='size-'])]:size-3.5",
        "icon-lg": "size-10 rounded-lg",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
)

type ButtonProps = React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
    /** Shows a spinner and blocks input. Width is held so the row cannot jump. */
    loading?: boolean
  }

function Button({
  className,
  variant,
  size,
  asChild = false,
  loading = false,
  disabled,
  children,
  ...props
}: ButtonProps) {
  const Comp = asChild ? Slot : "button"

  // Slot forwards a single child; injecting a spinner would break that
  // contract, so `loading` only applies to real buttons.
  if (asChild) {
    return (
      <Comp
        data-slot="button"
        className={cn(buttonVariants({ variant, size, className }))}
        {...props}
      >
        {children}
      </Comp>
    )
  }

  return (
    <button
      data-slot="button"
      data-loading={loading || undefined}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    >
      {loading && <Loader2 className="animate-spin" aria-hidden="true" />}
      {children}
    </button>
  )
}

export { Button, buttonVariants }
