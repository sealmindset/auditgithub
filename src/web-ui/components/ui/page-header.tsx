"use client"

import * as React from "react"
import Link from "next/link"
import { ArrowLeft } from "lucide-react"

import { cn } from "@/lib/utils"

interface PageHeaderProps {
  title: string
  description?: React.ReactNode
  /** Small caps line above the title — usually the section the page sits in. */
  eyebrow?: string
  icon?: React.ComponentType<{ className?: string }>
  /** Buttons, filters, live indicators. Right-aligned, wraps under on mobile. */
  actions?: React.ReactNode
  /** Back affordance for detail routes — sits left of the icon. */
  back?: React.ReactNode
  /** Tabs or a filter bar pinned to the bottom of the header block. */
  children?: React.ReactNode
  className?: string
}

/**
 * Page header.
 *
 * Every route used its own heading markup, so titles ranged from text-xl to
 * text-3xl and actions landed in three different places. This is the one
 * shape: eyebrow, title, description on the left; actions on the right;
 * optional tab rail underneath.
 */
export function PageHeader({
  title,
  description,
  eyebrow,
  icon: Icon,
  actions,
  back,
  children,
  className,
}: PageHeaderProps) {
  return (
    <header className={cn("flex flex-col gap-4", className)}>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          {back}
          {Icon && (
            <span
              aria-hidden="true"
              className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg border border-primary-line bg-primary-soft text-primary-text"
            >
              <Icon className="size-[1.125rem]" />
            </span>
          )}
          <div className="min-w-0 space-y-1">
            {eyebrow && <p className="eyebrow">{eyebrow}</p>}
            <h1 className="truncate text-2xl font-semibold tracking-[-0.02em]">
              {title}
            </h1>
            {description && (
              <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">
                {description}
              </p>
            )}
          </div>
        </div>

        {actions && (
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {actions}
          </div>
        )}
      </div>

      {children}
    </header>
  )
}

/**
 * Back affordance for detail routes.
 *
 * An icon-only control needs a name; every hand-rolled back button in the app
 * was an unlabelled chevron, which reads as nothing at all to a screen reader.
 */
export function BackButton({
  onClick,
  href,
  label = "Back",
}: {
  onClick?: () => void
  href?: string
  label?: string
}) {
  const className =
    "mt-0.5 flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-lg border bg-card text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"

  if (href) {
    return (
      <Link href={href} className={className} aria-label={label}>
        <ArrowLeft className="size-4" />
      </Link>
    )
  }
  return (
    <button type="button" onClick={onClick} className={className} aria-label={label}>
      <ArrowLeft className="size-4" />
    </button>
  )
}

/** Standard page frame: consistent padding and vertical rhythm on every route. */
export function PageShell({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("flex flex-1 flex-col gap-6 p-4 sm:p-6", className)}
      {...props}
    />
  )
}

/** Live/refreshing indicator used beside page titles. */
export function LiveIndicator({
  label = "Live",
  className,
}: {
  label?: string
  className?: string
}) {
  return (
    <span
      className={cn(
        "inline-flex h-7 items-center gap-2 rounded-md border border-success-line bg-success-soft px-2.5 text-xs font-medium text-success-text",
        className,
      )}
    >
      <span className="status-dot text-success" aria-hidden="true">
        <span className="absolute inset-0 rounded-full bg-success" />
      </span>
      {label}
    </span>
  )
}
