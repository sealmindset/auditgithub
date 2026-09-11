"use client"

import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * Table.
 *
 * Tuned for long finding lists: a quiet sticky header, hairline row rules,
 * generous horizontal padding, and no zebra striping (striping fights with the
 * severity tints that live in these rows).
 */
function Table({
  className,
  containerClassName,
  ...props
}: React.ComponentProps<"table"> & { containerClassName?: string }) {
  return (
    <div
      data-slot="table-container"
      className={cn("relative w-full overflow-x-auto", containerClassName)}
    >
      <table
        data-slot="table"
        className={cn(
          "w-full caption-bottom border-separate border-spacing-0 text-sm",
          className,
        )}
        {...props}
      />
    </div>
  )
}

function TableHeader({ className, ...props }: React.ComponentProps<"thead">) {
  return (
    <thead
      data-slot="table-header"
      className={cn(
        "[&_th]:border-b [&_th]:border-border [&_th]:bg-muted/60",
        className,
      )}
      {...props}
    />
  )
}

/** Header that stays put while a long result set scrolls under it. */
function TableHeaderSticky({
  className,
  ...props
}: React.ComponentProps<"thead">) {
  return (
    <TableHeader
      className={cn(
        "[&_th]:sticky [&_th]:top-0 [&_th]:z-10 [&_th]:backdrop-blur-sm",
        className,
      )}
      {...props}
    />
  )
}

function TableBody({ className, ...props }: React.ComponentProps<"tbody">) {
  return (
    <tbody
      data-slot="table-body"
      className={cn("[&_tr:last-child_td]:border-0", className)}
      {...props}
    />
  )
}

function TableFooter({ className, ...props }: React.ComponentProps<"tfoot">) {
  return (
    <tfoot
      data-slot="table-footer"
      className={cn(
        "bg-muted/50 font-medium [&_td]:border-t [&_td]:border-border",
        className,
      )}
      {...props}
    />
  )
}

function TableRow({ className, ...props }: React.ComponentProps<"tr">) {
  return (
    <tr
      data-slot="table-row"
      className={cn(
        "transition-colors duration-150",
        "hover:bg-accent/40 data-[state=selected]:bg-primary-soft",
        className,
      )}
      {...props}
    />
  )
}

function TableHead({ className, ...props }: React.ComponentProps<"th">) {
  return (
    <th
      data-slot="table-head"
      className={cn(
        "h-9 px-3 text-left align-middle text-xs font-semibold tracking-[0.02em] whitespace-nowrap text-muted-foreground uppercase",
        "first:pl-4 last:pr-4",
        "[&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]",
        className,
      )}
      {...props}
    />
  )
}

function TableCell({ className, ...props }: React.ComponentProps<"td">) {
  return (
    <td
      data-slot="table-cell"
      className={cn(
        "border-b border-border/70 px-3 py-2.5 align-middle whitespace-nowrap",
        "first:pl-4 last:pr-4",
        "[&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]",
        className,
      )}
      {...props}
    />
  )
}

function TableCaption({ className, ...props }: React.ComponentProps<"caption">) {
  return (
    <caption
      data-slot="table-caption"
      className={cn("mt-4 text-sm text-muted-foreground", className)}
      {...props}
    />
  )
}

export {
  Table,
  TableHeader,
  TableHeaderSticky,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
}
