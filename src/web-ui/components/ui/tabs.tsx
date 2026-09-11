"use client"

import * as React from "react"
import * as TabsPrimitive from "@radix-ui/react-tabs"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const TabsVariantContext = React.createContext<"segmented" | "underline">(
  "segmented",
)

function Tabs({
  className,
  variant = "segmented",
  ...props
}: React.ComponentProps<typeof TabsPrimitive.Root> & {
  variant?: "segmented" | "underline"
}) {
  return (
    <TabsVariantContext.Provider value={variant}>
      <TabsPrimitive.Root
        data-slot="tabs"
        data-variant={variant}
        className={cn("flex flex-col gap-4", className)}
        {...props}
      />
    </TabsVariantContext.Provider>
  )
}

const tabsListVariants = cva("inline-flex items-center", {
  variants: {
    variant: {
      /** Pill group. Best for 2-4 peer views. */
      segmented:
        "h-9 w-fit justify-center gap-1 rounded-lg bg-muted p-1 text-muted-foreground",
      /** Underlined rail. Best for many tabs, or tabs that page a whole view. */
      underline:
        "h-10 w-full justify-start gap-1 rounded-none border-b border-border bg-transparent p-0 text-muted-foreground",
    },
  },
  defaultVariants: { variant: "segmented" },
})

function TabsList({
  className,
  variant,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.List> &
  VariantProps<typeof tabsListVariants>) {
  const ctx = React.useContext(TabsVariantContext)
  return (
    <TabsPrimitive.List
      data-slot="tabs-list"
      className={cn(tabsListVariants({ variant: variant ?? ctx }), className)}
      {...props}
    />
  )
}

const tabsTriggerVariants = cva(
  [
    "inline-flex cursor-pointer items-center justify-center gap-1.5 whitespace-nowrap",
    "text-sm font-medium outline-none",
    "transition-[color,background-color,box-shadow] duration-150",
    "disabled:pointer-events-none disabled:opacity-50",
    "focus-visible:ring-ring/45 focus-visible:ring-[3px]",
    "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  ],
  {
    variants: {
      variant: {
        segmented: [
          "h-7 flex-1 rounded-md px-3 text-muted-foreground",
          "hover:text-foreground",
          "data-[state=active]:bg-card data-[state=active]:text-foreground data-[state=active]:shadow-xs",
        ],
        underline: [
          "relative h-10 rounded-none border-b-2 border-transparent px-3 pb-2.5 text-muted-foreground",
          "hover:border-border-strong hover:text-foreground",
          "data-[state=active]:border-primary data-[state=active]:text-foreground",
        ],
      },
    },
    defaultVariants: { variant: "segmented" },
  },
)

function TabsTrigger({
  className,
  variant,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.Trigger> &
  VariantProps<typeof tabsTriggerVariants>) {
  const ctx = React.useContext(TabsVariantContext)
  return (
    <TabsPrimitive.Trigger
      data-slot="tabs-trigger"
      className={cn(tabsTriggerVariants({ variant: variant ?? ctx }), className)}
      {...props}
    />
  )
}

function TabsContent({
  className,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return (
    <TabsPrimitive.Content
      data-slot="tabs-content"
      className={cn(
        "flex-1 outline-none data-[state=active]:animate-[rise_0.28s_var(--ease-out-quart)_both]",
        className,
      )}
      {...props}
    />
  )
}

export { Tabs, TabsList, TabsTrigger, TabsContent }
