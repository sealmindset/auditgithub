# LLM Prompt: Create Breadcrumb Navigation

## Task Overview

Create a **production-ready breadcrumb navigation component** for a Next.js 16+ application. The component should be positioned in the **header bar, to the right of the sidebar expand/collapse button** (upper left area). The implementation should follow the exact patterns, architecture, and conventions established in the AuditGitHub project.

---

## Tech Stack Requirements

| Technology | Version | Purpose |
|------------|---------|---------|
| **Next.js** | 16.0.6+ | React framework with App Router |
| **React** | 19.2.0+ | UI library |
| **TypeScript** | 5.x | Type safety |
| **Tailwind CSS** | v4 | Utility-first styling |
| **shadcn/ui** | Latest | Breadcrumb primitives (optional) |
| **lucide-react** | Latest | Icon library (Home, ChevronRight) |

---

## Required Dependencies

```bash
# Optional - shadcn breadcrumb primitives
npx shadcn-ui@latest add breadcrumb
```

---

## Feature Requirements

### Core Features
1. **Auto-generation** - Breadcrumbs generated from current URL path
2. **Home Icon** - Clickable home icon as first breadcrumb
3. **Separator** - Chevron right icons between items
4. **Clickable Links** - All items except last are clickable links
5. **Current Page** - Last item styled differently (not clickable)
6. **Segment Labels** - Human-readable labels for URL segments
7. **ID Handling** - UUIDs/IDs truncated or labeled appropriately

### Enhanced Features (Optional)
8. **Collapsible** - Collapse middle items when path is deep
9. **Dropdown** - Hidden items accessible via dropdown
10. **Dynamic Labels** - Fetch entity names for ID segments
11. **Structured Data** - JSON-LD for SEO
12. **Mobile Responsive** - Truncate or collapse on small screens

---

## Architecture Overview

### Component Structure

```
Header Bar
├── SidebarTrigger (expand/collapse button)
├── Breadcrumbs (to the right of sidebar trigger)
│   ├── Home Icon (link to /)
│   ├── Separator (ChevronRight)
│   ├── BreadcrumbItem (link)
│   ├── Separator
│   ├── BreadcrumbItem (link)
│   ├── Separator
│   └── BreadcrumbItem (current page - not a link)
├── Spacer (flex-1)
└── Right side items (search, theme toggle, etc.)
```

### URL to Breadcrumb Mapping

```
URL: /findings/abc123-def456/investigation

Breadcrumbs:
🏠 > Findings > abc123... > Investigation
     ↓           ↓           ↓
   (link)      (link)     (current)
```

---

## Core Implementation

### 1. `Breadcrumbs.tsx` - Main Component (Simple Version)

```tsx
"use client"

import * as React from "react"
import { usePathname } from "next/navigation"
import Link from "next/link"
import { ChevronRight, Home } from "lucide-react"
import { cn } from "@/lib/utils"

// ==========================================
// SEGMENT LABEL MAPPING
// ==========================================

/**
 * Map URL segments to human-readable labels.
 * Add entries for all known routes in your application.
 */
const SEGMENT_LABELS: Record<string, string> = {
  // Main navigation
  "": "Dashboard",
  "dashboard": "Dashboard",
  "findings": "Findings",
  "repositories": "Repositories",
  "projects": "Projects",
  "scheduler": "Scheduler",
  "attack-surface": "Attack Surface",
  "zero-day": "Zero Day Analysis",
  "reports": "Reports",

  // Settings & Admin
  "settings": "Settings",
  "admin": "Admin",
  "users": "Users",
  "api-audit": "API Audit",
  "integrations": "Integrations",

  // Sub-pages
  "scans": "Scans",
  "investigation": "Investigation",
  "history": "History",
  "details": "Details",
  "edit": "Edit",
  "new": "New",
}

// ==========================================
// TYPES
// ==========================================

interface BreadcrumbItem {
  label: string
  href: string
  isLast: boolean
  isId: boolean
}

// ==========================================
// URL PARSING
// ==========================================

/**
 * Check if a segment looks like an ID (UUID, numeric ID, etc.)
 */
function isIdSegment(segment: string): boolean {
  // UUID pattern (with or without hyphens)
  if (/^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(segment)) {
    return true
  }
  // Pure numeric ID
  if (/^\d+$/.test(segment)) {
    return true
  }
  // Short alphanumeric ID (e.g., "abc123")
  if (/^[a-z0-9]{6,}$/i.test(segment) && !/^[a-z]+$/i.test(segment)) {
    return true
  }
  return false
}

/**
 * Format a segment into a readable label
 */
function formatSegmentLabel(segment: string): string {
  // Check predefined labels first
  if (SEGMENT_LABELS[segment]) {
    return SEGMENT_LABELS[segment]
  }

  // If it's an ID, truncate it
  if (isIdSegment(segment)) {
    if (segment.length > 12) {
      return `${segment.substring(0, 8)}...`
    }
    return segment
  }

  // Convert kebab-case or snake_case to Title Case
  return segment
    .replace(/[-_]/g, " ")
    .split(" ")
    .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ")
}

/**
 * Parse pathname into breadcrumb items
 */
function parseBreadcrumbs(pathname: string): BreadcrumbItem[] {
  // Don't show breadcrumbs on home/dashboard
  if (pathname === "/" || pathname === "") {
    return []
  }

  const segments = pathname.split("/").filter(Boolean)
  const items: BreadcrumbItem[] = []

  let currentPath = ""

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]
    currentPath += `/${segment}`

    items.push({
      label: formatSegmentLabel(segment),
      href: currentPath,
      isLast: i === segments.length - 1,
      isId: isIdSegment(segment),
    })
  }

  return items
}

// ==========================================
// MAIN COMPONENT
// ==========================================

export function Breadcrumbs() {
  const pathname = usePathname()
  const items = parseBreadcrumbs(pathname)

  // Don't render anything on home page
  if (items.length === 0) {
    return null
  }

  return (
    <nav
      aria-label="Breadcrumb"
      className="flex items-center gap-1 text-sm"
    >
      {/* Home Icon */}
      <Link
        href="/"
        className={cn(
          "flex items-center justify-center",
          "text-muted-foreground hover:text-foreground",
          "transition-colors duration-200",
          "rounded-sm p-1 hover:bg-accent"
        )}
        title="Go to Dashboard"
      >
        <Home className="h-4 w-4" />
        <span className="sr-only">Dashboard</span>
      </Link>

      {/* Breadcrumb Items */}
      {items.map((item) => (
        <React.Fragment key={item.href}>
          {/* Separator */}
          <ChevronRight
            className="h-4 w-4 text-muted-foreground shrink-0"
            aria-hidden="true"
          />

          {/* Item */}
          {item.isLast ? (
            // Current page (not clickable)
            <span
              className={cn(
                "font-medium text-foreground",
                "max-w-[200px] truncate",
                item.isId && "font-mono text-xs"
              )}
              aria-current="page"
            >
              {item.label}
            </span>
          ) : (
            // Clickable link
            <Link
              href={item.href}
              className={cn(
                "text-muted-foreground hover:text-foreground",
                "transition-colors duration-200",
                "hover:underline underline-offset-4",
                "max-w-[150px] truncate",
                item.isId && "font-mono text-xs"
              )}
            >
              {item.label}
            </Link>
          )}
        </React.Fragment>
      ))}
    </nav>
  )
}
```

---

### 2. Layout Integration

```tsx
// app/layout.tsx
import { Breadcrumbs } from "@/components/Breadcrumbs"
import { SidebarTrigger } from "@/components/ui/sidebar"

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <SidebarProvider>
          <div className="flex min-h-screen w-full">
            {/* Sidebar */}
            <AppSidebar />

            {/* Main content */}
            <main className="flex-1 overflow-y-auto bg-background">
              {/* Header Bar */}
              <div className="flex h-14 items-center gap-4 border-b bg-muted/40 px-6">
                {/* Sidebar Toggle - Far Left */}
                <SidebarTrigger />

                {/* Breadcrumbs - Right of Toggle */}
                <Breadcrumbs />

                {/* Spacer */}
                <div className="flex-1" />

                {/* Right side items */}
                <QuickSearch />
                <ModeToggle />
              </div>

              {children}
            </main>
          </div>
        </SidebarProvider>
      </body>
    </html>
  )
}
```

---

### 3. Enhanced Version with Collapsible Items

```tsx
"use client"

import * as React from "react"
import { usePathname } from "next/navigation"
import Link from "next/link"
import { ChevronRight, Home, MoreHorizontal } from "lucide-react"
import { cn } from "@/lib/utils"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

// ... (SEGMENT_LABELS, types, and parsing functions from above) ...

interface CollapsibleBreadcrumbsProps {
  maxVisibleItems?: number  // Max items to show before collapsing
}

export function CollapsibleBreadcrumbs({
  maxVisibleItems = 3
}: CollapsibleBreadcrumbsProps) {
  const pathname = usePathname()
  const items = parseBreadcrumbs(pathname)

  if (items.length === 0) {
    return null
  }

  // Determine which items to show and which to collapse
  const shouldCollapse = items.length > maxVisibleItems
  const firstItem = items[0]
  const lastItems = items.slice(-2)  // Always show last 2 items
  const middleItems = items.slice(1, -2)  // Items to potentially collapse

  return (
    <nav
      aria-label="Breadcrumb"
      className="flex items-center gap-1 text-sm"
    >
      {/* Home Icon */}
      <Link
        href="/"
        className="flex items-center text-muted-foreground hover:text-foreground transition-colors p-1 rounded-sm hover:bg-accent"
      >
        <Home className="h-4 w-4" />
        <span className="sr-only">Dashboard</span>
      </Link>

      {/* First item (always visible) */}
      <ChevronRight className="h-4 w-4 text-muted-foreground" aria-hidden />
      <BreadcrumbLink item={firstItem} />

      {/* Collapsed middle items (if needed) */}
      {shouldCollapse && middleItems.length > 0 && (
        <>
          <ChevronRight className="h-4 w-4 text-muted-foreground" aria-hidden />
          <DropdownMenu>
            <DropdownMenuTrigger
              className={cn(
                "flex items-center justify-center",
                "h-6 w-6 rounded-sm",
                "text-muted-foreground hover:text-foreground",
                "hover:bg-accent transition-colors"
              )}
              aria-label={`Show ${middleItems.length} more items`}
            >
              <MoreHorizontal className="h-4 w-4" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              {middleItems.map((item) => (
                <DropdownMenuItem key={item.href} asChild>
                  <Link href={item.href}>
                    {item.label}
                  </Link>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </>
      )}

      {/* Non-collapsed middle items */}
      {!shouldCollapse && middleItems.map((item) => (
        <React.Fragment key={item.href}>
          <ChevronRight className="h-4 w-4 text-muted-foreground" aria-hidden />
          <BreadcrumbLink item={item} />
        </React.Fragment>
      ))}

      {/* Last items (always visible) */}
      {lastItems.map((item) => (
        <React.Fragment key={item.href}>
          <ChevronRight className="h-4 w-4 text-muted-foreground" aria-hidden />
          {item.isLast ? (
            <span
              className={cn(
                "font-medium text-foreground max-w-[200px] truncate",
                item.isId && "font-mono text-xs"
              )}
              aria-current="page"
            >
              {item.label}
            </span>
          ) : (
            <BreadcrumbLink item={item} />
          )}
        </React.Fragment>
      ))}
    </nav>
  )
}

// Helper component for breadcrumb links
function BreadcrumbLink({ item }: { item: BreadcrumbItem }) {
  return (
    <Link
      href={item.href}
      className={cn(
        "text-muted-foreground hover:text-foreground transition-colors",
        "hover:underline underline-offset-4",
        "max-w-[150px] truncate",
        item.isId && "font-mono text-xs"
      )}
    >
      {item.label}
    </Link>
  )
}
```

---

### 4. Using shadcn/ui Breadcrumb Primitives

```tsx
"use client"

import * as React from "react"
import { usePathname } from "next/navigation"
import Link from "next/link"
import { Home } from "lucide-react"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
  BreadcrumbEllipsis,
} from "@/components/ui/breadcrumb"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

// ... (SEGMENT_LABELS and parsing functions) ...

export function Breadcrumbs() {
  const pathname = usePathname()
  const items = parseBreadcrumbs(pathname)

  if (items.length === 0) {
    return null
  }

  const maxVisible = 3
  const shouldCollapse = items.length > maxVisible

  return (
    <Breadcrumb>
      <BreadcrumbList>
        {/* Home */}
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link href="/" className="flex items-center">
              <Home className="h-4 w-4" />
              <span className="sr-only">Home</span>
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>

        <BreadcrumbSeparator />

        {/* First item */}
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link href={items[0].href}>{items[0].label}</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>

        {/* Ellipsis for collapsed items */}
        {shouldCollapse && items.length > 3 && (
          <>
            <BreadcrumbSeparator />
            <BreadcrumbItem>
              <DropdownMenu>
                <DropdownMenuTrigger className="flex items-center gap-1">
                  <BreadcrumbEllipsis />
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start">
                  {items.slice(1, -2).map((item) => (
                    <DropdownMenuItem key={item.href} asChild>
                      <Link href={item.href}>{item.label}</Link>
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </BreadcrumbItem>
          </>
        )}

        {/* Remaining items */}
        {(shouldCollapse ? items.slice(-2) : items.slice(1)).map((item, index) => (
          <React.Fragment key={item.href}>
            <BreadcrumbSeparator />
            <BreadcrumbItem>
              {item.isLast ? (
                <BreadcrumbPage>{item.label}</BreadcrumbPage>
              ) : (
                <BreadcrumbLink asChild>
                  <Link href={item.href}>{item.label}</Link>
                </BreadcrumbLink>
              )}
            </BreadcrumbItem>
          </React.Fragment>
        ))}
      </BreadcrumbList>
    </Breadcrumb>
  )
}
```

---

### 5. Dynamic Labels with Data Fetching

```tsx
"use client"

import * as React from "react"
import { usePathname } from "next/navigation"
import useSWR from "swr"

// Fetcher for SWR
const fetcher = (url: string) => fetch(url).then(r => r.json())

// Hook to fetch entity name for an ID
function useEntityName(type: string | null, id: string | null): string | null {
  const { data } = useSWR(
    type && id ? `/api/${type}/${id}/name` : null,
    fetcher,
    { revalidateOnFocus: false }
  )
  return data?.name || null
}

// Enhanced parsing that tracks entity types
function parseBreadcrumbsWithTypes(pathname: string) {
  const segments = pathname.split("/").filter(Boolean)
  const items: Array<{
    segment: string
    href: string
    isLast: boolean
    entityType: string | null  // The preceding segment (e.g., "findings", "repositories")
    isId: boolean
  }> = []

  let currentPath = ""
  let lastEntityType: string | null = null

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]
    currentPath += `/${segment}`
    const isId = isIdSegment(segment)

    items.push({
      segment,
      href: currentPath,
      isLast: i === segments.length - 1,
      entityType: isId ? lastEntityType : null,
      isId,
    })

    // Track entity type for next potential ID
    if (!isId) {
      lastEntityType = segment
    }
  }

  return items
}

// Component with dynamic labels
export function DynamicBreadcrumbs() {
  const pathname = usePathname()
  const items = parseBreadcrumbsWithTypes(pathname)

  if (items.length === 0) return null

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-sm">
      <Link href="/" className="text-muted-foreground hover:text-foreground">
        <Home className="h-4 w-4" />
      </Link>

      {items.map((item) => (
        <React.Fragment key={item.href}>
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
          <DynamicBreadcrumbItem item={item} />
        </React.Fragment>
      ))}
    </nav>
  )
}

function DynamicBreadcrumbItem({ item }: { item: ReturnType<typeof parseBreadcrumbsWithTypes>[0] }) {
  // Fetch dynamic name for ID segments
  const dynamicName = useEntityName(
    item.isId ? item.entityType : null,
    item.isId ? item.segment : null
  )

  const label = item.isId
    ? (dynamicName || `${item.segment.substring(0, 8)}...`)
    : formatSegmentLabel(item.segment)

  if (item.isLast) {
    return (
      <span className="font-medium text-foreground" aria-current="page">
        {label}
      </span>
    )
  }

  return (
    <Link
      href={item.href}
      className="text-muted-foreground hover:text-foreground transition-colors"
    >
      {label}
    </Link>
  )
}
```

---

### 6. Mobile-Responsive Version

```tsx
"use client"

import * as React from "react"
import { usePathname } from "next/navigation"
import Link from "next/link"
import { ChevronRight, Home, ChevronLeft } from "lucide-react"
import { cn } from "@/lib/utils"

export function ResponsiveBreadcrumbs() {
  const pathname = usePathname()
  const items = parseBreadcrumbs(pathname)

  if (items.length === 0) return null

  // Get parent for mobile "back" navigation
  const parentItem = items.length > 1 ? items[items.length - 2] : null
  const currentItem = items[items.length - 1]

  return (
    <>
      {/* Desktop: Full breadcrumbs */}
      <nav
        aria-label="Breadcrumb"
        className="hidden sm:flex items-center gap-1 text-sm"
      >
        <Link href="/" className="text-muted-foreground hover:text-foreground p-1">
          <Home className="h-4 w-4" />
        </Link>
        {items.map((item) => (
          <React.Fragment key={item.href}>
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
            {item.isLast ? (
              <span className="font-medium text-foreground truncate max-w-[200px]">
                {item.label}
              </span>
            ) : (
              <Link
                href={item.href}
                className="text-muted-foreground hover:text-foreground truncate max-w-[120px]"
              >
                {item.label}
              </Link>
            )}
          </React.Fragment>
        ))}
      </nav>

      {/* Mobile: Back button + current page */}
      <nav
        aria-label="Breadcrumb"
        className="flex sm:hidden items-center gap-2 text-sm"
      >
        {parentItem ? (
          <Link
            href={parentItem.href}
            className={cn(
              "flex items-center gap-1",
              "text-muted-foreground hover:text-foreground",
              "transition-colors"
            )}
          >
            <ChevronLeft className="h-4 w-4" />
            <span className="truncate max-w-[100px]">{parentItem.label}</span>
          </Link>
        ) : (
          <Link
            href="/"
            className="flex items-center gap-1 text-muted-foreground hover:text-foreground"
          >
            <ChevronLeft className="h-4 w-4" />
            <span>Home</span>
          </Link>
        )}
        <span className="text-muted-foreground">/</span>
        <span className="font-medium text-foreground truncate max-w-[150px]">
          {currentItem.label}
        </span>
      </nav>
    </>
  )
}
```

---

## Complete File Structure

```
src/
├── app/
│   └── layout.tsx           # Layout with Breadcrumbs in header
├── components/
│   ├── ui/
│   │   ├── breadcrumb.tsx   # shadcn breadcrumb primitives (optional)
│   │   └── dropdown-menu.tsx # For collapsible version
│   └── Breadcrumbs.tsx      # Main component
└── lib/
    └── utils.ts             # cn() utility
```

---

## Styling Reference

### Color Tokens

```css
/* Text colors */
text-muted-foreground  /* Inactive/link items */
text-foreground        /* Current page item */

/* Hover states */
hover:text-foreground  /* Link hover */
hover:bg-accent        /* Background hover (optional) */

/* Transitions */
transition-colors duration-200
```

### Spacing

```css
/* Container */
gap-1                  /* Gap between items */

/* Items */
max-w-[150px]          /* Max width for links */
max-w-[200px]          /* Max width for current page */
truncate               /* Truncate long labels */

/* Icons */
h-4 w-4                /* Standard icon size */
shrink-0               /* Prevent separator shrinking */
```

---

## Accessibility Considerations

### ARIA Attributes

```tsx
// Navigation landmark
<nav aria-label="Breadcrumb">

// Current page indicator
<span aria-current="page">Current Page</span>

// Hidden separators
<ChevronRight aria-hidden="true" />

// Screen reader only home text
<span className="sr-only">Dashboard</span>
```

### Keyboard Navigation

- All links are focusable via Tab
- Enter activates focused link
- Dropdown (if used) accessible via arrow keys

### Screen Reader Behavior

1. Announces "Breadcrumb navigation"
2. Each link announced with its label
3. Current page announced with "current page"
4. Separators hidden from screen readers

---

## SEO Enhancement: Structured Data

```tsx
// Add JSON-LD structured data for SEO
function BreadcrumbStructuredData({ items }: { items: BreadcrumbItem[] }) {
  const structuredData = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    "itemListElement": [
      {
        "@type": "ListItem",
        "position": 1,
        "name": "Home",
        "item": "https://yourdomain.com/"
      },
      ...items.map((item, index) => ({
        "@type": "ListItem",
        "position": index + 2,
        "name": item.label,
        "item": `https://yourdomain.com${item.href}`
      }))
    ]
  }

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
    />
  )
}
```

---

## Testing Checklist

- [ ] Breadcrumbs appear on all pages except home
- [ ] Home icon links to dashboard (/)
- [ ] All intermediate items are clickable links
- [ ] Last item is styled differently and not clickable
- [ ] Long labels are truncated with ellipsis
- [ ] UUIDs/IDs are shortened appropriately
- [ ] Custom labels from SEGMENT_LABELS are displayed
- [ ] Unknown segments convert to Title Case
- [ ] Keyboard navigation works (Tab, Enter)
- [ ] Screen reader announces navigation landmark
- [ ] Collapsed items (if enabled) show in dropdown
- [ ] Mobile responsive behavior works
- [ ] No layout shift on navigation
- [ ] Works with dynamic routes (/findings/[id])

---

## Common URL Patterns

| URL Pattern | Breadcrumb Output |
|-------------|-------------------|
| `/` | (hidden) |
| `/findings` | 🏠 > Findings |
| `/findings/abc123` | 🏠 > Findings > abc123... |
| `/findings/abc123/investigation` | 🏠 > Findings > abc123... > Investigation |
| `/settings/integrations` | 🏠 > Settings > Integrations |
| `/admin/users/edit` | 🏠 > Admin > Users > Edit |
| `/repositories/my-repo-name` | 🏠 > Repositories > My Repo Name |

---

## Summary

This prompt provides everything needed to implement a professional breadcrumb navigation:

1. **Core Component** - Auto-generated from URL path
2. **Segment Labels** - Configurable mapping for human-readable names
3. **ID Handling** - Automatic detection and truncation of UUIDs
4. **Layout Integration** - Positioned right of sidebar toggle
5. **Enhanced Versions** - Collapsible, dynamic labels, mobile-responsive
6. **Accessibility** - Full ARIA support, keyboard navigation
7. **SEO** - JSON-LD structured data option

The component follows the exact patterns from the AuditGitHub project and integrates seamlessly with the header layout.
