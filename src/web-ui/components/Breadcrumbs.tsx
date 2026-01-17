"use client"

import { usePathname } from "next/navigation"
import Link from "next/link"
import { ChevronRight, Home } from "lucide-react"
import { cn } from "@/lib/utils"

// Map URL segments to readable names
const SEGMENT_LABELS: Record<string, string> = {
  "": "Dashboard",
  "findings": "Findings",
  "repositories": "Repositories",
  "scheduler": "Scheduler",
  "attack-surface": "Attack Surface",
  "zero-day": "Zero Day Analysis",
  "reports": "Reports",
  "settings": "Settings",
  "api-audit": "API Audit",
  "projects": "Projects",
  "scans": "Scans",
}

interface BreadcrumbItem {
  label: string
  href: string
  isLast: boolean
}

function parseBreadcrumbs(pathname: string): BreadcrumbItem[] {
  // Don't show breadcrumbs on dashboard
  if (pathname === "/") {
    return []
  }

  const segments = pathname.split("/").filter(Boolean)
  const items: BreadcrumbItem[] = []

  let currentPath = ""
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]
    currentPath += `/${segment}`

    // Check if this looks like an ID (UUID or similar)
    const isId = /^[0-9a-f-]{8,}$/i.test(segment) || /^\d+$/.test(segment)

    // Get label - use mapped name or format the segment
    let label = SEGMENT_LABELS[segment]
    if (!label) {
      if (isId) {
        // For IDs, use a shortened version or "Details"
        label = segment.length > 8 ? `${segment.substring(0, 8)}...` : segment
      } else {
        // Convert kebab-case to Title Case
        label = segment
          .split("-")
          .map(word => word.charAt(0).toUpperCase() + word.slice(1))
          .join(" ")
      }
    }

    items.push({
      label,
      href: currentPath,
      isLast: i === segments.length - 1
    })
  }

  return items
}

export function Breadcrumbs() {
  const pathname = usePathname()
  const items = parseBreadcrumbs(pathname)

  // Don't render anything on dashboard
  if (items.length === 0) {
    return null
  }

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-sm">
      <Link
        href="/"
        className={cn(
          "flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
        )}
      >
        <Home className="h-4 w-4" />
        <span className="sr-only">Dashboard</span>
      </Link>

      {items.map((item, index) => (
        <div key={item.href} className="flex items-center gap-1">
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
          {item.isLast ? (
            <span className="font-medium text-foreground">
              {item.label}
            </span>
          ) : (
            <Link
              href={item.href}
              className="text-muted-foreground hover:text-foreground transition-colors"
            >
              {item.label}
            </Link>
          )}
        </div>
      ))}
    </nav>
  )
}
