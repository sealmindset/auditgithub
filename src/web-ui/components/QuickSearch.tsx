"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import {
  Search,
  LayoutDashboard,
  AlertTriangle,
  GitBranch,
  Calendar,
  Target,
  ShieldCheck,
  ClipboardList,
  Settings,
  FileText,
  Command,
} from "lucide-react"
import { cn } from "@/lib/utils"

interface SearchItem {
  title: string
  description: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  keywords?: string[]
}

const SEARCH_ITEMS: SearchItem[] = [
  {
    title: "Dashboard",
    description: "Security overview and metrics",
    href: "/",
    icon: LayoutDashboard,
    keywords: ["home", "overview", "main"]
  },
  {
    title: "Findings",
    description: "View all security findings",
    href: "/findings",
    icon: AlertTriangle,
    keywords: ["vulnerabilities", "issues", "alerts"]
  },
  {
    title: "Repositories",
    description: "Manage tracked repositories",
    href: "/repositories",
    icon: GitBranch,
    keywords: ["repos", "projects", "github"]
  },
  {
    title: "Scheduler",
    description: "Scan scheduling and calendar",
    href: "/scheduler",
    icon: Calendar,
    keywords: ["scans", "schedule", "automation"]
  },
  {
    title: "Attack Surface",
    description: "Attack surface analysis",
    href: "/attack-surface",
    icon: Target,
    keywords: ["security", "exposure", "risk"]
  },
  {
    title: "Zero Day Analysis",
    description: "Zero day vulnerability analysis",
    href: "/zero-day",
    icon: ShieldCheck,
    keywords: ["zda", "analysis", "vulnerabilities"]
  },
  {
    title: "ZDA Reports",
    description: "Zero day analysis reports",
    href: "/zero-day/reports",
    icon: ClipboardList,
    keywords: ["reports", "documentation"]
  },
  {
    title: "Settings",
    description: "Platform configuration",
    href: "/settings",
    icon: Settings,
    keywords: ["config", "preferences", "options"]
  },
  {
    title: "API Audit Settings",
    description: "API audit configuration",
    href: "/api-audit/settings",
    icon: FileText,
    keywords: ["api", "audit"]
  },
]

export function QuickSearch() {
  const [open, setOpen] = React.useState(false)
  const [query, setQuery] = React.useState("")
  const [selectedIndex, setSelectedIndex] = React.useState(0)
  const router = useRouter()
  const inputRef = React.useRef<HTMLInputElement>(null)

  // Filter items based on query
  const filteredItems = React.useMemo(() => {
    if (!query) return SEARCH_ITEMS
    const lowerQuery = query.toLowerCase()
    return SEARCH_ITEMS.filter(item => {
      const matchesTitle = item.title.toLowerCase().includes(lowerQuery)
      const matchesDescription = item.description.toLowerCase().includes(lowerQuery)
      const matchesKeywords = item.keywords?.some(k => k.toLowerCase().includes(lowerQuery))
      return matchesTitle || matchesDescription || matchesKeywords
    })
  }, [query])

  // Reset selection when filtered items change
  React.useEffect(() => {
    setSelectedIndex(0)
  }, [filteredItems])

  // Keyboard shortcut to open
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        setOpen(true)
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [])

  // Focus input when dialog opens
  React.useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 0)
    } else {
      setQuery("")
      setSelectedIndex(0)
    }
  }, [open])

  const handleSelect = (item: SearchItem) => {
    setOpen(false)
    router.push(item.href)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault()
      setSelectedIndex(prev => Math.min(prev + 1, filteredItems.length - 1))
    } else if (e.key === "ArrowUp") {
      e.preventDefault()
      setSelectedIndex(prev => Math.max(prev - 1, 0))
    } else if (e.key === "Enter" && filteredItems[selectedIndex]) {
      e.preventDefault()
      handleSelect(filteredItems[selectedIndex])
    }
  }

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="gap-2 text-muted-foreground"
        onClick={() => setOpen(true)}
      >
        <Search className="h-4 w-4" />
        <span className="hidden sm:inline">Search...</span>
        <kbd className="hidden sm:inline-flex h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium">
          <Command className="h-3 w-3" />K
        </kbd>
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-[500px] p-0">
          <DialogHeader className="sr-only">
            <DialogTitle>Quick Search</DialogTitle>
          </DialogHeader>
          <div className="flex items-center border-b px-3">
            <Search className="h-4 w-4 text-muted-foreground mr-2" />
            <Input
              ref={inputRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search navigation..."
              className="border-0 focus-visible:ring-0 focus-visible:ring-offset-0"
            />
          </div>
          <div className="max-h-[300px] overflow-y-auto p-2">
            {filteredItems.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">
                No results found
              </div>
            ) : (
              <div className="space-y-1">
                {filteredItems.map((item, index) => (
                  <button
                    key={item.href}
                    onClick={() => handleSelect(item)}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-md px-3 py-2 text-left",
                      "hover:bg-accent transition-colors",
                      index === selectedIndex && "bg-accent"
                    )}
                  >
                    <item.icon className="h-4 w-4 text-muted-foreground" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">{item.title}</p>
                      <p className="text-xs text-muted-foreground truncate">
                        {item.description}
                      </p>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="border-t px-3 py-2 text-xs text-muted-foreground flex items-center gap-4">
            <span className="flex items-center gap-1">
              <kbd className="px-1 rounded border bg-muted">↑↓</kbd> Navigate
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 rounded border bg-muted">↵</kbd> Select
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 rounded border bg-muted">Esc</kbd> Close
            </span>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
