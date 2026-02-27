# LLM Prompt: Create Navigation Search (Command Palette)

## Task Overview

Create a **production-ready navigation search component** (also known as a "Command Palette" or "Quick Search") for a Next.js 16+ application. The component should be positioned in the **upper right corner** of the browser header and activated via **⌘K (Mac) / Ctrl+K (Windows)** keyboard shortcut. The implementation should follow the exact patterns, architecture, and conventions established in the AuditGitHub project.

---

## Tech Stack Requirements

| Technology | Version | Purpose |
|------------|---------|---------|
| **Next.js** | 16.0.6+ | React framework with App Router |
| **React** | 19.2.0+ | UI library |
| **TypeScript** | 5.x | Type safety |
| **Tailwind CSS** | v4 | Utility-first styling |
| **shadcn/ui** | Latest | Dialog, Input, Button components |
| **Radix UI** | Latest | Accessible dialog primitives |
| **lucide-react** | Latest | Icon library |

---

## Required shadcn/ui Components

```bash
npx shadcn-ui@latest add dialog input button
```

---

## Feature Requirements

### Core Features
1. **Trigger Button** - Visible in header with search icon and ⌘K hint
2. **Keyboard Shortcut** - Opens on ⌘K (Mac) / Ctrl+K (Windows)
3. **Modal Dialog** - Centered overlay with search input
4. **Fuzzy Search** - Matches title, description, and keywords
5. **Keyboard Navigation** - Arrow keys to navigate, Enter to select, Escape to close
6. **Visual Selection** - Highlighted current selection
7. **Instant Navigation** - Routes to selected page on selection

### Enhanced Features (Optional)
8. **Recent Searches** - Track and display recently visited pages
9. **Grouped Results** - Organize by category (Pages, Settings, Actions)
10. **Dynamic Search** - Search API data (repositories, findings, etc.)
11. **Actions Support** - Execute actions (create, scan, export)
12. **Fuzzy Matching** - Typo-tolerant search with scoring

---

## Architecture Overview

### Component Structure

```
QuickSearch (main component)
├── Trigger Button
│   ├── Search Icon
│   ├── "Search..." text
│   └── Keyboard Shortcut Badge (⌘K)
└── Dialog Modal
    ├── Search Input (with icon)
    ├── Results List
    │   └── SearchResultItem (per result)
    │       ├── Icon
    │       ├── Title
    │       └── Description
    └── Footer (keyboard hints)
```

---

## Core Implementation

### 1. `QuickSearch.tsx` - Main Component

```tsx
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
  Users,
  Scan,
  Plus,
  Download,
} from "lucide-react"
import { cn } from "@/lib/utils"

// ==========================================
// TYPES
// ==========================================

interface SearchItem {
  id: string
  title: string
  description: string
  href?: string                                    // For navigation items
  action?: () => void                              // For action items
  icon: React.ComponentType<{ className?: string }>
  keywords?: string[]                              // Additional search terms
  category?: "navigation" | "settings" | "actions" // For grouping
}

// ==========================================
// SEARCH DATA - Customize for your app
// ==========================================

const NAVIGATION_ITEMS: SearchItem[] = [
  {
    id: "dashboard",
    title: "Dashboard",
    description: "Security overview and metrics",
    href: "/",
    icon: LayoutDashboard,
    keywords: ["home", "overview", "main", "metrics"],
    category: "navigation",
  },
  {
    id: "findings",
    title: "Findings",
    description: "View all security findings",
    href: "/findings",
    icon: AlertTriangle,
    keywords: ["vulnerabilities", "issues", "alerts", "security"],
    category: "navigation",
  },
  {
    id: "repositories",
    title: "Repositories",
    description: "Manage tracked repositories",
    href: "/repositories",
    icon: GitBranch,
    keywords: ["repos", "projects", "github", "code"],
    category: "navigation",
  },
  {
    id: "scheduler",
    title: "Scheduler",
    description: "Scan scheduling and calendar",
    href: "/scheduler",
    icon: Calendar,
    keywords: ["scans", "schedule", "automation", "cron"],
    category: "navigation",
  },
  {
    id: "attack-surface",
    title: "Attack Surface",
    description: "Attack surface analysis",
    href: "/attack-surface",
    icon: Target,
    keywords: ["security", "exposure", "risk", "assets"],
    category: "navigation",
  },
  {
    id: "zero-day",
    title: "Zero Day Analysis",
    description: "Zero day vulnerability analysis",
    href: "/zero-day",
    icon: ShieldCheck,
    keywords: ["zda", "analysis", "vulnerabilities", "threats"],
    category: "navigation",
  },
  {
    id: "zda-reports",
    title: "ZDA Reports",
    description: "Zero day analysis reports",
    href: "/zero-day/reports",
    icon: ClipboardList,
    keywords: ["reports", "documentation", "pdf"],
    category: "navigation",
  },
  {
    id: "users",
    title: "Users",
    description: "User management",
    href: "/admin/users",
    icon: Users,
    keywords: ["team", "members", "accounts", "permissions"],
    category: "navigation",
  },
]

const SETTINGS_ITEMS: SearchItem[] = [
  {
    id: "settings",
    title: "Settings",
    description: "Platform configuration",
    href: "/settings",
    icon: Settings,
    keywords: ["config", "preferences", "options"],
    category: "settings",
  },
  {
    id: "api-settings",
    title: "API Audit Settings",
    description: "API audit configuration",
    href: "/api-audit/settings",
    icon: FileText,
    keywords: ["api", "audit", "config"],
    category: "settings",
  },
]

// Action items (no href, have action callback)
const ACTION_ITEMS: SearchItem[] = [
  {
    id: "new-scan",
    title: "Start New Scan",
    description: "Scan a repository for vulnerabilities",
    icon: Scan,
    keywords: ["scan", "analyze", "check"],
    category: "actions",
    action: () => {
      // This would be replaced with actual action
      console.log("Start new scan")
    },
  },
  {
    id: "add-repo",
    title: "Add Repository",
    description: "Track a new repository",
    icon: Plus,
    keywords: ["add", "new", "create", "repository"],
    category: "actions",
    action: () => {
      console.log("Add repository")
    },
  },
  {
    id: "export-report",
    title: "Export Report",
    description: "Download findings as PDF/CSV",
    icon: Download,
    keywords: ["export", "download", "report", "pdf", "csv"],
    category: "actions",
    action: () => {
      console.log("Export report")
    },
  },
]

// Combine all search items
const ALL_SEARCH_ITEMS: SearchItem[] = [
  ...NAVIGATION_ITEMS,
  ...SETTINGS_ITEMS,
  ...ACTION_ITEMS,
]

// ==========================================
// SEARCH UTILITIES
// ==========================================

function searchItems(query: string, items: SearchItem[]): SearchItem[] {
  if (!query.trim()) return items

  const lowerQuery = query.toLowerCase().trim()
  const queryTerms = lowerQuery.split(/\s+/)

  return items
    .map(item => {
      // Calculate match score
      let score = 0

      const titleLower = item.title.toLowerCase()
      const descLower = item.description.toLowerCase()
      const keywordsLower = item.keywords?.map(k => k.toLowerCase()) || []

      // Exact title match (highest priority)
      if (titleLower === lowerQuery) score += 100

      // Title starts with query
      if (titleLower.startsWith(lowerQuery)) score += 50

      // Title contains query
      if (titleLower.includes(lowerQuery)) score += 30

      // All query terms match
      const allTermsMatch = queryTerms.every(term =>
        titleLower.includes(term) ||
        descLower.includes(term) ||
        keywordsLower.some(k => k.includes(term))
      )
      if (allTermsMatch) score += 20

      // Description contains query
      if (descLower.includes(lowerQuery)) score += 10

      // Keywords match
      const keywordMatch = keywordsLower.some(k => k.includes(lowerQuery))
      if (keywordMatch) score += 15

      // Individual term matches
      queryTerms.forEach(term => {
        if (titleLower.includes(term)) score += 5
        if (descLower.includes(term)) score += 2
        if (keywordsLower.some(k => k.includes(term))) score += 3
      })

      return { item, score }
    })
    .filter(({ score }) => score > 0)
    .sort((a, b) => b.score - a.score)
    .map(({ item }) => item)
}

// ==========================================
// MAIN COMPONENT
// ==========================================

export function QuickSearch() {
  const [open, setOpen] = React.useState(false)
  const [query, setQuery] = React.useState("")
  const [selectedIndex, setSelectedIndex] = React.useState(0)
  const router = useRouter()
  const inputRef = React.useRef<HTMLInputElement>(null)
  const listRef = React.useRef<HTMLDivElement>(null)

  // Filter items based on query
  const filteredItems = React.useMemo(() => {
    return searchItems(query, ALL_SEARCH_ITEMS)
  }, [query])

  // Reset selection when filtered items change
  React.useEffect(() => {
    setSelectedIndex(0)
  }, [filteredItems])

  // Scroll selected item into view
  React.useEffect(() => {
    if (listRef.current && filteredItems.length > 0) {
      const selectedElement = listRef.current.children[selectedIndex] as HTMLElement
      if (selectedElement) {
        selectedElement.scrollIntoView({ block: "nearest" })
      }
    }
  }, [selectedIndex, filteredItems])

  // ==========================================
  // KEYBOARD SHORTCUT TO OPEN (⌘K / Ctrl+K)
  // ==========================================
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Open on ⌘K (Mac) or Ctrl+K (Windows/Linux)
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        setOpen(prev => !prev) // Toggle open/closed
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [])

  // Focus input when dialog opens, reset state when closes
  React.useEffect(() => {
    if (open) {
      // Small delay ensures dialog is mounted before focusing
      setTimeout(() => inputRef.current?.focus(), 0)
    } else {
      // Reset state when closing
      setQuery("")
      setSelectedIndex(0)
    }
  }, [open])

  // ==========================================
  // SELECTION HANDLER
  // ==========================================
  const handleSelect = React.useCallback((item: SearchItem) => {
    setOpen(false)

    if (item.href) {
      // Navigation item - route to page
      router.push(item.href)
    } else if (item.action) {
      // Action item - execute callback
      item.action()
    }
  }, [router])

  // ==========================================
  // KEYBOARD NAVIGATION
  // ==========================================
  const handleKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault()
        setSelectedIndex(prev =>
          prev < filteredItems.length - 1 ? prev + 1 : prev
        )
        break

      case "ArrowUp":
        e.preventDefault()
        setSelectedIndex(prev => (prev > 0 ? prev - 1 : prev))
        break

      case "Enter":
        e.preventDefault()
        if (filteredItems[selectedIndex]) {
          handleSelect(filteredItems[selectedIndex])
        }
        break

      case "Home":
        e.preventDefault()
        setSelectedIndex(0)
        break

      case "End":
        e.preventDefault()
        setSelectedIndex(filteredItems.length - 1)
        break

      case "Tab":
        // Prevent tab from moving focus out of search
        e.preventDefault()
        if (e.shiftKey) {
          setSelectedIndex(prev => (prev > 0 ? prev - 1 : filteredItems.length - 1))
        } else {
          setSelectedIndex(prev => (prev < filteredItems.length - 1 ? prev + 1 : 0))
        }
        break
    }
  }

  // ==========================================
  // RENDER
  // ==========================================
  return (
    <>
      {/* Trigger Button */}
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

      {/* Search Dialog */}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent
          className="sm:max-w-[500px] p-0 gap-0"
          showCloseButton={false}
        >
          {/* Accessible title (visually hidden) */}
          <DialogHeader className="sr-only">
            <DialogTitle>Quick Search</DialogTitle>
          </DialogHeader>

          {/* Search Input */}
          <div className="flex items-center border-b px-3">
            <Search className="h-4 w-4 text-muted-foreground mr-2 shrink-0" />
            <Input
              ref={inputRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search pages, settings, actions..."
              className="border-0 focus-visible:ring-0 focus-visible:ring-offset-0 h-12"
            />
            {query && (
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 p-0 shrink-0"
                onClick={() => setQuery("")}
              >
                <span className="sr-only">Clear</span>
                ×
              </Button>
            )}
          </div>

          {/* Results List */}
          <div
            ref={listRef}
            className="max-h-[300px] overflow-y-auto p-2"
            role="listbox"
            aria-label="Search results"
          >
            {filteredItems.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">
                No results found for "{query}"
              </div>
            ) : (
              <div className="space-y-1">
                {filteredItems.map((item, index) => (
                  <SearchResultItem
                    key={item.id}
                    item={item}
                    isSelected={index === selectedIndex}
                    onSelect={() => handleSelect(item)}
                    onMouseEnter={() => setSelectedIndex(index)}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Footer with keyboard hints */}
          <div className="border-t px-3 py-2 text-xs text-muted-foreground flex items-center gap-4">
            <span className="flex items-center gap-1">
              <kbd className="px-1.5 py-0.5 rounded border bg-muted font-mono">↑↓</kbd>
              Navigate
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1.5 py-0.5 rounded border bg-muted font-mono">↵</kbd>
              Select
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1.5 py-0.5 rounded border bg-muted font-mono">Esc</kbd>
              Close
            </span>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}

// ==========================================
// SEARCH RESULT ITEM COMPONENT
// ==========================================

interface SearchResultItemProps {
  item: SearchItem
  isSelected: boolean
  onSelect: () => void
  onMouseEnter: () => void
}

function SearchResultItem({
  item,
  isSelected,
  onSelect,
  onMouseEnter,
}: SearchResultItemProps) {
  const Icon = item.icon

  return (
    <button
      onClick={onSelect}
      onMouseEnter={onMouseEnter}
      role="option"
      aria-selected={isSelected}
      className={cn(
        "flex w-full items-center gap-3 rounded-md px-3 py-2 text-left",
        "transition-colors duration-100",
        "hover:bg-accent",
        isSelected && "bg-accent"
      )}
    >
      <div className={cn(
        "flex h-8 w-8 items-center justify-center rounded-md",
        item.category === "actions"
          ? "bg-primary/10 text-primary"
          : "bg-muted text-muted-foreground"
      )}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">{item.title}</p>
        <p className="text-xs text-muted-foreground truncate">
          {item.description}
        </p>
      </div>
      {item.category === "actions" && (
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
          Action
        </span>
      )}
    </button>
  )
}
```

---

### 2. Layout Integration

```tsx
// app/layout.tsx
import { QuickSearch } from "@/components/QuickSearch"

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="flex min-h-screen w-full">
          {/* Sidebar */}
          <aside>{/* ... */}</aside>

          {/* Main content */}
          <main className="flex-1 overflow-y-auto bg-background">
            {/* Header with QuickSearch in upper right */}
            <div className="flex h-14 items-center gap-4 border-b bg-muted/40 px-6">
              {/* Left side content */}
              <div className="flex-1" /> {/* Spacer */}

              {/* Quick Search - Upper Right */}
              <QuickSearch />

              {/* Other header items (theme toggle, etc.) */}
            </div>

            {children}
          </main>
        </div>
      </body>
    </html>
  )
}
```

---

## Enhanced Version: Grouped Results

### With Category Headers

```tsx
// Group items by category
const groupedItems = React.useMemo(() => {
  const groups: Record<string, SearchItem[]> = {
    navigation: [],
    settings: [],
    actions: [],
  }

  filteredItems.forEach(item => {
    const category = item.category || "navigation"
    groups[category].push(item)
  })

  return groups
}, [filteredItems])

// Render with group headers
<div className="space-y-4">
  {Object.entries(groupedItems).map(([category, items]) => {
    if (items.length === 0) return null

    return (
      <div key={category}>
        <div className="px-3 py-1 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          {category}
        </div>
        <div className="space-y-1">
          {items.map((item, index) => (
            <SearchResultItem
              key={item.id}
              item={item}
              isSelected={/* calculate global index */}
              onSelect={() => handleSelect(item)}
              onMouseEnter={() => /* set global index */}
            />
          ))}
        </div>
      </div>
    )
  })}
</div>
```

---

## Enhanced Version: Recent Searches

```tsx
const RECENT_KEY = "quick-search-recent"
const MAX_RECENT = 5

function useRecentSearches() {
  const [recent, setRecent] = React.useState<string[]>([])

  // Load from localStorage on mount
  React.useEffect(() => {
    try {
      const stored = localStorage.getItem(RECENT_KEY)
      if (stored) setRecent(JSON.parse(stored))
    } catch {}
  }, [])

  const addRecent = React.useCallback((id: string) => {
    setRecent(prev => {
      const filtered = prev.filter(r => r !== id)
      const updated = [id, ...filtered].slice(0, MAX_RECENT)
      try {
        localStorage.setItem(RECENT_KEY, JSON.stringify(updated))
      } catch {}
      return updated
    })
  }, [])

  const clearRecent = React.useCallback(() => {
    setRecent([])
    try {
      localStorage.removeItem(RECENT_KEY)
    } catch {}
  }, [])

  return { recent, addRecent, clearRecent }
}

// Usage in component
const { recent, addRecent } = useRecentSearches()

const handleSelect = (item: SearchItem) => {
  addRecent(item.id)
  // ... rest of selection logic
}

// Show recent when no query
{!query && recent.length > 0 && (
  <div className="px-3 py-2">
    <div className="text-xs font-semibold text-muted-foreground mb-2">
      Recent
    </div>
    {recent.map(id => {
      const item = ALL_SEARCH_ITEMS.find(i => i.id === id)
      if (!item) return null
      return <SearchResultItem key={id} item={item} /* ... */ />
    })}
  </div>
)}
```

---

## Enhanced Version: Dynamic API Search

```tsx
// Add dynamic search for repositories, findings, etc.

interface DynamicSearchResult {
  id: string
  title: string
  description: string
  href: string
  type: "repository" | "finding" | "user"
}

function useDynamicSearch(query: string) {
  const [results, setResults] = React.useState<DynamicSearchResult[]>([])
  const [loading, setLoading] = React.useState(false)

  React.useEffect(() => {
    if (!query || query.length < 2) {
      setResults([])
      return
    }

    const controller = new AbortController()
    const timeoutId = setTimeout(async () => {
      setLoading(true)
      try {
        const res = await fetch(`/api/search?q=${encodeURIComponent(query)}`, {
          signal: controller.signal,
        })
        if (res.ok) {
          const data = await res.json()
          setResults(data.results)
        }
      } catch (e) {
        if (e instanceof Error && e.name !== "AbortError") {
          console.error("Search failed:", e)
        }
      } finally {
        setLoading(false)
      }
    }, 300) // Debounce

    return () => {
      clearTimeout(timeoutId)
      controller.abort()
    }
  }, [query])

  return { results, loading }
}

// In component
const { results: dynamicResults, loading } = useDynamicSearch(query)

// Combine static and dynamic results
const allResults = React.useMemo(() => {
  const staticResults = searchItems(query, ALL_SEARCH_ITEMS)
  return [...staticResults, ...dynamicResults.map(r => ({
    id: r.id,
    title: r.title,
    description: r.description,
    href: r.href,
    icon: r.type === "repository" ? GitBranch :
          r.type === "finding" ? AlertTriangle : Users,
    category: "dynamic" as const,
  }))]
}, [query, dynamicResults])
```

---

## Styling Variants

### Variant A: Minimal (Default)

```tsx
<Button variant="outline" size="sm" className="gap-2 text-muted-foreground">
  <Search className="h-4 w-4" />
  <span className="hidden sm:inline">Search...</span>
  <kbd className="hidden sm:inline-flex h-5 items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px]">
    <Command className="h-3 w-3" />K
  </kbd>
</Button>
```

### Variant B: Wider Search Bar

```tsx
<Button
  variant="outline"
  className="w-64 justify-start text-muted-foreground"
  onClick={() => setOpen(true)}
>
  <Search className="h-4 w-4 mr-2" />
  <span className="flex-1 text-left">Search...</span>
  <kbd className="ml-2 h-5 items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px]">
    ⌘K
  </kbd>
</Button>
```

### Variant C: Icon Only (Mobile)

```tsx
<Button variant="ghost" size="icon" onClick={() => setOpen(true)}>
  <Search className="h-5 w-5" />
  <span className="sr-only">Search</span>
</Button>
```

### Variant D: Floating Search Bar

```tsx
<div className="relative">
  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
  <Input
    placeholder="Search..."
    className="pl-10 pr-20 w-64 cursor-pointer"
    readOnly
    onClick={() => setOpen(true)}
  />
  <kbd className="absolute right-3 top-1/2 -translate-y-1/2 h-5 items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px]">
    ⌘K
  </kbd>
</div>
```

---

## Complete File Structure

```
src/
├── app/
│   └── layout.tsx           # Layout with QuickSearch in header
├── components/
│   ├── ui/
│   │   ├── dialog.tsx       # shadcn dialog
│   │   ├── input.tsx        # shadcn input
│   │   └── button.tsx       # shadcn button
│   └── QuickSearch.tsx      # Main component
└── lib/
    └── utils.ts             # cn() utility
```

---

## Accessibility Checklist

- [x] **Screen reader**: Title is announced via DialogTitle (sr-only)
- [x] **Role attributes**: listbox/option for results
- [x] **aria-selected**: Indicates current selection
- [x] **Keyboard navigation**: Full support (arrows, enter, escape, tab)
- [x] **Focus management**: Auto-focus input on open
- [x] **Focus trap**: Dialog keeps focus within
- [x] **Escape to close**: Standard dialog behavior
- [x] **Click outside**: Closes dialog

---

## Testing Checklist

- [ ] ⌘K (Mac) / Ctrl+K (Windows) opens search
- [ ] Pressing shortcut again closes search
- [ ] Click on trigger button opens search
- [ ] Input is auto-focused when dialog opens
- [ ] Typing filters results in real-time
- [ ] Arrow Up/Down navigates through results
- [ ] Selected item is visually highlighted
- [ ] Enter selects current item and navigates
- [ ] Escape closes dialog
- [ ] Clicking outside closes dialog
- [ ] Clicking on result navigates and closes
- [ ] Empty state shows "No results" message
- [ ] Dialog state resets when reopened
- [ ] Works on mobile (touch)
- [ ] Works with screen readers

---

## Performance Considerations

1. **Memoize filtered results**:
   ```tsx
   const filteredItems = React.useMemo(() => searchItems(query, items), [query])
   ```

2. **Debounce API searches**:
   ```tsx
   const timeoutId = setTimeout(fetchResults, 300)
   ```

3. **Virtual scrolling for large lists** (if needed):
   ```tsx
   import { useVirtualizer } from "@tanstack/react-virtual"
   ```

4. **Lazy load icons**:
   ```tsx
   const Icon = React.lazy(() => import(`lucide-react`).then(m => ({ default: m[iconName] })))
   ```

---

## Keyboard Shortcut Reference

| Key | Action |
|-----|--------|
| `⌘K` / `Ctrl+K` | Open/toggle search |
| `↑` / `↓` | Navigate results |
| `Enter` | Select current item |
| `Escape` | Close search |
| `Tab` / `Shift+Tab` | Cycle through results |
| `Home` | Jump to first result |
| `End` | Jump to last result |

---

## Summary

This prompt provides everything needed to implement a professional navigation search (command palette):

1. **QuickSearch Component** - Full implementation with keyboard navigation
2. **Search Algorithm** - Weighted scoring across title, description, keywords
3. **Trigger Button** - Multiple styling variants
4. **Layout Integration** - Positioned in upper right header
5. **Enhancements** - Recent searches, grouped results, dynamic API search
6. **Accessibility** - Full ARIA support, keyboard navigation
7. **Performance** - Memoization, debouncing, scroll optimization

The component follows the exact patterns from the AuditGitHub project and integrates seamlessly with shadcn/ui and Tailwind CSS.
