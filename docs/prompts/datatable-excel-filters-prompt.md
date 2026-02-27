# LLM Prompt: Create Pagination DataTable with Microsoft Excel-Style Filters

## Task Overview

Create a **production-ready, paginated DataTable component** with **Microsoft Excel-style column filters** for a Next.js 16+ application. The implementation should follow the exact patterns, architecture, and conventions established in the AuditGitHub project's `/findings` page.

---

## Tech Stack Requirements

| Technology | Version | Purpose |
|------------|---------|---------|
| **Next.js** | 16.0.6+ | React framework with App Router |
| **React** | 19.2.0+ | UI library |
| **TypeScript** | 5.x | Type safety |
| **TanStack React Table** | v8 | Headless table library |
| **Tailwind CSS** | v4 | Utility-first styling |
| **shadcn/ui** | Latest | Component primitives (Radix UI-based) |
| **lucide-react** | Latest | Icon library |

---

## Required shadcn/ui Components

Ensure these components are installed via `npx shadcn-ui@latest add <component>`:

```
button, input, badge, checkbox, popover, dropdown-menu,
select, scroll-area, table, separator, label, switch, tabs
```

---

## Architecture Overview

### Component Hierarchy

```
DataTable (main container)
├── DataTableToolbar
│   ├── Global Search Input
│   ├── Active Filter Badges
│   ├── Group By Dropdown
│   ├── Column Visibility Popover
│   └── Reset Button
├── Table (with TableHeader, TableBody)
│   └── DataTableColumnHeader (per column)
│       └── Excel-style Filter Popover
│           ├── Sorting Controls (A→Z, Z→A)
│           ├── Filter Mode Toggle (Multi-select / Comparison)
│           ├── Multi-select Filter
│           │   ├── Search within values
│           │   ├── Quick actions (Select All, Clear, Invert)
│           │   ├── Checkbox list with counts
│           │   └── Hover actions (Select Only, Exclude)
│           └── Comparison Filter (for dates/numbers)
│               ├── Operator selector (>=, <=, >, <, =, !=)
│               └── Value input
├── DataTablePagination (for standard mode)
└── GroupedPagination (for grouped mode)
```

---

## Core Implementation Files

### 1. `data-table.tsx` - Main DataTable Component

```tsx
"use client"

import * as React from "react"
import {
    ColumnDef,
    ColumnFiltersState,
    SortingState,
    VisibilityState,
    flexRender,
    getCoreRowModel,
    getFacetedRowModel,
    getFacetedUniqueValues,
    getFilteredRowModel,
    getGroupedRowModel,
    getExpandedRowModel,
    getPaginationRowModel,
    getSortedRowModel,
    useReactTable,
    GroupingState,
    ExpandedState,
    Row,
    FilterFn,
} from "@tanstack/react-table"

// Filter value type that supports both array-based and comparison-based filtering
export type FilterValue =
    | string[] // Array of selected values (multi-select)
    | { operator: '>=' | '<=' | '>' | '<' | '=' | '!='; value: string | number } // Comparison
    | undefined

// Custom filter function that supports array-based multi-select AND comparison operators
const arrayIncludesFilter: FilterFn<unknown> = (row, columnId, filterValue) => {
    if (!filterValue) {
        return true
    }

    const cellValue = row.getValue(columnId)

    // Handle comparison operators
    if (filterValue && typeof filterValue === 'object' && 'operator' in filterValue) {
        const { operator, value } = filterValue as { operator: string; value: string | number }

        // Try to parse as date first
        const cellDate = parseDate(cellValue)
        const filterDate = parseDate(value)

        if (cellDate && filterDate) {
            // Date comparison
            switch (operator) {
                case '>=': return cellDate >= filterDate
                case '<=': return cellDate <= filterDate
                case '>': return cellDate > filterDate
                case '<': return cellDate < filterDate
                case '=': return cellDate.getTime() === filterDate.getTime()
                case '!=': return cellDate.getTime() !== filterDate.getTime()
            }
        }

        // Numeric comparison
        const cellNum = parseFloat(String(cellValue))
        const filterNum = typeof value === 'number' ? value : parseFloat(String(value))

        if (!isNaN(cellNum) && !isNaN(filterNum)) {
            switch (operator) {
                case '>=': return cellNum >= filterNum
                case '<=': return cellNum <= filterNum
                case '>': return cellNum > filterNum
                case '<': return cellNum < filterNum
                case '=': return cellNum === filterNum
                case '!=': return cellNum !== filterNum
            }
        }

        // String comparison (for = and !=)
        const cellStr = String(cellValue ?? "")
        const filterStr = String(value)
        if (operator === '=') return cellStr === filterStr
        if (operator === '!=') return cellStr !== filterStr

        return true
    }

    // Array-based filtering (multi-select)
    if (Array.isArray(filterValue)) {
        if (filterValue.length === 0) return true
        const value = String(cellValue ?? "")
        return filterValue.includes(value)
    }

    // String contains
    const value = String(cellValue ?? "")
    return value.toLowerCase().includes(String(filterValue).toLowerCase())
}

// Helper to parse various date formats
function parseDate(value: unknown): Date | null {
    if (!value) return null
    if (value instanceof Date) return value

    const str = String(value).trim()

    // Year only (e.g., "2023")
    if (/^\d{4}$/.test(str)) {
        return new Date(parseInt(str), 0, 1) // Jan 1 of that year
    }

    // Year-Month (e.g., "2023-06")
    if (/^\d{4}-\d{2}$/.test(str)) {
        const [year, month] = str.split('-').map(Number)
        return new Date(year, month - 1, 1)
    }

    // Try parsing as ISO date or common formats
    const parsed = new Date(str)
    if (!isNaN(parsed.getTime())) {
        return parsed
    }

    return null
}

// [Rest of implementation - see complete reference below]
```

**Key Features to Implement:**

1. **State Management**:
   - `sorting: SortingState`
   - `columnFilters: ColumnFiltersState`
   - `columnVisibility: VisibilityState`
   - `globalFilter: string`
   - `grouping: GroupingState`
   - `expanded: ExpandedState`
   - `pageIndex: number`
   - `pageSize: number`

2. **LocalStorage Persistence**:
   - Save/restore: sorting, columnFilters, columnVisibility, globalFilter, grouping, pageSize
   - Storage key: `table-filters-{tableId}`
   - Validate persisted columns against current column definitions

3. **Table Configuration**:
   ```tsx
   const table = useReactTable({
       data,
       columns: columnsWithFilter,
       state: { sorting, columnVisibility, columnFilters, globalFilter, grouping, expanded, pagination },
       enableRowSelection: true,
       enableGrouping: true,
       getCoreRowModel: getCoreRowModel(),
       getFilteredRowModel: getFilteredRowModel(),
       getPaginationRowModel: getPaginationRowModel(),
       getSortedRowModel: getSortedRowModel(),
       getFacetedRowModel: getFacetedRowModel(),
       getFacetedUniqueValues: getFacetedUniqueValues(),
       getGroupedRowModel: getGroupedRowModel(),
       getExpandedRowModel: getExpandedRowModel(),
       globalFilterFn: "includesString",
       filterFns: { arrayIncludes: arrayIncludesFilter },
       manualPagination: isGrouped,
   })
   ```

4. **Grouped Mode Pagination**:
   - Paginate by groups, not individual rows
   - When expanded, show ALL children (exceed page limit)
   - Custom pagination controls for grouped mode

---

### 2. `data-table-column-header.tsx` - Excel-Style Column Header

This is the **core Excel-like filter component**. Each column header is a button that opens a popover with:

**Header Section:**
- Column title
- Hide column button
- Sort buttons: "Sort A→Z", "Sort Z→A", Clear sort

**Filter Section (for columns with unique values):**

**Mode Toggle (for date/number columns):**
- Multi-Select mode (default)
- Comparison mode

**Multi-Select Mode:**
```
┌─────────────────────────────────────┐
│ [Search 47 values...]           [X] │
├─────────────────────────────────────┤
│ When searching:                     │
│ [✓ Select 5 matching] [Exclude]     │
├─────────────────────────────────────┤
│ [Select All] [Clear] [Invert]       │
├─────────────────────────────────────┤
│ Showing 1,234 of 5,678 rows         │
├─────────────────────────────────────┤
│ ┌─────────────────────────────────┐ │
│ │ ☑ Critical              (127)  │ │
│ │   [👁] [👁‍🗨]                    │ │  <- Hover actions
│ │ ☑ High                  (456)  │ │
│ │ ☐ Medium                (789)  │ │
│ │ ☐ Low                   (234)  │ │
│ └─────────────────────────────────┘ │
├─────────────────────────────────────┤
│        [Clear all filters]          │
└─────────────────────────────────────┘
```

**Comparison Mode (for dates/numbers):**
```
┌─────────────────────────────────────┐
│ Filter dates where Column:          │
│ ┌────┐ ┌─────────────────┐ [✓] [X] │
│ │ >= │ │ 2023            │          │
│ └────┘ └─────────────────┘          │
│ Examples: 2023, 2023-06, 2023-06-15 │
│ Active: Column >= 2023              │
└─────────────────────────────────────┘
```

**Comparison Operators:**
```tsx
const OPERATORS = [
    { value: '>=', label: '≥ Greater or Equal' },
    { value: '<=', label: '≤ Less or Equal' },
    { value: '>', label: '> Greater Than' },
    { value: '<', label: '< Less Than' },
    { value: '=', label: '= Equals' },
    { value: '!=', label: '≠ Not Equals' },
]
```

**Hover Actions on Filter Values:**
- 👁 Eye icon: "Select Only" - filter to show only this value
- 👁‍🗨 Eye-Off icon: "Select All Except" - filter to hide only this value

**Auto-detect Column Type:**
```tsx
const columnType = React.useMemo(() => {
    const sampleValues = allUniqueValues.slice(0, 10).map(v => v.value)

    // Check for date patterns
    const datePatterns = [/^\d{4}-\d{2}-\d{2}/, /^\d{4}$/, /^\d{1,2}\/\d{1,2}\/\d{2,4}/]
    if (sampleValues.some(v => datePatterns.some(p => p.test(v)))) return 'date'

    // Check for numbers
    if (sampleValues.every(v => !isNaN(parseFloat(v)))) return 'number'

    return 'string'
}, [allUniqueValues])
```

---

### 3. `data-table-toolbar.tsx` - Toolbar Component

Features:
- **Global Search**: Search across all columns with clear button
- **Active Filter Count Badge**: Shows "3 filters" when filters active
- **Group By Dropdown**: Select column to group rows by
- **Column Visibility Popover**: Toggle columns on/off with "Show all" button
- **Reset Button**: Clear all filters, sorting, visibility, grouping; styled orange when customizations active

---

### 4. `data-table-pagination.tsx` - Pagination Component

Features:
- Row selection count display
- "Rows per page" dropdown: 10, 20, 30, 40, 50
- Direct page input with Enter to submit, Escape to cancel
- Navigation buttons: First, Previous, Next, Last

---

## Page Implementation Example

### `/findings/page.tsx`

```tsx
"use client"

import { useEffect, useState } from "react"
import { DataTable } from "@/components/data-table"
import { ColumnDef } from "@tanstack/react-table"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { Badge } from "@/components/ui/badge"
import Link from "next/link"

interface Finding {
    id: string
    title: string
    description: string | null
    severity: string
    status: string
    scanner_name: string | null
    repo_name: string
    repository_id: string | null
    file_path: string | null
    line_start: number | null
    created_at: string
    risk_score: number | null
    risk_level: string | null
}

// Custom severity sort order
const SEVERITY_ORDER: Record<string, number> = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    info: 5,
    warning: 6,
}

// Column definitions with Excel-style headers
const columns: ColumnDef<Finding>[] = [
    {
        accessorKey: "severity",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Severity" />
        ),
        cell: ({ row }) => getSeverityBadge(row.getValue("severity")),
        sortingFn: (rowA, rowB) => {
            const sevA = SEVERITY_ORDER[rowA.original.severity?.toLowerCase()] || 99
            const sevB = SEVERITY_ORDER[rowB.original.severity?.toLowerCase()] || 99
            return sevA - sevB
        },
        filterFn: (row, id, value) => {
            if (!value || !Array.isArray(value) || value.length === 0) return true
            return value.includes(row.getValue(id))
        },
    },
    {
        accessorKey: "title",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Title" />
        ),
        cell: ({ row }) => (
            <Link
                href={`/findings/${row.original.id}`}
                className="font-medium text-blue-600 hover:underline max-w-md truncate block"
            >
                {row.getValue("title")}
            </Link>
        ),
    },
    // ... additional columns following same pattern
]

export default function FindingsPage() {
    const [findings, setFindings] = useState<Finding[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetchFindings()
    }, [])

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">All Findings</h1>
                <p className="text-muted-foreground">
                    {findings.length.toLocaleString()} security issues
                </p>
            </div>

            <DataTable
                columns={columns}
                data={findings}
                searchKey="title"
                searchPlaceholder={`Search ${findings.length.toLocaleString()} findings...`}
                tableId="findings"
                enableGrouping={true}
                initialPageSize={50}
            />
        </div>
    )
}
```

---

## API Integration Pattern

### Paginated Endpoint Response Schema

```typescript
interface PaginatedResponse<T> {
    items: T[]
    total: number
    page: number
    page_size: number
    total_pages: number
    has_next: boolean
    has_prev: boolean
}
```

### Progressive Data Loading

```tsx
const fetchData = async () => {
    let allItems: T[] = []
    let page = 1
    const pageSize = 100
    let hasMore = true

    while (hasMore) {
        const params = new URLSearchParams({
            page: page.toString(),
            page_size: pageSize.toString(),
            order_by: "severity"
        })

        const res = await fetch(`${API_BASE}/endpoint/paginated?${params}`, {
            credentials: 'include'
        })

        if (res.ok) {
            const data: PaginatedResponse<T> = await res.json()
            allItems = [...allItems, ...data.items]
            hasMore = data.has_next && allItems.length < 5000 // Safety limit
            page++
            setItems(allItems) // Progressive update for UX
        } else {
            hasMore = false
        }
    }
}
```

---

## Styling Guidelines

### Badge Color Mappings

```tsx
// Severity badges
const severityColors: Record<string, string> = {
    critical: "bg-red-500 hover:bg-red-600",
    high: "bg-orange-500 hover:bg-orange-600",
    medium: "bg-yellow-500 hover:bg-yellow-600",
    low: "bg-blue-500 hover:bg-blue-600",
    info: "bg-gray-400 hover:bg-gray-500",
}

// Status badges (outline variant)
const statusColors: Record<string, string> = {
    open: "border-red-500 text-red-600",
    in_progress: "border-yellow-500 text-yellow-600",
    resolved: "border-green-500 text-green-600",
    false_positive: "border-gray-500 text-gray-600",
}
```

### Table Styling

```tsx
<Table>
    <TableHeader className="bg-muted/50">
        {/* Headers */}
    </TableHeader>
    <TableBody>
        {/* Grouped rows have special styling */}
        <TableRow className="bg-muted/30 hover:bg-muted/50 cursor-pointer font-medium">
            {/* Group header content */}
        </TableRow>
    </TableBody>
</Table>
```

---

## Key Implementation Details

### 1. Filter Persistence with Validation

```tsx
const loadPersistedState = React.useCallback(() => {
    const stored = getStorageItem(storageKey)
    if (!stored) return null

    const parsed = JSON.parse(stored)

    // Get valid column IDs from current columns definition
    const validColumnIds = new Set(
        columns.map(col => {
            if ('accessorKey' in col && col.accessorKey) return String(col.accessorKey)
            if ('id' in col && col.id) return col.id
            return null
        }).filter(Boolean)
    )

    // Filter out invalid column references
    if (parsed.sorting) {
        parsed.sorting = parsed.sorting.filter((s: any) => validColumnIds.has(s.id))
    }
    if (parsed.columnFilters) {
        parsed.columnFilters = parsed.columnFilters.filter((f: any) => validColumnIds.has(f.id))
    }

    return parsed
}, [storageKey, columns])
```

### 2. Faceted Values with Counts

```tsx
const facetedUniqueValues = column.getFacetedUniqueValues()
const allUniqueValues = React.useMemo(() => {
    const values: { value: string; count: number }[] = []
    facetedUniqueValues.forEach((count, value) => {
        values.push({ value: String(value ?? ""), count })
    })
    return values.sort((a, b) => b.count - a.count) // Sort by count descending
}, [facetedUniqueValues])
```

### 3. Search-Based Bulk Actions

```tsx
{searchValue && filteredValues.length > 0 && (
    <div className="flex gap-1 mb-3 p-2 bg-accent/50 rounded-md">
        <Button
            onClick={() => {
                const matchingValues = filteredValues.map(v => v.value)
                const newSelected = new Set([...selectedValues, ...matchingValues])
                column.setFilterValue(Array.from(newSelected))
            }}
        >
            Select {filteredValues.length} matching
        </Button>
        <Button
            onClick={() => {
                const matchingValues = new Set(filteredValues.map(v => v.value))
                const nonMatching = allUniqueValues
                    .filter(v => !matchingValues.has(v.value))
                    .map(v => v.value)
                column.setFilterValue(nonMatching.length > 0 ? nonMatching : undefined)
            }}
        >
            Exclude matching
        </Button>
    </div>
)}
```

---

## Required Utility Functions

### `lib/utils.ts`

```tsx
import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs))
}
```

---

## Complete File Structure

```
src/
├── components/
│   ├── ui/
│   │   ├── button.tsx
│   │   ├── input.tsx
│   │   ├── badge.tsx
│   │   ├── checkbox.tsx
│   │   ├── popover.tsx
│   │   ├── dropdown-menu.tsx
│   │   ├── select.tsx
│   │   ├── scroll-area.tsx
│   │   ├── table.tsx
│   │   ├── separator.tsx
│   │   ├── label.tsx
│   │   ├── switch.tsx
│   │   └── tabs.tsx
│   ├── data-table.tsx
│   ├── data-table-column-header.tsx
│   ├── data-table-pagination.tsx
│   ├── data-table-toolbar.tsx
│   └── data-table-advanced-filter.tsx (optional alternative)
├── app/
│   └── [your-page]/
│       └── page.tsx
└── lib/
    └── utils.ts
```

---

## Testing Checklist

- [ ] Multi-select filtering works with checkbox toggles
- [ ] "Select All", "Clear", "Invert" quick actions work
- [ ] Search within filter values filters the list
- [ ] "Select matching" and "Exclude matching" work during search
- [ ] Hover actions (Select Only, Select All Except) work
- [ ] Comparison mode works for date columns (>=, <=, etc.)
- [ ] Comparison mode works for numeric columns
- [ ] Sorting (A→Z, Z→A) works and shows correct arrow icons
- [ ] Column visibility toggle works
- [ ] Hidden columns bar shows with quick restore
- [ ] Grouping works and expands/collapses
- [ ] Pagination works in both standard and grouped modes
- [ ] Direct page input works (Enter to submit, Escape to cancel)
- [ ] Filter state persists in localStorage
- [ ] Reset button clears all customizations
- [ ] Global search filters across all columns
- [ ] Performance is acceptable with 5,000+ rows

---

## Performance Considerations

1. **Memoize columns with filter function**:
   ```tsx
   const columnsWithFilter = React.useMemo(() => {
       return columns.map(col => ({
           ...col,
           filterFn: arrayIncludesFilter,
       }))
   }, [columns])
   ```

2. **Use `getFacetedRowModel` and `getFacetedUniqueValues`** for efficient filter value computation

3. **Progressive data loading** - update UI as each batch arrives

4. **Limit persisted state validation** - only validate against current columns

---

## Additional Notes

- All components use `"use client"` directive for client-side rendering
- Icons are from `lucide-react` library
- Popover uses `modal={false}` to prevent focus trapping issues
- Filter badge shows count or comparison expression
- Reset button is always visible but styled differently when customizations are active
- Empty values display as "(empty)" in filter lists
