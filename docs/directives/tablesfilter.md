# Advanced Table Filtering System (TFS) for React/Next.js Applications

## Overview

This directive provides a comprehensive implementation guide for building an advanced, production-ready table filtering system using **TanStack Table (React Table v8)** with **shadcn/ui** components in a **Next.js** application. The system provides Excel-like filtering capabilities with an intuitive, modern UX.

---

## Features Summary

| Feature | Description |
|---------|-------------|
| **Global Search** | Search across all columns simultaneously |
| **Per-Column Filtering** | Multi-select checkbox filters with value counts |
| **Comparison Operators** | For date/numeric columns: `>=`, `<=`, `>`, `<`, `=`, `!=` |
| **Search & Select Matching** | Type to search values, then bulk-select or exclude all matching |
| **Column Sorting** | Ascending/descending sort with visual indicators |
| **Column Visibility** | Hide/show columns with quick restore |
| **Row Grouping** | Group rows by any column with expand/collapse |
| **Smart Pagination** | Groups stay together; direct page jump input |
| **Filter Actions** | Select All, Clear, Invert, Show Only, Exclude |
| **Filter Persistence** | Filters persist in localStorage across navigation |
| **Reset All** | One-click reset of all customizations (clears persisted state) |

---

## Dependencies

```bash
# Core table library
npm install @tanstack/react-table

# Radix UI primitives (for shadcn/ui)
npm install @radix-ui/react-popover @radix-ui/react-checkbox @radix-ui/react-dropdown-menu @radix-ui/react-select @radix-ui/react-scroll-area

# Icons
npm install lucide-react
```

---

## File Structure

```
components/
├── ui/
│   ├── button.tsx
│   ├── input.tsx
│   ├── badge.tsx
│   ├── table.tsx
│   ├── popover.tsx
│   ├── checkbox.tsx
│   ├── dropdown-menu.tsx
│   ├── select.tsx
│   └── scroll-area.tsx
├── data-table.tsx              # Main table component
├── data-table-column-header.tsx # Column header with filter popover
├── data-table-toolbar.tsx       # Toolbar with search, grouping, visibility
└── data-table-pagination.tsx    # Pagination with page jump
```

---

## Component 1: Main Data Table (`data-table.tsx`)

This is the core component that orchestrates all table functionality.

### Key Imports

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
```

### Custom Filter Function (Define BEFORE Table Creation)

> **CRITICAL**: The custom filter function that supports array-based multi-select filtering AND comparison operators MUST be applied to columns BEFORE passing them to `useReactTable()`. If you try to set the filter function in a `useEffect` after the table is created, persisted filters will not work correctly on initial render.

Define the filter function at module level (outside the component):

```tsx
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
```

### localStorage Helpers

```tsx
// Helper to safely access localStorage (handles SSR)
const getStorageItem = (key: string): string | null => {
    if (typeof window === 'undefined') return null
    try {
        return localStorage.getItem(key)
    } catch {
        return null
    }
}

const setStorageItem = (key: string, value: string): void => {
    if (typeof window === 'undefined') return
    try {
        localStorage.setItem(key, value)
    } catch {
        // Ignore storage errors
    }
}
```

### Props Interface

```tsx
interface DataTableProps<TData, TValue> {
    columns: ColumnDef<TData, TValue>[]
    data: TData[]
    tableId?: string // Unique ID for persisting filters (e.g., "findings", "repositories")
    searchPlaceholder?: string
    enableGrouping?: boolean
    defaultGrouping?: string[]
    initialPageSize?: number
    persistFilters?: boolean // Whether to persist filters in localStorage (default: true)
}
```

### State Management

```tsx
// Storage key for this table
const storageKey = tableId ? `table-filters-${tableId}` : null

// Load persisted state from localStorage
const loadPersistedState = React.useCallback(() => {
    if (!storageKey || !persistFilters) return null
    const stored = getStorageItem(storageKey)
    if (!stored) return null
    try {
        return JSON.parse(stored)
    } catch {
        return null
    }
}, [storageKey, persistFilters])

// Initialize state from persisted values or defaults
const persistedState = React.useMemo(() => loadPersistedState(), [loadPersistedState])

const [sorting, setSorting] = React.useState<SortingState>(
    persistedState?.sorting ?? []
)
const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    persistedState?.columnFilters ?? []
)
const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>(
    persistedState?.columnVisibility ?? {}
)
const [globalFilter, setGlobalFilter] = React.useState(
    persistedState?.globalFilter ?? ""
)
const [grouping, setGrouping] = React.useState<GroupingState>(
    persistedState?.grouping ?? defaultGrouping
)
const [expanded, setExpanded] = React.useState<ExpandedState>({})
const [groupByColumn, setGroupByColumn] = React.useState<string | undefined>(
    persistedState?.groupByColumn ?? (defaultGrouping.length > 0 ? defaultGrouping[0] : undefined)
)
const [pageSize, setPageSize] = React.useState(
    persistedState?.pageSize ?? initialPageSize
)
const [pageIndex, setPageIndex] = React.useState(0)

// Persist state changes to localStorage
React.useEffect(() => {
    if (!storageKey || !persistFilters) return
    
    const stateToSave = {
        sorting,
        columnFilters,
        columnVisibility,
        globalFilter,
        grouping,
        groupByColumn,
        pageSize,
    }
    setStorageItem(storageKey, JSON.stringify(stateToSave))
}, [storageKey, persistFilters, sorting, columnFilters, columnVisibility, globalFilter, grouping, groupByColumn, pageSize])

// Function to clear persisted state (called by Reset button)
const clearPersistedState = () => {
    if (storageKey) {
        localStorage.removeItem(storageKey)
    }
}
```

### Table Configuration

> **IMPORTANT**: Apply the custom filter function to columns BEFORE passing them to `useReactTable()`. This ensures persisted filters work correctly on initial render.

```tsx
// Apply custom filter function to all columns BEFORE creating the table
const columnsWithFilter = React.useMemo(() => {
    return columns.map(col => ({
        ...col,
        filterFn: arrayIncludesFilter,
    }))
}, [columns])

const table = useReactTable({
    data,
    columns: columnsWithFilter, // Use modified columns with filter function
    state: {
        sorting,
        columnVisibility,
        columnFilters,
        globalFilter,
        grouping,
        expanded,
        pagination: { pageIndex, pageSize },
    },
    enableRowSelection: true,
    enableGrouping: true,
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onColumnVisibilityChange: setColumnVisibility,
    onGlobalFilterChange: setGlobalFilter,
    onGroupingChange: setGrouping,
    onExpandedChange: setExpanded,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getGroupedRowModel: getGroupedRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    globalFilterFn: "includesString",
    filterFns: {
        arrayIncludes: arrayIncludesFilter,
    },
    manualPagination: isGrouped, // Custom pagination when grouped
})
```

> ⚠️ **DO NOT** set the filter function in a `useEffect` after table creation. This causes a race condition where persisted filters are applied before the custom filter function is set, resulting in no visible rows.

### Group-Aware Pagination

When grouping is active, paginate by groups (not rows) and keep expanded groups together:

```tsx
const paginatedRows = React.useMemo(() => {
    if (!isGrouped) {
        return table.getRowModel().rows
    }

    // Paginate by groups, but include ALL children when expanded
    const groupRows = allExpandedRows.filter(row => row.depth === 0)
    const startIdx = pageIndex * pageSize
    const endIdx = startIdx + pageSize
    const pageGroups = groupRows.slice(startIdx, Math.min(endIdx, groupRows.length))
    
    const result: Row<TData>[] = []
    pageGroups.forEach((groupRow) => {
        result.push(groupRow)
        if (groupRow.getIsExpanded() && groupRow.subRows) {
            result.push(...groupRow.subRows) // Exception: exceed page limit to keep group together
        }
    })
    return result
}, [isGrouped, allExpandedRows, pageIndex, pageSize, expanded])
```

### Grouped Row Rendering

```tsx
function GroupedTableRow<TData>({ row, enableGrouping }: { row: Row<TData>; enableGrouping: boolean }) {
    const isGrouped = row.getIsGrouped()
    const isExpanded = row.getIsExpanded()

    if (isGrouped) {
        return (
            <TableRow
                className="bg-muted/30 hover:bg-muted/50 cursor-pointer"
                onClick={() => row.toggleExpanded()}
            >
                <TableCell colSpan={row.getVisibleCells().length}>
                    <div className="flex items-center gap-2">
                        {isExpanded ? <ChevronDown /> : <ChevronRight />}
                        <Layers className="h-4 w-4" />
                        <span className="font-semibold">{String(row.groupingValue) || "(empty)"}</span>
                        <Badge variant="secondary">{row.subRows.length} items</Badge>
                    </div>
                </TableCell>
            </TableRow>
        )
    }

    return (
        <TableRow>
            {row.getVisibleCells().map((cell) => (
                <TableCell key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </TableCell>
            ))}
        </TableRow>
    )
}
```

---

## Component 2: Column Header with Filter (`data-table-column-header.tsx`)

Each column header is a clickable popover with sorting and filtering controls. The filter supports two modes:
- **Multi-Select Mode**: Traditional checkbox selection of values
- **Comparison Mode**: For date/numeric columns, use operators like `>=`, `<=`, `>`, `<`, `=`, `!=`

### Key Imports and Types

```tsx
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"

// Comparison operators
type ComparisonOperator = '>=' | '<=' | '>' | '<' | '=' | '!='

const OPERATORS: { value: ComparisonOperator; label: string }[] = [
    { value: '>=', label: '≥ Greater or Equal' },
    { value: '<=', label: '≤ Less or Equal' },
    { value: '>', label: '> Greater Than' },
    { value: '<', label: '< Less Than' },
    { value: '=', label: '= Equals' },
    { value: '!=', label: '≠ Not Equals' },
]

type FilterMode = 'multiselect' | 'comparison'
```

### Filter Mode State

```tsx
const [filterMode, setFilterMode] = React.useState<FilterMode>('multiselect')
const [comparisonOperator, setComparisonOperator] = React.useState<ComparisonOperator>('>=')
const [comparisonValue, setComparisonValue] = React.useState("")

// Initialize from existing comparison filter
React.useEffect(() => {
    const currentFilter = column.getFilterValue()
    if (currentFilter && typeof currentFilter === 'object' && 'operator' in currentFilter) {
        const { operator, value } = currentFilter as { operator: ComparisonOperator; value: string | number }
        setFilterMode('comparison')
        setComparisonOperator(operator)
        setComparisonValue(String(value))
    }
}, [column])
```

### Column Type Detection

Auto-detect if a column contains dates or numbers to show the comparison mode toggle:

```tsx
const columnType = React.useMemo(() => {
    if (allUniqueValues.length === 0) return 'string'
    const sampleValues = allUniqueValues.slice(0, 10).map(v => v.value)
    
    // Check for date patterns
    const datePatterns = [
        /^\d{4}-\d{2}-\d{2}/, // ISO date
        /^\d{4}$/, // Year only
        /^\d{1,2}\/\d{1,2}\/\d{2,4}/, // MM/DD/YYYY
    ]
    const looksLikeDates = sampleValues.some(v => 
        datePatterns.some(p => p.test(v)) || !isNaN(Date.parse(v))
    )
    if (looksLikeDates) return 'date'
    
    // Check for numbers
    const looksLikeNumbers = sampleValues.every(v => !isNaN(parseFloat(v)))
    if (looksLikeNumbers) return 'number'
    
    return 'string'
}, [allUniqueValues])

const supportsComparison = columnType === 'date' || columnType === 'number'
```

### Filter Mode Toggle UI

```tsx
{/* Filter mode toggle - only show if column supports comparison */}
{supportsComparison && (
    <div className="flex gap-1 mb-3">
        <Button
            variant={filterMode === 'multiselect' ? 'default' : 'outline'}
            size="sm"
            className="h-7 flex-1 text-xs"
            onClick={() => switchToMode('multiselect')}
        >
            <List className="h-3 w-3 mr-1" />
            Multi-Select
        </Button>
        <Button
            variant={filterMode === 'comparison' ? 'default' : 'outline'}
            size="sm"
            className="h-7 flex-1 text-xs"
            onClick={() => switchToMode('comparison')}
        >
            <Calculator className="h-3 w-3 mr-1" />
            Comparison
        </Button>
    </div>
)}
```

### Comparison Filter UI

Inline layout: `| >= ▼ | [value] | ✓ | × |`

```tsx
{/* Comparison filter UI */}
{filterMode === 'comparison' && supportsComparison && (
    <div className="space-y-3 mb-3 p-3 bg-muted/50 rounded-lg">
        <div className="text-xs font-medium text-muted-foreground">
            Filter {columnType === 'date' ? 'dates' : 'values'} where {title}:
        </div>
        <div className="flex items-center gap-1">
            <Select
                value={comparisonOperator}
                onValueChange={(v) => setComparisonOperator(v as ComparisonOperator)}
            >
                <SelectTrigger className="w-[60px] h-9 font-mono text-lg justify-center px-2">
                    <SelectValue placeholder=">=" />
                </SelectTrigger>
                <SelectContent side="bottom" align="start" sideOffset={4}>
                    {OPERATORS.map((op) => (
                        <SelectItem key={op.value} value={op.value}>
                            <div className="flex items-center gap-2">
                                <span className="font-mono font-bold w-6">{op.value}</span>
                                <span className="text-muted-foreground text-xs">
                                    {op.label.split(' ').slice(1).join(' ')}
                                </span>
                            </div>
                        </SelectItem>
                    ))}
                </SelectContent>
            </Select>
            <Input
                placeholder={columnType === 'date' ? '2023' : 'value'}
                value={comparisonValue}
                onChange={(e) => setComparisonValue(e.target.value)}
                onKeyDown={(e) => {
                    if (e.key === 'Enter') applyComparisonFilter()
                }}
                className="h-9 flex-1 font-mono"
            />
            <Button
                variant="default"
                size="sm"
                className="h-9 px-3"
                onClick={applyComparisonFilter}
                disabled={!comparisonValue.trim()}
            >
                <Check className="h-4 w-4" />
            </Button>
            {isComparisonFilter && (
                <Button
                    variant="ghost"
                    size="sm"
                    className="h-9 px-2"
                    onClick={clearComparisonFilter}
                >
                    <X className="h-4 w-4" />
                </Button>
            )}
        </div>
        {columnType === 'date' && (
            <div className="text-xs text-muted-foreground">
                Examples: 2023, 2023-06, 2023-06-15
            </div>
        )}
    </div>
)}
```

### Comparison Filter Handlers

```tsx
// Apply comparison filter
const applyComparisonFilter = () => {
    if (comparisonValue.trim()) {
        column.setFilterValue({
            operator: comparisonOperator,
            value: comparisonValue.trim()
        })
    }
}

// Clear comparison filter
const clearComparisonFilter = () => {
    setComparisonValue("")
    column.setFilterValue(undefined)
}

// Switch filter mode
const switchToMode = (mode: FilterMode) => {
    setFilterMode(mode)
    column.setFilterValue(undefined) // Clear existing filter when switching modes
    setComparisonValue("")
}

// Check if currently using comparison filter
const isComparisonFilter = currentFilterValue && 
    typeof currentFilterValue === 'object' && 
    'operator' in currentFilterValue

// Update isFiltered to include comparison
const isFiltered = selectedValues.size > 0 || isComparisonFilter
```

### Badge Display for Comparison Filter

```tsx
{isFiltered && (
    <Badge
        variant="secondary"
        className="ml-2 h-5 rounded-sm px-1.5 font-mono text-[10px] bg-primary text-primary-foreground"
    >
        {isComparisonFilter 
            ? `${(currentFilterValue as { operator: string }).operator}${(currentFilterValue as { value: string }).value}`
            : selectedValues.size
        }
    </Badge>
)}
```

> **Important**: When nesting a Select inside a Popover, add `modal={false}` to the Popover to prevent focus trapping issues:
> ```tsx
> <Popover open={open} onOpenChange={setOpen} modal={false}>
> ```

### Filter Value Extraction

Use `getFacetedUniqueValues()` to get all unique values with their counts:

```tsx
const facetedUniqueValues = column.getFacetedUniqueValues()
const allUniqueValues = React.useMemo(() => {
    const values: { value: string; count: number }[] = []
    facetedUniqueValues.forEach((count, value) => {
        values.push({ value: String(value ?? ""), count })
    })
    return values.sort((a, b) => b.count - a.count) // Sort by frequency
}, [facetedUniqueValues])
```

### Filter Actions

```tsx
const toggleValue = (value: string) => {
    const newSelected = new Set(selectedValues)
    if (newSelected.has(value)) {
        newSelected.delete(value)
    } else {
        newSelected.add(value)
    }
    column.setFilterValue(newSelected.size > 0 ? Array.from(newSelected) : undefined)
}

const selectAll = () => column.setFilterValue(allUniqueValues.map((v) => v.value))
const selectNone = () => column.setFilterValue(undefined)
const selectOnly = (value: string) => column.setFilterValue([value])
const selectAllExcept = (value: string) => {
    const values = allUniqueValues.filter((v) => v.value !== value).map((v) => v.value)
    column.setFilterValue(values.length > 0 ? values : undefined)
}
const invertSelection = () => {
    const inverted = allUniqueValues.map((v) => v.value).filter((v) => !selectedValues.has(v))
    column.setFilterValue(inverted.length > 0 ? inverted : undefined)
}

// Select all values matching current search
const selectMatching = () => {
    const matchingValues = filteredValues.map(v => v.value)
    const newSelected = new Set([...selectedValues, ...matchingValues])
    column.setFilterValue(Array.from(newSelected))
}

// Select all EXCEPT values matching current search
const excludeMatching = () => {
    const matchingValues = new Set(filteredValues.map(v => v.value))
    const nonMatching = allUniqueValues
        .filter(v => !matchingValues.has(v.value))
        .map(v => v.value)
    column.setFilterValue(nonMatching.length > 0 ? nonMatching : undefined)
}
```

### Search Match Actions (Select/Exclude Matching)

When a user types in the search box, show action buttons to bulk-select or bulk-exclude all matching values:

```tsx
{/* Search match actions - show when searching */}
{searchValue && filteredValues.length > 0 && (
    <div className="flex gap-1 mb-3 p-2 bg-accent/50 rounded-md">
        <Button
            variant="default"
            size="sm"
            className="h-6 text-xs px-2 flex-1"
            onClick={selectMatching}
        >
            <Check className="h-3 w-3 mr-1" />
            Select {filteredValues.length} matching
        </Button>
        <Button
            variant="outline"
            size="sm"
            className="h-6 text-xs px-2 flex-1"
            onClick={excludeMatching}
        >
            <EyeOff className="h-3 w-3 mr-1" />
            Exclude matching
        </Button>
    </div>
)}
```

This feature allows users to:
- **Select matching**: Add all values that match the search query to the current filter selection
- **Exclude matching**: Select all values EXCEPT those matching the search query

### Filter Value Item with Hover Actions

```tsx
function FilterValueItem({ value, count, isSelected, onToggle, onSelectOnly, onSelectAllExcept }) {
    const [showActions, setShowActions] = React.useState(false)

    return (
        <div
            className="flex items-center px-2 py-1.5 hover:bg-accent cursor-pointer"
            onMouseEnter={() => setShowActions(true)}
            onMouseLeave={() => setShowActions(false)}
        >
            <Checkbox checked={isSelected} onClick={onToggle} />
            <span className="truncate flex-1">{value || "(empty)"}</span>
            <span className="text-xs text-muted-foreground">{count.toLocaleString()}</span>
            
            {showActions && (
                <div className="absolute right-1 flex gap-0.5">
                    <Button size="sm" onClick={onSelectOnly} title="Show only this">
                        <Eye className="h-3 w-3" />
                    </Button>
                    <Button size="sm" onClick={onSelectAllExcept} title="Hide only this">
                        <EyeOff className="h-3 w-3" />
                    </Button>
                </div>
            )}
        </div>
    )
}
```

---

## Component 3: Toolbar (`data-table-toolbar.tsx`)

### Features

1. **Global Search** - Searches all columns
2. **Active Filter Count Badge**
3. **Group By Dropdown** - Select column to group by
4. **Column Visibility Manager** - Popover with toggle switches
5. **Hidden Columns Bar** - Quick-restore badges for hidden columns
6. **Reset All Button** - Clears all customizations

### Global Search Implementation

```tsx
<div className="relative flex-1 max-w-sm">
    <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
    <Input
        placeholder={searchPlaceholder}
        value={globalFilter}
        onChange={(e) => {
            setGlobalFilter(e.target.value)
            table.setGlobalFilter(e.target.value)
        }}
        className="pl-8 pr-8"
    />
    {globalFilter && (
        <Button
            variant="ghost"
            size="sm"
            className="absolute right-1 top-1"
            onClick={() => {
                setGlobalFilter("")
                table.setGlobalFilter("")
            }}
        >
            <X className="h-4 w-4" />
        </Button>
    )}
</div>
```

### Hidden Columns Quick-Restore Bar

```tsx
function HiddenColumnsBar<TData>({ table }: { table: Table<TData> }) {
    const hiddenColumns = table.getAllColumns()
        .filter((column) => column.getCanHide() && !column.getIsVisible())

    if (hiddenColumns.length === 0) return null

    return (
        <div className="flex items-center gap-2 p-2 bg-muted/50 rounded-lg">
            <EyeOff className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">Hidden columns:</span>
            <div className="flex flex-wrap gap-1">
                {hiddenColumns.map((column) => (
                    <Badge
                        key={column.id}
                        variant="secondary"
                        className="cursor-pointer hover:bg-primary hover:text-primary-foreground"
                        onClick={() => column.toggleVisibility(true)}
                    >
                        {column.id}
                        <Eye className="h-3 w-3 ml-1" />
                    </Badge>
                ))}
            </div>
        </div>
    )
}
```

---

## Component 4: Pagination with Page Jump (`data-table-pagination.tsx`)

### Editable Page Number Input

```tsx
const [inputValue, setInputValue] = React.useState(String(currentPage))

React.useEffect(() => {
    setInputValue(String(currentPage))
}, [currentPage])

const handlePageInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
        const page = parseInt(inputValue, 10)
        if (!isNaN(page) && page >= 1 && page <= pageCount) {
            table.setPageIndex(page - 1)
        }
        (e.target as HTMLInputElement).blur()
    } else if (e.key === 'Escape') {
        setInputValue(String(currentPage))
        (e.target as HTMLInputElement).blur()
    }
}

// Render
<div className="flex items-center space-x-2 text-sm font-medium">
    <span>Page</span>
    <Input
        type="text"
        inputMode="numeric"
        value={inputValue}
        onChange={(e) => setInputValue(e.target.value)}
        onBlur={handlePageInputBlur}
        onKeyDown={handlePageInputKeyDown}
        className="h-8 w-14 text-center"
    />
    <span>of {pageCount}</span>
</div>
```

---

## Column Definition Example

When defining columns, use `DataTableColumnHeader` for the header:

```tsx
import { DataTableColumnHeader } from "@/components/data-table-column-header"

const columns: ColumnDef<Finding>[] = [
    {
        accessorKey: "severity",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Severity" />
        ),
        cell: ({ row }) => <Badge>{row.getValue("severity")}</Badge>,
        filterFn: "arrIncludesSome", // Will be overridden by our custom function
    },
    {
        accessorKey: "repository",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Repository" />
        ),
    },
    {
        accessorKey: "description",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Description" />
        ),
    },
]
```

---

## Usage Example

```tsx
import { DataTable } from "@/components/data-table"
import { columns } from "./columns"

export default function FindingsPage() {
    const [data, setData] = useState<Finding[]>([])

    useEffect(() => {
        fetch("/api/findings")
            .then((res) => res.json())
            .then(setData)
    }, [])

    return (
        <DataTable
            columns={columns}
            data={data}
            tableId="findings" // Unique ID for filter persistence
            searchPlaceholder="Search findings..."
            enableGrouping={true}
            initialPageSize={20}
        />
    )
}
```

### Filter Persistence Behavior

When `tableId` is provided:

1. **Automatic Save**: Filters, sorting, visibility, grouping, and page size are saved to localStorage whenever they change
2. **Automatic Restore**: When navigating back to the page, all settings are restored
3. **Reset Clears All**: Clicking "Reset" clears both the table state AND the localStorage entry
4. **Unique per Table**: Each `tableId` creates a separate localStorage entry, so different tables maintain independent filter state

**Example tableId values:**
- `"findings"` - Main findings page
- `"repositories"` - Repositories list
- `"project-secrets"` - Project detail secrets tab
- `"sbom-dependencies"` - SBOM dependencies view

### Comparison Filter Examples

For date and numeric columns, users can switch to "Comparison" mode and use operators:

| Column | Operator | Value | Result |
|--------|----------|-------|--------|
| Last Commit | `>=` | `2023` | Shows commits from Jan 1, 2023 onwards |
| Last Commit | `<` | `2024` | Shows commits before 2024 |
| Last Commit | `>=` | `2023-06` | Shows commits from June 2023 onwards |
| Stars | `>=` | `100` | Shows repos with 100+ stars |
| Score | `>` | `80` | Shows scores above 80 |
| Count | `!=` | `0` | Shows non-zero counts |
| Version | `=` | `2.0` | Shows exact version matches |

**Supported date input formats:**
- Year only: `2023` → interpreted as January 1, 2023
- Year-month: `2023-06` → interpreted as June 1, 2023
- Full ISO date: `2023-06-15`
- Common formats: `MM/DD/YYYY`, `YYYY-MM-DD`

---

## UI/UX Guidelines

### Visual Indicators

| Element | Indicator |
|---------|-----------|
| Sorted column | Arrow icon (↑ or ↓) |
| Filtered column (multi-select) | Badge with count of selected values (e.g., `3`) |
| Filtered column (comparison) | Badge with operator and value (e.g., `>=2023`) |
| Hidden columns | Bar with clickable restore badges |
| Active filters | Badge showing filter count |
| Grouped mode | Info bar with group/item counts |
| Expanded group exceeds limit | "Expanded group exceeds limit" badge |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| Enter | Apply page number in pagination input |
| Escape | Cancel and revert to current page |

### Color Scheme (using CSS variables)

```css
/* Ensure your tailwind.config.js has these */
--muted: 240 4.8% 95.9%;
--muted-foreground: 240 3.8% 46.1%;
--accent: 240 4.8% 95.9%;
--primary: 240 5.9% 10%;
--primary-foreground: 0 0% 98%;
```

---

## Performance Considerations

1. **Memoize expensive calculations** - Use `React.useMemo` for unique values, filtered values, paginated rows
2. **Virtualization** - For tables with 10,000+ rows, consider `@tanstack/react-virtual`
3. **Debounce global search** - Add 300ms debounce for large datasets
4. **Lazy load faceted values** - Only compute when filter popover opens

---

## Accessibility

- All buttons have `aria-label` or screen reader text
- Keyboard navigable popovers and dropdowns
- Focus management in filter inputs
- Color contrast meets WCAG 2.1 AA standards

---

## Customization Points

| Aspect | How to Customize |
|--------|------------------|
| Page sizes | Modify array in pagination: `[10, 20, 30, 50, 100]` |
| Max grouped columns | Change `allColumns.slice(0, 10)` in toolbar |
| Filter value sort | Change `.sort((a, b) => b.count - a.count)` to sort alphabetically |
| Default page size | Pass `initialPageSize` prop |
| Disable grouping | Set `enableGrouping={false}` |

---

## Complete Implementation Checklist

- [ ] Install dependencies (`@tanstack/react-table`, Radix UI primitives, lucide-react)
- [ ] Create shadcn/ui components (button, input, badge, table, popover, checkbox, dropdown-menu, select, scroll-area)
- [ ] Create `data-table.tsx` with all state management and grouping logic
- [ ] Create `data-table-column-header.tsx` with filter popover
- [ ] Create `data-table-toolbar.tsx` with search, grouping, visibility controls
- [ ] Create `data-table-pagination.tsx` with page jump input
- [ ] Define columns using `DataTableColumnHeader` for headers
- [ ] Add `tableId` prop to each `<DataTable>` for filter persistence
- [ ] Use `<DataTable>` component in pages
- [ ] Test: global search, column filters, sorting, grouping, pagination, visibility toggle
- [ ] Test: filter persistence across navigation (apply filters, navigate away, return)

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Filters applied but no rows visible | **CRITICAL**: Apply `filterFn` to columns BEFORE passing to `useReactTable()` using `columnsWithFilter` memo. Do NOT use `useEffect` to set filter function after table creation. |
| Persisted filters not restoring | Ensure `tableId` prop is passed to DataTable and `persistFilters` is not set to `false` |
| Grouping breaks pagination | Use `manualPagination: isGrouped` and custom `paginatedRows` logic |
| Empty counts in filter | Check that `getFacetedRowModel` and `getFacetedUniqueValues` are included |
| Page jump not working | Ensure input is synced with `currentPage` in useEffect |
| Reset doesn't clear persisted state | Call `clearPersistedState()` in the reset handler and pass `onReset` prop to toolbar |
| Operator dropdown not showing in Popover | Add `modal={false}` to the Popover component: `<Popover modal={false}>` |
| Comparison filter not working | Ensure the `parseDate()` helper and comparison logic are in the `arrayIncludesFilter` function |
| Comparison mode not appearing | Column type detection must identify the column as 'date' or 'number' - check sample values |

---

*This Table Filtering System (TFS) provides a complete, production-ready implementation that can be adapted to any React/Next.js application using TanStack Table and shadcn/ui.*
