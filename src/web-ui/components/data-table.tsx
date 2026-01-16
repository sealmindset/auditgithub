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
import { useSearchParams, useRouter, usePathname } from "next/navigation"
import { ChevronRight, ChevronDown, Layers, ChevronUp, ChevronsUpDown, ChevronLeft, ChevronsLeft, ChevronsRight } from "lucide-react"

import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import { DataTablePagination } from "./data-table-pagination"
import { DataTableToolbar } from "./data-table-toolbar"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Input } from "@/components/ui/input"
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"

// Helper to safely access localStorage
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

interface DataTableProps<TData, TValue> {
    columns: ColumnDef<TData, TValue>[]
    data: TData[]
    tableId?: string // Unique ID for persisting filters (e.g., "findings", "repositories")
    searchKey?: string
    searchPlaceholder?: string
    enableGrouping?: boolean
    defaultGrouping?: string[]
    initialPageSize?: number
    maxGroupedHeight?: number // Max height in pixels when grouped (for scroll)
    persistFilters?: boolean // Whether to persist filters in localStorage
}

export function DataTable<TData, TValue>({
    columns,
    data,
    tableId,
    searchKey,
    searchPlaceholder,
    enableGrouping = true,
    defaultGrouping = [],
    initialPageSize = 20,
    maxGroupedHeight = 600,
    persistFilters = true,
}: DataTableProps<TData, TValue>) {
    const router = useRouter()
    const pathname = usePathname()
    const searchParams = useSearchParams()
    
    // Storage key for this table
    const storageKey = tableId ? `table-filters-${tableId}` : null

    // Load persisted state from localStorage
    const loadPersistedState = React.useCallback(() => {
        if (!storageKey || !persistFilters) return null
        const stored = getStorageItem(storageKey)
        if (!stored) return null
        try {
            const parsed = JSON.parse(stored)
            
            // Get valid column IDs from current columns definition
            const validColumnIds = new Set(
                columns.map(col => {
                    if ('accessorKey' in col && col.accessorKey) return String(col.accessorKey)
                    if ('id' in col && col.id) return col.id
                    return null
                }).filter(Boolean)
            )
            
            // Filter out invalid column references from persisted state
            if (parsed.sorting) {
                parsed.sorting = parsed.sorting.filter((s: any) => validColumnIds.has(s.id))
            }
            if (parsed.columnFilters) {
                parsed.columnFilters = parsed.columnFilters.filter((f: any) => validColumnIds.has(f.id))
            }
            if (parsed.columnVisibility) {
                const validVisibility: Record<string, boolean> = {}
                for (const [key, value] of Object.entries(parsed.columnVisibility)) {
                    if (validColumnIds.has(key)) {
                        validVisibility[key] = value as boolean
                    }
                }
                parsed.columnVisibility = validVisibility
            }
            if (parsed.groupByColumn && !validColumnIds.has(parsed.groupByColumn)) {
                parsed.groupByColumn = undefined
            }
            if (parsed.grouping) {
                parsed.grouping = parsed.grouping.filter((g: string) => validColumnIds.has(g))
            }
            
            return parsed
        } catch {
            return null
        }
    }, [storageKey, persistFilters, columns])

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

    // Track if we're in grouped mode
    const isGrouped = groupByColumn !== undefined

    // Update grouping when groupByColumn changes
    React.useEffect(() => {
        setGrouping(groupByColumn ? [groupByColumn] : [])
        setExpanded({})
    }, [groupByColumn])

    // Memoize columns with the correct filter function applied
    const columnsWithFilter = React.useMemo(() => {
        return columns.map(col => ({
            ...col,
            filterFn: arrayIncludesFilter,
        }))
    }, [columns])

    const table = useReactTable({
        data,
        columns: columnsWithFilter,
        state: {
            sorting,
            columnVisibility,
            columnFilters,
            globalFilter,
            grouping,
            expanded,
            pagination: {
                pageIndex,
                pageSize,
            },
        },
        enableRowSelection: true,
        enableGrouping: enableGrouping,
        onSortingChange: setSorting,
        onColumnFiltersChange: setColumnFilters,
        onColumnVisibilityChange: setColumnVisibility,
        onGlobalFilterChange: setGlobalFilter,
        onGroupingChange: setGrouping,
        onExpandedChange: setExpanded,
        onPaginationChange: (updater) => {
            const newState = typeof updater === 'function' 
                ? updater({ pageIndex, pageSize }) 
                : updater
            setPageIndex(newState.pageIndex)
            setPageSize(newState.pageSize)
        },
        getCoreRowModel: getCoreRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getFacetedRowModel: getFacetedRowModel(),
        getFacetedUniqueValues: getFacetedUniqueValues(),
        getGroupedRowModel: enableGrouping ? getGroupedRowModel() : undefined,
        getExpandedRowModel: enableGrouping ? getExpandedRowModel() : undefined,
        globalFilterFn: "includesString",
        filterFns: {
            arrayIncludes: arrayIncludesFilter,
        },
        // Use manual pagination when grouped so we can control it
        manualPagination: isGrouped,
    })

    // Get all rows from the expanded row model (includes group headers and their children)
    const allExpandedRows = React.useMemo(() => {
        if (!isGrouped) return []
        return table.getExpandedRowModel().rows
    }, [table, isGrouped, expanded, sorting, columnFilters, globalFilter])

    // Custom pagination for grouped mode that keeps groups together
    const paginatedRows = React.useMemo(() => {
        if (!isGrouped) {
            // Normal pagination handled by TanStack
            return table.getRowModel().rows
        }

        // For grouped mode: paginate by groups, not individual rows
        // But when a group is expanded, include ALL its children (exceeding page limit if needed)
        const groupRows = allExpandedRows.filter(row => row.depth === 0)
        const startIdx = pageIndex * pageSize
        const endIdx = startIdx + pageSize

        // Get groups for this page
        const pageGroups = groupRows.slice(startIdx, Math.min(endIdx, groupRows.length))
        
        // Build the final row list including expanded children
        const result: Row<TData>[] = []
        
        pageGroups.forEach((groupRow) => {
            result.push(groupRow)
            // If this group is expanded, add ALL its children (this is the "exception" - exceed limit)
            if (groupRow.getIsExpanded() && groupRow.subRows) {
                result.push(...groupRow.subRows)
            }
        })

        return result
    }, [isGrouped, allExpandedRows, pageIndex, pageSize, expanded, table])

    // Calculate total pages for grouped mode
    const totalGroupCount = React.useMemo(() => {
        if (!isGrouped) return 0
        return allExpandedRows.filter(row => row.depth === 0).length
    }, [isGrouped, allExpandedRows])

    const totalPages = isGrouped 
        ? Math.ceil(totalGroupCount / pageSize)
        : table.getPageCount()

    // Count items on current page
    const currentPageItemCount = paginatedRows.filter(r => !r.getIsGrouped()).length
    const currentPageGroupCount = paginatedRows.filter(r => r.getIsGrouped()).length

    // Navigation handlers for grouped mode
    const canPreviousPage = pageIndex > 0
    const canNextPage = pageIndex < totalPages - 1

    const goToNextPage = () => {
        if (canNextPage) setPageIndex(pageIndex + 1)
    }

    const goToPreviousPage = () => {
        if (canPreviousPage) setPageIndex(pageIndex - 1)
    }

    const goToFirstPage = () => setPageIndex(0)
    const goToLastPage = () => setPageIndex(totalPages - 1)

    // Reset page when filters change
    React.useEffect(() => {
        setPageIndex(0)
    }, [columnFilters, globalFilter, groupByColumn])

    const totalFilteredRows = table.getFilteredRowModel().rows.length

    // Clear persisted state
    const clearPersistedState = React.useCallback(() => {
        if (storageKey) {
            try {
                localStorage.removeItem(storageKey)
            } catch {
                // Ignore storage errors
            }
        }
    }, [storageKey])

    return (
        <div className="space-y-4">
            {/* Enhanced Toolbar */}
            <DataTableToolbar
                table={table}
                searchPlaceholder={searchPlaceholder || `Search ${data.length.toLocaleString()} rows...`}
                groupByColumn={enableGrouping ? groupByColumn : undefined}
                onGroupByChange={enableGrouping ? setGroupByColumn : undefined}
                onReset={clearPersistedState}
                initialGlobalFilter={globalFilter}
            />

            {/* Grouped mode info bar */}
            {isGrouped && (
                <div className="flex items-center justify-between px-3 py-2 bg-muted/50 rounded-lg text-sm">
                    <div className="flex items-center gap-2">
                        <Layers className="h-4 w-4 text-primary" />
                        <span>
                            Page {pageIndex + 1} of {totalPages} •{" "}
                            <strong>{currentPageGroupCount}</strong> groups •{" "}
                            <strong>{currentPageItemCount}</strong> items shown
                            {currentPageItemCount > pageSize && (
                                <Badge variant="outline" className="ml-2 text-xs">
                                    Expanded group exceeds limit
                                </Badge>
                            )}
                        </span>
                    </div>
                    <div className="flex items-center gap-2">
                        <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => setExpanded(true)}
                        >
                            <ChevronsUpDown className="h-3 w-3 mr-1" />
                            Expand All
                        </Button>
                        <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => setExpanded({})}
                        >
                            <ChevronUp className="h-3 w-3 mr-1" />
                            Collapse All
                        </Button>
                    </div>
                </div>
            )}

            {/* Table */}
            <div className="rounded-md border overflow-hidden">
                <Table>
                    <TableHeader className="bg-muted/50">
                        {table.getHeaderGroups().map((headerGroup) => (
                            <TableRow key={headerGroup.id}>
                                {headerGroup.headers.map((header) => (
                                    <TableHead
                                        key={header.id}
                                        className="whitespace-nowrap"
                                    >
                                        {header.isPlaceholder
                                            ? null
                                            : flexRender(
                                                header.column.columnDef.header,
                                                header.getContext()
                                            )}
                                    </TableHead>
                                ))}
                            </TableRow>
                        ))}
                    </TableHeader>
                    <TableBody>
                        {paginatedRows?.length ? (
                            paginatedRows.map((row) => (
                                <GroupedTableRow
                                    key={row.id}
                                    row={row}
                                    enableGrouping={enableGrouping && groupByColumn !== undefined}
                                />
                            ))
                        ) : (
                            <TableRow>
                                <TableCell
                                    colSpan={columns.length}
                                    className="h-24 text-center"
                                >
                                    No results found.
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </div>

            {/* Pagination - custom for grouped, standard for non-grouped */}
            {isGrouped ? (
                <GroupedPagination
                    pageIndex={pageIndex}
                    pageSize={pageSize}
                    totalPages={totalPages}
                    totalGroups={totalGroupCount}
                    totalItems={totalFilteredRows}
                    canPreviousPage={canPreviousPage}
                    canNextPage={canNextPage}
                    goToFirstPage={goToFirstPage}
                    goToPreviousPage={goToPreviousPage}
                    goToNextPage={goToNextPage}
                    goToLastPage={goToLastPage}
                    goToPage={setPageIndex}
                    setPageSize={(size) => {
                        setPageSize(size)
                        setPageIndex(0)
                    }}
                />
            ) : (
                <DataTablePagination table={table} />
            )}
        </div>
    )
}

// Grouped row component
function GroupedTableRow<TData>({
    row,
    enableGrouping,
}: {
    row: Row<TData>
    enableGrouping: boolean
}) {
    const isGrouped = row.getIsGrouped()
    const isExpanded = row.getIsExpanded()
    const depth = row.depth

    if (isGrouped) {
        return (
            <TableRow
                className={cn(
                    "bg-muted/30 hover:bg-muted/50 cursor-pointer font-medium",
                    depth > 0 && "bg-muted/20"
                )}
                onClick={() => row.toggleExpanded()}
            >
                <TableCell colSpan={row.getVisibleCells().length}>
                    <div
                        className="flex items-center gap-2"
                        style={{ paddingLeft: `${depth * 1.5}rem` }}
                    >
                        <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                            {isExpanded ? (
                                <ChevronDown className="h-4 w-4" />
                            ) : (
                                <ChevronRight className="h-4 w-4" />
                            )}
                        </Button>
                        <Layers className="h-4 w-4 text-muted-foreground" />
                        <span className="font-semibold">
                            {String(row.groupingValue) || "(empty)"}
                        </span>
                        <Badge variant="secondary" className="ml-2">
                            {row.subRows.length} items
                        </Badge>
                    </div>
                </TableCell>
            </TableRow>
        )
    }

    return (
        <TableRow
            data-state={row.getIsSelected() && "selected"}
        >
            {row.getVisibleCells().map((cell) => (
                <TableCell key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </TableCell>
            ))}
        </TableRow>
    )
}

// Grouped mode pagination component
interface GroupedPaginationProps {
    pageIndex: number
    pageSize: number
    totalPages: number
    totalGroups: number
    totalItems: number
    canPreviousPage: boolean
    canNextPage: boolean
    goToFirstPage: () => void
    goToPreviousPage: () => void
    goToNextPage: () => void
    goToLastPage: () => void
    goToPage: (page: number) => void
    setPageSize: (size: number) => void
}

function GroupedPagination({
    pageIndex,
    pageSize,
    totalPages,
    totalGroups,
    totalItems,
    canPreviousPage,
    canNextPage,
    goToFirstPage,
    goToPreviousPage,
    goToNextPage,
    goToLastPage,
    goToPage,
    setPageSize,
}: GroupedPaginationProps) {
    const currentPage = pageIndex + 1
    const [inputValue, setInputValue] = React.useState(String(currentPage))

    // Sync input with actual page when it changes externally
    React.useEffect(() => {
        setInputValue(String(currentPage))
    }, [currentPage])

    const handlePageInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setInputValue(e.target.value)
    }

    const handlePageInputBlur = () => {
        const page = parseInt(inputValue, 10)
        if (!isNaN(page) && page >= 1 && page <= totalPages) {
            goToPage(page - 1)
        } else {
            setInputValue(String(currentPage))
        }
    }

    const handlePageInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Enter') {
            handlePageInputBlur()
            ;(e.target as HTMLInputElement).blur()
        } else if (e.key === 'Escape') {
            setInputValue(String(currentPage))
            ;(e.target as HTMLInputElement).blur()
        }
    }

    return (
        <div className="flex items-center justify-between px-2">
            <div className="flex-1 text-sm text-muted-foreground">
                {totalGroups} groups • {totalItems.toLocaleString()} total items
            </div>
            <div className="flex items-center space-x-6 lg:space-x-8">
                <div className="flex items-center space-x-2">
                    <p className="text-sm font-medium">Groups per page</p>
                    <Select
                        value={`${pageSize}`}
                        onValueChange={(value) => setPageSize(Number(value))}
                    >
                        <SelectTrigger className="h-8 w-[70px]">
                            <SelectValue placeholder={pageSize} />
                        </SelectTrigger>
                        <SelectContent side="top">
                            {[10, 20, 30, 50, 100].map((size) => (
                                <SelectItem key={size} value={`${size}`}>
                                    {size}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                </div>
                <div className="flex items-center space-x-2 text-sm font-medium">
                    <span>Page</span>
                    <Input
                        type="text"
                        inputMode="numeric"
                        pattern="[0-9]*"
                        value={inputValue}
                        onChange={handlePageInputChange}
                        onBlur={handlePageInputBlur}
                        onKeyDown={handlePageInputKeyDown}
                        className="h-8 w-14 text-center"
                    />
                    <span>of {totalPages}</span>
                </div>
                <div className="flex items-center space-x-2">
                    <Button
                        variant="outline"
                        className="hidden h-8 w-8 p-0 lg:flex"
                        onClick={goToFirstPage}
                        disabled={!canPreviousPage}
                    >
                        <span className="sr-only">Go to first page</span>
                        <ChevronsLeft className="h-4 w-4" />
                    </Button>
                    <Button
                        variant="outline"
                        className="h-8 w-8 p-0"
                        onClick={goToPreviousPage}
                        disabled={!canPreviousPage}
                    >
                        <span className="sr-only">Go to previous page</span>
                        <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <Button
                        variant="outline"
                        className="h-8 w-8 p-0"
                        onClick={goToNextPage}
                        disabled={!canNextPage}
                    >
                        <span className="sr-only">Go to next page</span>
                        <ChevronRight className="h-4 w-4" />
                    </Button>
                    <Button
                        variant="outline"
                        className="hidden h-8 w-8 p-0 lg:flex"
                        onClick={goToLastPage}
                        disabled={!canNextPage}
                    >
                        <span className="sr-only">Go to last page</span>
                        <ChevronsRight className="h-4 w-4" />
                    </Button>
                </div>
            </div>
        </div>
    )
}
