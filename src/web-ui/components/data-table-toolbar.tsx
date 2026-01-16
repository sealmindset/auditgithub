"use client"

import * as React from "react"
import { Table } from "@tanstack/react-table"
import {
    Settings2,
    Eye,
    EyeOff,
    Columns3,
    RotateCcw,
    Search,
    X,
    Filter,
    Download,
    Layers,
} from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import {
    Popover,
    PopoverContent,
    PopoverTrigger,
} from "@/components/ui/popover"
import {
    DropdownMenu,
    DropdownMenuCheckboxItem,
    DropdownMenuContent,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { cn } from "@/lib/utils"

interface DataTableToolbarProps<TData> {
    table: Table<TData>
    searchKey?: string
    searchPlaceholder?: string
    filterableColumns?: {
        id: string
        title: string
        options?: { label: string; value: string }[]
    }[]
    groupByColumn?: string
    onGroupByChange?: (columnId: string | undefined) => void
    onReset?: () => void // Called when reset button is clicked (for clearing persisted state)
    initialGlobalFilter?: string // Initial value for global filter (from persisted state)
}

export function DataTableToolbar<TData>({
    table,
    searchKey,
    searchPlaceholder = "Search all columns...",
    filterableColumns = [],
    groupByColumn,
    onGroupByChange,
    onReset,
    initialGlobalFilter = "",
}: DataTableToolbarProps<TData>) {
    const [globalFilter, setGlobalFilter] = React.useState(initialGlobalFilter)

    // Sync with table's global filter on mount
    React.useEffect(() => {
        if (initialGlobalFilter) {
            table.setGlobalFilter(initialGlobalFilter)
        }
    }, []) // Only on mount

    // Count active filters
    const activeFilterCount = table.getState().columnFilters.length
    const hiddenColumnCount = Object.values(table.getState().columnVisibility).filter(
        (v) => v === false
    ).length

    // Get all columns that can be hidden
    const allColumns = table.getAllColumns().filter((column) => column.getCanHide())

    // Reset all filters and visibility
    const resetAll = () => {
        table.resetColumnFilters()
        table.resetColumnVisibility()
        table.resetSorting()
        setGlobalFilter("")
        table.setGlobalFilter("")
        onGroupByChange?.(undefined)
        onReset?.() // Clear persisted state
    }

    // Check if any customizations are active
    const hasCustomizations =
        activeFilterCount > 0 ||
        hiddenColumnCount > 0 ||
        table.getState().sorting.length > 0 ||
        globalFilter !== "" ||
        groupByColumn !== undefined

    return (
        <div className="flex flex-col gap-4">
            {/* Main toolbar row */}
            <div className="flex items-center justify-between gap-4">
                {/* Left side: Search */}
                <div className="flex items-center gap-2 flex-1">
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
                                className="absolute right-1 top-1 h-7 w-7 p-0"
                                onClick={() => {
                                    setGlobalFilter("")
                                    table.setGlobalFilter("")
                                }}
                            >
                                <X className="h-4 w-4" />
                            </Button>
                        )}
                    </div>

                    {/* Active filter badges */}
                    {activeFilterCount > 0 && (
                        <div className="flex items-center gap-1">
                            <Badge variant="secondary" className="gap-1">
                                <Filter className="h-3 w-3" />
                                {activeFilterCount} filter{activeFilterCount > 1 ? "s" : ""}
                            </Badge>
                        </div>
                    )}
                </div>

                {/* Right side: Controls */}
                <div className="flex items-center gap-2">
                    {/* Group By Selector */}
                    {onGroupByChange && (
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button variant="outline" size="sm" className="h-9">
                                    <Layers className="h-4 w-4 mr-2" />
                                    {groupByColumn ? (
                                        <>
                                            Grouped by{" "}
                                            <Badge variant="secondary" className="ml-1">
                                                {groupByColumn}
                                            </Badge>
                                        </>
                                    ) : (
                                        "Group By"
                                    )}
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-[180px]">
                                <DropdownMenuLabel>Group rows by</DropdownMenuLabel>
                                <DropdownMenuSeparator />
                                {groupByColumn && (
                                    <>
                                        <DropdownMenuCheckboxItem
                                            checked={false}
                                            onCheckedChange={() => onGroupByChange(undefined)}
                                        >
                                            No grouping
                                        </DropdownMenuCheckboxItem>
                                        <DropdownMenuSeparator />
                                    </>
                                )}
                                {allColumns.slice(0, 10).map((column) => (
                                    <DropdownMenuCheckboxItem
                                        key={column.id}
                                        checked={groupByColumn === column.id}
                                        onCheckedChange={(checked) =>
                                            onGroupByChange(checked ? column.id : undefined)
                                        }
                                    >
                                        {column.id
                                            .replace(/_/g, " ")
                                            .replace(/([A-Z])/g, " $1")
                                            .trim()}
                                    </DropdownMenuCheckboxItem>
                                ))}
                            </DropdownMenuContent>
                        </DropdownMenu>
                    )}

                    {/* Column Visibility */}
                    <ColumnVisibilityDropdown table={table} />

                    {/* Reset button - always visible for clearing stale filters */}
                    <Button
                        variant={hasCustomizations ? "outline" : "ghost"}
                        size="sm"
                        className={cn("h-9", hasCustomizations && "border-orange-300 text-orange-600 hover:bg-orange-50")}
                        onClick={resetAll}
                        title="Reset all filters, sorting, and column visibility"
                    >
                        <RotateCcw className="h-4 w-4 mr-2" />
                        Reset
                        {hasCustomizations && (
                            <Badge variant="secondary" className="ml-1 bg-orange-100 text-orange-700">
                                Active
                            </Badge>
                        )}
                    </Button>
                </div>
            </div>

            {/* Hidden columns indicator */}
            {hiddenColumnCount > 0 && (
                <HiddenColumnsBar table={table} />
            )}
        </div>
    )
}

// Column Visibility Dropdown
function ColumnVisibilityDropdown<TData>({ table }: { table: Table<TData> }) {
    const columns = table.getAllColumns().filter((column) => column.getCanHide())
    const hiddenCount = columns.filter((col) => !col.getIsVisible()).length

    return (
        <Popover>
            <PopoverTrigger asChild>
                <Button variant="outline" size="sm" className="h-9">
                    <Columns3 className="h-4 w-4 mr-2" />
                    Columns
                    {hiddenCount > 0 && (
                        <Badge variant="secondary" className="ml-2">
                            {columns.length - hiddenCount}/{columns.length}
                        </Badge>
                    )}
                </Button>
            </PopoverTrigger>
            <PopoverContent align="end" className="w-[250px] p-0">
                <div className="p-3 border-b">
                    <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">Toggle columns</span>
                        <div className="flex gap-1">
                            <Button
                                variant="ghost"
                                size="sm"
                                className="h-6 px-2 text-xs"
                                onClick={() => {
                                    columns.forEach((col) => col.toggleVisibility(true))
                                }}
                            >
                                Show all
                            </Button>
                        </div>
                    </div>
                </div>
                <ScrollArea className="h-[300px]">
                    <div className="p-2">
                        {columns.map((column) => {
                            const isVisible = column.getIsVisible()
                            const title = column.id
                                .replace(/_/g, " ")
                                .replace(/([A-Z])/g, " $1")
                                .trim()

                            return (
                                <div
                                    key={column.id}
                                    className={cn(
                                        "flex items-center justify-between rounded-sm px-2 py-1.5 hover:bg-accent cursor-pointer",
                                        !isVisible && "opacity-60"
                                    )}
                                    onClick={() => column.toggleVisibility(!isVisible)}
                                >
                                    <span className="text-sm capitalize">{title}</span>
                                    <div className="flex items-center">
                                        {isVisible ? (
                                            <Eye className="h-4 w-4 text-primary" />
                                        ) : (
                                            <EyeOff className="h-4 w-4 text-muted-foreground" />
                                        )}
                                    </div>
                                </div>
                            )
                        })}
                    </div>
                </ScrollArea>
            </PopoverContent>
        </Popover>
    )
}

// Hidden columns quick-restore bar
function HiddenColumnsBar<TData>({ table }: { table: Table<TData> }) {
    const hiddenColumns = table
        .getAllColumns()
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
                        className="cursor-pointer hover:bg-primary hover:text-primary-foreground transition-colors"
                        onClick={() => column.toggleVisibility(true)}
                    >
                        {column.id.replace(/_/g, " ").replace(/([A-Z])/g, " $1").trim()}
                        <Eye className="h-3 w-3 ml-1" />
                    </Badge>
                ))}
            </div>
            <Button
                variant="ghost"
                size="sm"
                className="h-6 ml-auto text-xs"
                onClick={() => hiddenColumns.forEach((col) => col.toggleVisibility(true))}
            >
                Show all
            </Button>
        </div>
    )
}
