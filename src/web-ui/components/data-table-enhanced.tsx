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
} from "@tanstack/react-table"
import { ChevronRight, ChevronDown, Layers } from "lucide-react"

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

interface DataTableProps<TData, TValue> {
    columns: ColumnDef<TData, TValue>[]
    data: TData[]
    searchKey?: string
    searchPlaceholder?: string
    enableGrouping?: boolean
    defaultGrouping?: string[]
    initialPageSize?: number
}

export function DataTable<TData, TValue>({
    columns,
    data,
    searchKey,
    searchPlaceholder,
    enableGrouping = false,
    defaultGrouping = [],
    initialPageSize = 20,
}: DataTableProps<TData, TValue>) {
    const [sorting, setSorting] = React.useState<SortingState>([])
    const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
    const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>({})
    const [globalFilter, setGlobalFilter] = React.useState("")
    const [grouping, setGrouping] = React.useState<GroupingState>(defaultGrouping)
    const [expanded, setExpanded] = React.useState<ExpandedState>({})
    const [groupByColumn, setGroupByColumn] = React.useState<string | undefined>(
        defaultGrouping.length > 0 ? defaultGrouping[0] : undefined
    )

    // Update grouping when groupByColumn changes
    React.useEffect(() => {
        setGrouping(groupByColumn ? [groupByColumn] : [])
        setExpanded({}) // Reset expanded state when grouping changes
    }, [groupByColumn])

    const table = useReactTable({
        data,
        columns,
        state: {
            sorting,
            columnVisibility,
            columnFilters,
            globalFilter,
            grouping,
            expanded,
        },
        initialState: {
            pagination: {
                pageSize: initialPageSize,
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
        getCoreRowModel: getCoreRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getFacetedRowModel: getFacetedRowModel(),
        getFacetedUniqueValues: getFacetedUniqueValues(),
        getGroupedRowModel: enableGrouping ? getGroupedRowModel() : undefined,
        getExpandedRowModel: enableGrouping ? getExpandedRowModel() : undefined,
        // Custom filter function that supports array filters (for multi-select)
        filterFns: {
            arrIncludesSome: (row, columnId, filterValue: string[]) => {
                const value = row.getValue(columnId)
                return filterValue.includes(String(value))
            },
        },
        globalFilterFn: "includesString",
    })

    // Override column filter function for array-based filtering
    React.useEffect(() => {
        table.getAllColumns().forEach((column) => {
            if (column.getCanFilter()) {
                column.columnDef.filterFn = (row, columnId, filterValue) => {
                    if (!filterValue || (Array.isArray(filterValue) && filterValue.length === 0)) {
                        return true
                    }
                    const value = String(row.getValue(columnId))
                    if (Array.isArray(filterValue)) {
                        return filterValue.includes(value)
                    }
                    return value.toLowerCase().includes(String(filterValue).toLowerCase())
                }
            }
        })
    }, [table])

    return (
        <div className="space-y-4">
            {/* Enhanced Toolbar */}
            <DataTableToolbar
                table={table}
                searchPlaceholder={searchPlaceholder || `Search ${data.length.toLocaleString()} rows...`}
                groupByColumn={enableGrouping ? groupByColumn : undefined}
                onGroupByChange={enableGrouping ? setGroupByColumn : undefined}
            />

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
                                        style={{
                                            width: header.getSize() !== 150 ? header.getSize() : undefined,
                                        }}
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
                        {table.getRowModel().rows?.length ? (
                            table.getRowModel().rows.map((row) => (
                                <GroupedTableRow
                                    key={row.id}
                                    row={row}
                                    enableGrouping={enableGrouping}
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

            {/* Pagination */}
            <DataTablePagination table={table} />
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
            style={{
                paddingLeft: enableGrouping && depth > 0 ? `${depth * 1.5}rem` : undefined,
            }}
        >
            {row.getVisibleCells().map((cell) => (
                <TableCell key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </TableCell>
            ))}
        </TableRow>
    )
}
