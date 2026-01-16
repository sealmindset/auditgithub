"use client"

import * as React from "react"
import { Column } from "@tanstack/react-table"
import {
    ArrowDown,
    ArrowUp,
    ChevronsUpDown,
    EyeOff,
    Filter,
    Search,
    X,
    Check,
    ListFilter,
    Eye,
} from "lucide-react"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import {
    Popover,
    PopoverContent,
    PopoverTrigger,
} from "@/components/ui/popover"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import {
    Tabs,
    TabsContent,
    TabsList,
    TabsTrigger,
} from "@/components/ui/tabs"

interface AdvancedColumnFilterProps<TData, TValue>
    extends React.HTMLAttributes<HTMLDivElement> {
    column: Column<TData, TValue>
    title: string
}

export function AdvancedColumnFilter<TData, TValue>({
    column,
    title,
    className,
}: AdvancedColumnFilterProps<TData, TValue>) {
    const [open, setOpen] = React.useState(false)
    const [searchValue, setSearchValue] = React.useState("")
    const [filterMode, setFilterMode] = React.useState<"include" | "exclude">("include")

    // Get unique values with counts
    const facetedUniqueValues = column.getFacetedUniqueValues()
    const allUniqueValues = React.useMemo(() => {
        const values: { value: string; count: number }[] = []
        facetedUniqueValues.forEach((count, value) => {
            values.push({ value: String(value), count })
        })
        return values.sort((a, b) => b.count - a.count) // Sort by count descending
    }, [facetedUniqueValues])

    // Filter values based on search
    const filteredValues = React.useMemo(() => {
        if (!searchValue) return allUniqueValues
        return allUniqueValues.filter((item) =>
            item.value.toLowerCase().includes(searchValue.toLowerCase())
        )
    }, [allUniqueValues, searchValue])

    // Get currently selected values
    const currentFilterValue = column.getFilterValue()
    const selectedValues = React.useMemo(() => {
        if (Array.isArray(currentFilterValue)) {
            return new Set(currentFilterValue as string[])
        }
        return new Set<string>()
    }, [currentFilterValue])

    // Handlers
    const toggleValue = (value: string) => {
        const newSelected = new Set(selectedValues)
        if (newSelected.has(value)) {
            newSelected.delete(value)
        } else {
            newSelected.add(value)
        }
        column.setFilterValue(newSelected.size > 0 ? Array.from(newSelected) : undefined)
    }

    const selectAll = () => {
        column.setFilterValue(allUniqueValues.map((v) => v.value))
    }

    const selectNone = () => {
        column.setFilterValue(undefined)
    }

    const selectOnly = (value: string) => {
        column.setFilterValue([value])
    }

    const selectAllExcept = (value: string) => {
        const values = allUniqueValues.filter((v) => v.value !== value).map((v) => v.value)
        column.setFilterValue(values.length > 0 ? values : undefined)
    }

    const invertSelection = () => {
        const currentSelected = Array.from(selectedValues)
        const inverted = allUniqueValues
            .map((v) => v.value)
            .filter((v) => !currentSelected.includes(v))
        column.setFilterValue(inverted.length > 0 ? inverted : undefined)
    }

    const isFiltered = selectedValues.size > 0
    const totalCount = allUniqueValues.reduce((acc, v) => acc + v.count, 0)
    const selectedCount = allUniqueValues
        .filter((v) => selectedValues.has(v.value))
        .reduce((acc, v) => acc + v.count, 0)

    if (!column.getCanSort() && !column.getCanFilter()) {
        return <div className={cn(className)}>{title}</div>
    }

    return (
        <div className={cn("flex items-center space-x-2", className)}>
            <Popover open={open} onOpenChange={setOpen}>
                <PopoverTrigger asChild>
                    <Button
                        variant="ghost"
                        size="sm"
                        className="-ml-3 h-8 data-[state=open]:bg-accent"
                    >
                        <span className="font-medium">{title}</span>
                        {column.getIsSorted() === "desc" ? (
                            <ArrowDown className="ml-2 h-4 w-4" />
                        ) : column.getIsSorted() === "asc" ? (
                            <ArrowUp className="ml-2 h-4 w-4" />
                        ) : (
                            <ChevronsUpDown className="ml-2 h-4 w-4 opacity-50" />
                        )}
                        {isFiltered && (
                            <Badge
                                variant="secondary"
                                className="ml-2 h-5 rounded-sm px-1.5 font-mono text-[10px] bg-primary text-primary-foreground"
                            >
                                {selectedValues.size}
                            </Badge>
                        )}
                    </Button>
                </PopoverTrigger>
                <PopoverContent className="w-[320px] p-0" align="start">
                    {/* Header with sorting */}
                    <div className="p-3 border-b">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-semibold">{title}</span>
                            {column.getCanHide() && (
                                <Button
                                    variant="ghost"
                                    size="sm"
                                    className="h-7 px-2 text-muted-foreground"
                                    onClick={() => {
                                        column.toggleVisibility(false)
                                        setOpen(false)
                                    }}
                                >
                                    <EyeOff className="h-3.5 w-3.5 mr-1" />
                                    Hide
                                </Button>
                            )}
                        </div>

                        {column.getCanSort() && (
                            <div className="flex gap-1">
                                <Button
                                    variant={column.getIsSorted() === "asc" ? "default" : "outline"}
                                    size="sm"
                                    className="h-7 flex-1 text-xs"
                                    onClick={() => column.toggleSorting(false)}
                                >
                                    <ArrowUp className="h-3 w-3 mr-1" />
                                    Sort A→Z
                                </Button>
                                <Button
                                    variant={column.getIsSorted() === "desc" ? "default" : "outline"}
                                    size="sm"
                                    className="h-7 flex-1 text-xs"
                                    onClick={() => column.toggleSorting(true)}
                                >
                                    <ArrowDown className="h-3 w-3 mr-1" />
                                    Sort Z→A
                                </Button>
                                {column.getIsSorted() && (
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        className="h-7 px-2"
                                        onClick={() => column.clearSorting()}
                                    >
                                        <X className="h-3 w-3" />
                                    </Button>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Filter section */}
                    {column.getCanFilter() && allUniqueValues.length > 0 && (
                        <div className="p-3">
                            {/* Search input */}
                            <div className="relative mb-3">
                                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                                <Input
                                    placeholder={`Search ${allUniqueValues.length} values...`}
                                    value={searchValue}
                                    onChange={(e) => setSearchValue(e.target.value)}
                                    className="h-9 pl-8 pr-8"
                                />
                                {searchValue && (
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        className="absolute right-1 top-1 h-7 w-7 p-0"
                                        onClick={() => setSearchValue("")}
                                    >
                                        <X className="h-3 w-3" />
                                    </Button>
                                )}
                            </div>

                            {/* Quick actions */}
                            <div className="flex flex-wrap gap-1 mb-3">
                                <Button
                                    variant="outline"
                                    size="sm"
                                    className="h-6 text-xs px-2"
                                    onClick={selectAll}
                                >
                                    Select All
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    className="h-6 text-xs px-2"
                                    onClick={selectNone}
                                >
                                    Clear
                                </Button>
                                {selectedValues.size > 0 && (
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        className="h-6 text-xs px-2"
                                        onClick={invertSelection}
                                    >
                                        Invert
                                    </Button>
                                )}
                            </div>

                            {/* Filter stats */}
                            {isFiltered && (
                                <div className="text-xs text-muted-foreground mb-2">
                                    Showing {selectedCount.toLocaleString()} of {totalCount.toLocaleString()} rows
                                </div>
                            )}

                            {/* Values list */}
                            <ScrollArea className="h-[240px] rounded border">
                                <div className="p-1">
                                    {filteredValues.length === 0 ? (
                                        <div className="py-6 text-center text-sm text-muted-foreground">
                                            No values match "{searchValue}"
                                        </div>
                                    ) : (
                                        filteredValues.map((item) => (
                                            <FilterValueItem
                                                key={item.value}
                                                value={item.value}
                                                count={item.count}
                                                isSelected={selectedValues.has(item.value)}
                                                onToggle={() => toggleValue(item.value)}
                                                onSelectOnly={() => selectOnly(item.value)}
                                                onSelectAllExcept={() => selectAllExcept(item.value)}
                                            />
                                        ))
                                    )}
                                </div>
                            </ScrollArea>
                        </div>
                    )}

                    {/* Footer */}
                    {isFiltered && (
                        <div className="p-2 border-t bg-muted/50">
                            <Button
                                variant="ghost"
                                size="sm"
                                className="w-full h-8 text-xs"
                                onClick={selectNone}
                            >
                                <X className="h-3 w-3 mr-1" />
                                Clear all filters
                            </Button>
                        </div>
                    )}
                </PopoverContent>
            </Popover>
        </div>
    )
}

// Individual filter value item with context menu
interface FilterValueItemProps {
    value: string
    count: number
    isSelected: boolean
    onToggle: () => void
    onSelectOnly: () => void
    onSelectAllExcept: () => void
}

function FilterValueItem({
    value,
    count,
    isSelected,
    onToggle,
    onSelectOnly,
    onSelectAllExcept,
}: FilterValueItemProps) {
    const [showActions, setShowActions] = React.useState(false)

    return (
        <div
            className={cn(
                "relative flex items-center rounded-sm px-2 py-1.5 text-sm cursor-pointer transition-colors",
                "hover:bg-accent",
                isSelected && "bg-accent/50"
            )}
            onMouseEnter={() => setShowActions(true)}
            onMouseLeave={() => setShowActions(false)}
        >
            <div
                className="flex items-center flex-1 min-w-0"
                onClick={onToggle}
            >
                <Checkbox
                    checked={isSelected}
                    className="mr-2 h-4 w-4"
                />
                <span className="truncate flex-1" title={value}>
                    {value || "(empty)"}
                </span>
                <span className="ml-2 text-xs text-muted-foreground tabular-nums">
                    {count.toLocaleString()}
                </span>
            </div>

            {/* Quick action buttons on hover */}
            {showActions && (
                <div className="absolute right-1 flex gap-0.5 bg-accent rounded px-1">
                    <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 hover:bg-primary hover:text-primary-foreground"
                        onClick={(e) => {
                            e.stopPropagation()
                            onSelectOnly()
                        }}
                        title="Show only this"
                    >
                        <Eye className="h-3 w-3" />
                    </Button>
                    <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 hover:bg-destructive hover:text-destructive-foreground"
                        onClick={(e) => {
                            e.stopPropagation()
                            onSelectAllExcept()
                        }}
                        title="Hide only this"
                    >
                        <EyeOff className="h-3 w-3" />
                    </Button>
                </div>
            )}
        </div>
    )
}
