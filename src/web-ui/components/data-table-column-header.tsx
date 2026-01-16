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
    Eye,
    Calculator,
    List,
} from "lucide-react"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Checkbox } from "@/components/ui/checkbox"
import {
    Popover,
    PopoverContent,
    PopoverTrigger,
} from "@/components/ui/popover"
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

interface DataTableColumnHeaderProps<TData, TValue>
    extends React.HTMLAttributes<HTMLDivElement> {
    column: Column<TData, TValue>
    title: string
}

export function DataTableColumnHeader<TData, TValue>({
    column,
    title,
    className,
}: DataTableColumnHeaderProps<TData, TValue>) {
    const [open, setOpen] = React.useState(false)
    const [searchValue, setSearchValue] = React.useState("")
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

    // Get unique values with counts
    const facetedUniqueValues = column.getFacetedUniqueValues()
    const allUniqueValues = React.useMemo(() => {
        const values: { value: string; count: number }[] = []
        facetedUniqueValues.forEach((count, value) => {
            values.push({ value: String(value ?? ""), count })
        })
        return values.sort((a, b) => b.count - a.count)
    }, [facetedUniqueValues])

    // Detect if column looks like dates or numbers (for showing comparison option)
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

    // Filter values based on search
    const filteredValues = React.useMemo(() => {
        if (!searchValue) return allUniqueValues
        return allUniqueValues.filter((item) =>
            item.value.toLowerCase().includes(searchValue.toLowerCase())
        )
    }, [allUniqueValues, searchValue])

    // Get currently selected values (for multi-select mode)
    const currentFilterValue = column.getFilterValue()
    const selectedValues = React.useMemo(() => {
        if (Array.isArray(currentFilterValue)) {
            return new Set(currentFilterValue as string[])
        }
        return new Set<string>()
    }, [currentFilterValue])

    // Check if using comparison filter
    const isComparisonFilter = currentFilterValue && 
        typeof currentFilterValue === 'object' && 
        'operator' in currentFilterValue

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

    const isFiltered = selectedValues.size > 0 || isComparisonFilter
    const totalCount = allUniqueValues.reduce((acc, v) => acc + v.count, 0)
    const selectedCount = allUniqueValues
        .filter((v) => selectedValues.has(v.value))
        .reduce((acc, v) => acc + v.count, 0)

    if (!column.getCanSort() && !column.getCanFilter()) {
        return <div className={cn(className)}>{title}</div>
    }

    return (
        <div className={cn("flex items-center space-x-2", className)}>
            <Popover open={open} onOpenChange={setOpen} modal={false}>
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
                                {isComparisonFilter 
                                    ? `${(currentFilterValue as { operator: string }).operator}${(currentFilterValue as { value: string }).value}`
                                    : selectedValues.size
                                }
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
                                                            <span className="text-muted-foreground text-xs">{op.label.split(' ').slice(1).join(' ')}</span>
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
                                    {isComparisonFilter && (
                                        <div className="text-xs font-medium text-primary">
                                            Active: {title} {(currentFilterValue as { operator: string }).operator} {(currentFilterValue as { value: string }).value}
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Multi-select filter UI */}
                            {filterMode === 'multiselect' && (
                                <>
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

                                    {/* Search match actions - show when searching */}
                                    {searchValue && filteredValues.length > 0 && (
                                        <div className="flex gap-1 mb-3 p-2 bg-accent/50 rounded-md">
                                            <Button
                                                variant="default"
                                                size="sm"
                                                className="h-6 text-xs px-2 flex-1"
                                                onClick={() => {
                                                    // Add all matching values to selection
                                                    const matchingValues = filteredValues.map(v => v.value)
                                                    const newSelected = new Set([...selectedValues, ...matchingValues])
                                                    column.setFilterValue(Array.from(newSelected))
                                                }}
                                            >
                                                <Check className="h-3 w-3 mr-1" />
                                                Select {filteredValues.length} matching
                                            </Button>
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                className="h-6 text-xs px-2 flex-1"
                                                onClick={() => {
                                                    // Select all EXCEPT matching values
                                                    const matchingValues = new Set(filteredValues.map(v => v.value))
                                                    const nonMatching = allUniqueValues
                                                        .filter(v => !matchingValues.has(v.value))
                                                        .map(v => v.value)
                                                    column.setFilterValue(nonMatching.length > 0 ? nonMatching : undefined)
                                                }}
                                            >
                                                <EyeOff className="h-3 w-3 mr-1" />
                                                Exclude matching
                                            </Button>
                                        </div>
                                    )}

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
                                    {selectedValues.size > 0 && (
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
                                </>
                            )}
                        </div>
                    )}

                    {/* Footer */}
                    {isFiltered && (
                        <div className="p-2 border-t bg-muted/50">
                            <Button
                                variant="ghost"
                                size="sm"
                                className="w-full h-8 text-xs"
                                onClick={() => {
                                    selectNone()
                                    clearComparisonFilter()
                                }}
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

// Individual filter value item with hover actions
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
                        title="Show only this value"
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
                        title="Hide only this value"
                    >
                        <EyeOff className="h-3 w-3" />
                    </Button>
                </div>
            )}
        </div>
    )
}
