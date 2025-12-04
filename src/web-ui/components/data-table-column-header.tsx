"use client"

import { Column } from "@tanstack/react-table"
import { ArrowDown, ArrowUp, ChevronsUpDown, EyeOff, Filter } from "lucide-react"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
    DropdownMenuCheckboxItem,
    DropdownMenuLabel,
} from "@/components/ui/dropdown-menu"
import { Badge } from "@/components/ui/badge"

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
    if (!column.getCanSort() && !column.getCanFilter()) {
        return <div className={cn(className)}>{title}</div>
    }

    // Get unique values for filtering
    const facetedUniqueValues = column.getFacetedUniqueValues()
    const uniqueValues = Array.from(facetedUniqueValues.keys()).sort().slice(0, 50) // Limit to 50 for performance
    const selectedValues = new Set(column.getFilterValue() as string[])

    const toggleFilter = (value: string) => {
        const newSelectedValues = new Set(selectedValues)
        if (newSelectedValues.has(value)) {
            newSelectedValues.delete(value)
        } else {
            newSelectedValues.add(value)
        }
        const filterValue = Array.from(newSelectedValues)
        column.setFilterValue(filterValue.length ? filterValue : undefined)
    }

    const clearFilter = () => {
        column.setFilterValue(undefined)
    }

    return (
        <div className={cn("flex items-center space-x-2", className)}>
            <DropdownMenu>
                <DropdownMenuTrigger asChild>
                    <Button
                        variant="ghost"
                        size="sm"
                        className="-ml-3 h-8 data-[state=open]:bg-accent"
                    >
                        <span>{title}</span>
                        {column.getIsSorted() === "desc" ? (
                            <ArrowDown className="ml-2 h-4 w-4" />
                        ) : column.getIsSorted() === "asc" ? (
                            <ArrowUp className="ml-2 h-4 w-4" />
                        ) : (
                            <ChevronsUpDown className="ml-2 h-4 w-4" />
                        )}
                        {selectedValues.size > 0 && (
                            <Badge variant="secondary" className="ml-2 h-5 rounded-sm px-1 font-mono text-[10px]">
                                {selectedValues.size}
                            </Badge>
                        )}
                    </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="w-[200px]">
                    {column.getCanSort() && (
                        <>
                            <DropdownMenuItem onClick={() => column.toggleSorting(false)}>
                                <ArrowUp className="mr-2 h-3.5 w-3.5 text-muted-foreground/70" />
                                Asc
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => column.toggleSorting(true)}>
                                <ArrowDown className="mr-2 h-3.5 w-3.5 text-muted-foreground/70" />
                                Desc
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                        </>
                    )}

                    {column.getCanHide() && (
                        <>
                            <DropdownMenuItem onClick={() => column.toggleVisibility(false)}>
                                <EyeOff className="mr-2 h-3.5 w-3.5 text-muted-foreground/70" />
                                Hide
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                        </>
                    )}

                    {column.getCanFilter() && uniqueValues.length > 0 && (
                        <>
                            <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                                Filter by value
                            </DropdownMenuLabel>
                            <div className="max-h-[200px] overflow-y-auto">
                                {uniqueValues.map((value: any) => (
                                    <DropdownMenuCheckboxItem
                                        key={value}
                                        checked={selectedValues.has(String(value))}
                                        onCheckedChange={() => toggleFilter(String(value))}
                                    >
                                        <span className="truncate">{String(value)}</span>
                                    </DropdownMenuCheckboxItem>
                                ))}
                            </div>
                            {selectedValues.size > 0 && (
                                <>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem onClick={clearFilter} className="justify-center text-center">
                                        Clear filters
                                    </DropdownMenuItem>
                                </>
                            )}
                        </>
                    )}
                </DropdownMenuContent>
            </DropdownMenu>
        </div>
    )
}
