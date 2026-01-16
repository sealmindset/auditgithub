"use client"

import * as React from "react"
import { Table } from "@tanstack/react-table"
import {
    ChevronLeft,
    ChevronRight,
    ChevronsLeft,
    ChevronsRight,
} from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

interface DataTablePaginationProps<TData> {
    table: Table<TData>
}

export function DataTablePagination<TData>({
    table,
}: DataTablePaginationProps<TData>) {
    const pageCount = table.getPageCount()
    const currentPage = table.getState().pagination.pageIndex + 1
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
        if (!isNaN(page) && page >= 1 && page <= pageCount) {
            table.setPageIndex(page - 1)
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
                {table.getFilteredSelectedRowModel().rows.length} of{" "}
                {table.getFilteredRowModel().rows.length} row(s) selected.
            </div>
            <div className="flex items-center space-x-6 lg:space-x-8">
                <div className="flex items-center space-x-2">
                    <p className="text-sm font-medium">Rows per page</p>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button
                                variant="outline"
                                className="h-8 w-[70px] p-0"
                            >
                                {table.getState().pagination.pageSize}
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent side="top">
                            {[10, 20, 30, 40, 50].map((pageSize) => (
                                <DropdownMenuItem
                                    key={pageSize}
                                    onClick={() => table.setPageSize(pageSize)}
                                >
                                    {pageSize}
                                </DropdownMenuItem>
                            ))}
                        </DropdownMenuContent>
                    </DropdownMenu>
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
                    <span>of {pageCount}</span>
                </div>
                <div className="flex items-center space-x-2">
                    <Button
                        variant="outline"
                        className="hidden h-8 w-8 p-0 lg:flex"
                        onClick={() => table.setPageIndex(0)}
                        disabled={!table.getCanPreviousPage()}
                    >
                        <span className="sr-only">Go to first page</span>
                        <ChevronsLeft className="h-4 w-4" />
                    </Button>
                    <Button
                        variant="outline"
                        className="h-8 w-8 p-0"
                        onClick={() => table.previousPage()}
                        disabled={!table.getCanPreviousPage()}
                    >
                        <span className="sr-only">Go to previous page</span>
                        <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <Button
                        variant="outline"
                        className="h-8 w-8 p-0"
                        onClick={() => table.nextPage()}
                        disabled={!table.getCanNextPage()}
                    >
                        <span className="sr-only">Go to next page</span>
                        <ChevronRight className="h-4 w-4" />
                    </Button>
                    <Button
                        variant="outline"
                        className="hidden h-8 w-8 p-0 lg:flex"
                        onClick={() => table.setPageIndex(table.getPageCount() - 1)}
                        disabled={!table.getCanNextPage()}
                    >
                        <span className="sr-only">Go to last page</span>
                        <ChevronsRight className="h-4 w-4" />
                    </Button>
                </div>
            </div>
        </div>
    )
}
