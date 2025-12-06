"use client"

import { useEffect, useState } from "react"
import { DataTable } from "@/components/data-table"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Loader2 } from "lucide-react"

interface Contributor {
    id: string
    name: string
    email: string
    commits: number
    last_commit_at: string | null
    languages: string[]
    risk_score: number
}

interface ContributorsViewProps {
    projectId: string
}

const API_BASE = "http://localhost:8000"

export function ContributorsView({ projectId }: ContributorsViewProps) {
    const [contributors, setContributors] = useState<Contributor[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchContributors = async () => {
            try {
                const res = await fetch(`${API_BASE}/projects/${projectId}/contributors`)
                if (res.ok) {
                    const data = await res.json()
                    setContributors(data)
                }
            } catch (error) {
                console.error("Failed to fetch contributors:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchContributors()
    }, [projectId])

    const columns: ColumnDef<Contributor>[] = [
        {
            accessorKey: "name",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Contributor" />
            ),
            cell: ({ row }) => {
                const name = row.getValue("name") as string
                const email = row.original.email
                const initials = name.split(" ").map((n) => n[0]).join("").slice(0, 2).toUpperCase()

                return (
                    <div className="flex items-center gap-3">
                        <Avatar className="h-9 w-9">
                            <AvatarImage src={`https://github.com/${name}.png`} alt={name} />
                            <AvatarFallback>{initials}</AvatarFallback>
                        </Avatar>
                        <div className="flex flex-col">
                            <span className="font-medium text-sm">{name}</span>
                            <span className="text-xs text-muted-foreground">{email}</span>
                        </div>
                    </div>
                )
            },
            filterFn: (row, id, value) => {
                return value.includes(row.getValue(id))
            },
        },
        {
            accessorKey: "commits",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Commits" />
            ),
            cell: ({ row }) => (
                <div className="font-medium">{row.getValue("commits")}</div>
            )
        },
        {
            accessorKey: "last_commit_at",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Last Active" />
            ),
            cell: ({ row }) => {
                const date = row.getValue("last_commit_at") as string
                if (!date) return <span className="text-muted-foreground">-</span>
                return (
                    <span className="text-sm">
                        {new Date(date).toLocaleDateString(undefined, {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric'
                        })}
                    </span>
                )
            }
        },
        {
            accessorKey: "languages",
            header: ({ column }) => (
                <DataTableColumnHeader column={column} title="Languages" />
            ),
            cell: ({ row }) => {
                const languages = row.getValue("languages") as string[]
                return (
                    <div className="flex flex-wrap gap-1">
                        {languages.map((lang) => (
                            <Badge key={lang} variant="secondary" className="text-[10px] px-1 py-0 h-5">
                                {lang}
                            </Badge>
                        ))}
                    </div>
                )
            }
        }
    ]

    if (loading) {
        return (
            <div className="flex h-40 items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        )
    }

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <div>
                    <h3 className="text-lg font-medium">Project Contributors</h3>
                    <p className="text-sm text-muted-foreground">
                        People who have committed code to this repository.
                    </p>
                </div>
                <Badge variant="outline" className="ml-auto">
                    {contributors.length} Contributors
                </Badge>
            </div>
            <DataTable columns={columns} data={contributors} searchKey="name" />
        </div>
    )
}
