"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ShieldAlert, Plus, GitFork, Calendar, Loader2 } from "lucide-react"

const API_BASE = "http://localhost:8000"

interface Project {
    id: string
    name: string
    description: string
    language: string
    last_scanned_at: string | null
    stats: {
        open_findings: number
    }
}

export function ProjectScorecard() {
    const [projects, setProjects] = useState<Project[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchProjects = async () => {
            try {
                const res = await fetch(`${API_BASE}/projects/`)
                if (res.ok) {
                    const data = await res.json()
                    setProjects(data)
                }
            } catch (error) {
                console.error("Failed to fetch projects:", error)
            } finally {
                setLoading(false)
            }
        }

        fetchProjects()
    }, [])

    if (loading) {
        return (
            <div className="flex h-64 items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    return (
        <div className="flex flex-col gap-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight">Project Scorecard</h2>
                    <p className="text-muted-foreground">
                        Overview of security posture by project.
                    </p>
                </div>
                <Button>
                    <Plus className="mr-2 h-4 w-4" /> Add Project
                </Button>
            </div>

            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
                {projects.map((project) => (
                    <Link key={project.id} href={`/projects/${project.id}`}>
                        <Card className="h-full transition-all hover:shadow-md">
                            <CardHeader>
                                <div className="flex items-center justify-between">
                                    <CardTitle className="text-xl">{project.name}</CardTitle>
                                    <Badge variant={project.stats.open_findings > 0 ? "destructive" : "secondary"}>
                                        {project.stats.open_findings} Issues
                                    </Badge>
                                </div>
                                <CardDescription className="line-clamp-2">
                                    {project.description || "No description provided"}
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <div className="flex flex-col gap-2 text-sm text-muted-foreground">
                                    <div className="flex items-center gap-2">
                                        <ShieldAlert className="h-4 w-4" />
                                        <span>{project.language}</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <Calendar className="h-4 w-4" />
                                        <span>
                                            {project.last_scanned_at
                                                ? new Date(project.last_scanned_at).toLocaleDateString()
                                                : "Never scanned"}
                                        </span>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    </Link>
                ))}

                {projects.length === 0 && (
                    <div className="col-span-full flex flex-col items-center justify-center rounded-lg border border-dashed p-8 text-center animate-in fade-in-50">
                        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-secondary">
                            <GitFork className="h-6 w-6" />
                        </div>
                        <h3 className="mt-4 text-lg font-semibold">No projects found</h3>
                        <p className="mb-4 mt-2 text-sm text-muted-foreground">
                            Get started by adding your first repository to scan.
                        </p>
                        <Button>
                            <Plus className="mr-2 h-4 w-4" /> Add Project
                        </Button>
                    </div>
                )}
            </div>
        </div>
    )
}
