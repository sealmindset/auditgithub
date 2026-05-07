"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ShieldAlert, FileCode, Star, GitFork, Clock, Eye, EyeOff, Globe, Archive, GitBranch, Tag, Scale, Users, BookOpen, MessageSquare, ExternalLink, Calendar, HardDrive } from "lucide-react"
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts"
import Link from "next/link"

interface ProjectOverviewProps {
    project: any
    secrets: any[]
    sast: any[]
    terraform: any[]
    oss: any[]
}

function formatDate(dateString: string | null) {
    if (!dateString) return "—"
    return new Date(dateString).toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric"
    })
}

function formatRelativeDate(dateString: string | null) {
    if (!dateString) return null
    const date = new Date(dateString)
    const now = new Date()
    const diffDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24))
    
    if (diffDays === 0) return "Today"
    if (diffDays === 1) return "Yesterday"
    if (diffDays < 7) return `${diffDays} days ago`
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`
    if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`
    return `${Math.floor(diffDays / 365)} years ago`
}

function formatSize(kb: number) {
    if (kb < 1024) return `${kb} KB`
    if (kb < 1024 * 1024) return `${(kb / 1024).toFixed(1)} MB`
    return `${(kb / (1024 * 1024)).toFixed(1)} GB`
}

export function ProjectOverview({ project, secrets, sast, terraform, oss }: ProjectOverviewProps) {
    // Calculate stats
    const allFindings = [...secrets, ...sast, ...terraform, ...oss]

    const severityCounts = {
        critical: allFindings.filter(f => f.severity === "critical").length,
        high: allFindings.filter(f => f.severity === "high").length,
        medium: allFindings.filter(f => f.severity === "medium").length,
        low: allFindings.filter(f => f.severity === "low").length,
    }

    const severityData = [
        { name: "Critical", value: severityCounts.critical, color: "#ef4444" },
        { name: "High", value: severityCounts.high, color: "#f97316" },
        { name: "Medium", value: severityCounts.medium, color: "#eab308" },
        { name: "Low", value: severityCounts.low, color: "#3b82f6" },
    ].filter(d => d.value > 0)

    const typeData = [
        { name: "Secrets", count: secrets.length },
        { name: "SAST", count: sast.length },
        { name: "IaC", count: terraform.length },
        { name: "OSS", count: oss.length },
    ]

    // Determine visibility display
    const getVisibilityBadge = () => {
        const visibility = project.visibility
        const isPrivate = project.is_private
        const effectiveVisibility = visibility || (isPrivate ? "private" : "public")
        
        if (effectiveVisibility === "public") {
            return (
                <Badge variant="destructive" className="bg-red-500">
                    <Globe className="h-3 w-3 mr-1" />
                    Public
                </Badge>
            )
        } else if (effectiveVisibility === "internal") {
            return (
                <Badge className="bg-green-500">
                    <Eye className="h-3 w-3 mr-1" />
                    Internal
                </Badge>
            )
        }
        return (
            <Badge className="bg-green-500">
                <EyeOff className="h-3 w-3 mr-1" />
                Private
            </Badge>
        )
    }

    return (
        <div className="space-y-6">
            {/* Repository Info Header */}
            <Card className="border-l-4 border-l-blue-500">
                <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <CardTitle className="text-xl">{project.name}</CardTitle>
                            {getVisibilityBadge()}
                            {project.is_archived && (
                                <Badge variant="secondary">
                                    <Archive className="h-3 w-3 mr-1" />
                                    Archived
                                </Badge>
                            )}
                            {project.is_fork && (
                                <Badge variant="outline">
                                    <GitFork className="h-3 w-3 mr-1" />
                                    Fork
                                </Badge>
                            )}
                        </div>
                        {project.url && (
                            <Link href={project.url} target="_blank" className="text-blue-600 hover:underline flex items-center gap-1 text-sm">
                                View on GitHub <ExternalLink className="h-3 w-3" />
                            </Link>
                        )}
                    </div>
                </CardHeader>
                <CardContent>
                    {project.description && (
                        <p className="text-muted-foreground mb-4">{project.description}</p>
                    )}
                    
                    {/* Topics/Tags */}
                    {project.topics && project.topics.length > 0 && (
                        <div className="flex flex-wrap gap-2 mb-4">
                            {project.topics.map((topic: string) => (
                                <Badge key={topic} variant="outline" className="text-xs">
                                    <Tag className="h-3 w-3 mr-1" />
                                    {topic}
                                </Badge>
                            ))}
                        </div>
                    )}
                    
                    {/* Key Dates Row */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t">
                        <div className="flex items-center gap-2 text-sm">
                            <Clock className="h-4 w-4 text-muted-foreground" />
                            <div>
                                <div className="font-medium">Last Push</div>
                                <div className="text-muted-foreground">
                                    {formatRelativeDate(project.pushed_at) || formatDate(project.pushed_at)}
                                </div>
                            </div>
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                            <Calendar className="h-4 w-4 text-muted-foreground" />
                            <div>
                                <div className="font-medium">Created</div>
                                <div className="text-muted-foreground">{formatDate(project.github_created_at)}</div>
                            </div>
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                            <GitBranch className="h-4 w-4 text-muted-foreground" />
                            <div>
                                <div className="font-medium">Default Branch</div>
                                <div className="text-muted-foreground">{project.default_branch || "main"}</div>
                            </div>
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                            <Scale className="h-4 w-4 text-muted-foreground" />
                            <div>
                                <div className="font-medium">License</div>
                                <div className="text-muted-foreground">{project.license_name || "None"}</div>
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Stats Cards Row */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Open Findings</CardTitle>
                        <ShieldAlert className="h-4 w-4 text-red-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{project.stats?.open_findings || 0}</div>
                        <p className="text-xs text-muted-foreground">Security issues</p>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Language</CardTitle>
                        <FileCode className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold truncate">{project.language || "Unknown"}</div>
                        <p className="text-xs text-muted-foreground">Primary language</p>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Stars</CardTitle>
                        <Star className="h-4 w-4 text-yellow-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{project.stats?.stars || 0}</div>
                        <p className="text-xs text-muted-foreground">GitHub stars</p>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Forks</CardTitle>
                        <GitFork className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{project.stats?.forks || 0}</div>
                        <p className="text-xs text-muted-foreground">Repository forks</p>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Size</CardTitle>
                        <HardDrive className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{formatSize(project.stats?.size_kb || 0)}</div>
                        <p className="text-xs text-muted-foreground">Repository size</p>
                    </CardContent>
                </Card>
            </div>

            {/* Additional Info Row */}
            <div className="grid gap-4 md:grid-cols-3">
                <Card className="col-span-1">
                    <CardHeader>
                        <CardTitle className="text-sm">Repository Features</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                        <div className="flex items-center justify-between">
                            <span className="flex items-center gap-2 text-sm">
                                <BookOpen className="h-4 w-4" /> Wiki
                            </span>
                            <Badge variant={project.has_wiki ? "default" : "secondary"}>
                                {project.has_wiki ? "Enabled" : "Disabled"}
                            </Badge>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="flex items-center gap-2 text-sm">
                                <Globe className="h-4 w-4" /> Pages
                            </span>
                            <Badge variant={project.has_pages ? "default" : "secondary"}>
                                {project.has_pages ? "Enabled" : "Disabled"}
                            </Badge>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="flex items-center gap-2 text-sm">
                                <MessageSquare className="h-4 w-4" /> Discussions
                            </span>
                            <Badge variant={project.has_discussions ? "default" : "secondary"}>
                                {project.has_discussions ? "Enabled" : "Disabled"}
                            </Badge>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="flex items-center gap-2 text-sm">
                                <Users className="h-4 w-4" /> Watchers
                            </span>
                            <span className="font-medium">{project.stats?.watchers || 0}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="flex items-center gap-2 text-sm">
                                <ShieldAlert className="h-4 w-4" /> Open Issues
                            </span>
                            <span className="font-medium">{project.stats?.open_issues || 0}</span>
                        </div>
                    </CardContent>
                </Card>

                {/* Charts */}
                <Card>
                    <CardHeader>
                        <CardTitle className="text-sm">Severity Distribution</CardTitle>
                    </CardHeader>
                    <CardContent className="h-[200px]">
                        {severityData.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={severityData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={40}
                                        outerRadius={60}
                                        paddingAngle={5}
                                        dataKey="value"
                                    >
                                        {severityData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} />
                                        ))}
                                    </Pie>
                                    <Tooltip />
                                    <Legend />
                                </PieChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="flex items-center justify-center h-full text-muted-foreground">
                                No findings
                            </div>
                        )}
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader>
                        <CardTitle className="text-sm">Findings by Type</CardTitle>
                    </CardHeader>
                    <CardContent className="h-[200px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={typeData}>
                                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                                <YAxis tick={{ fontSize: 12 }} />
                                <Tooltip />
                                <Bar dataKey="count" fill="#8884d8" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </CardContent>
                </Card>
            </div>
        </div>
    )
}
