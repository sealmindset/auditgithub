"use client"

import { useEffect, useState } from "react"
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Progress } from "@/components/ui/progress"
import {
    Loader2,
    Mail,
    User,
    GitBranch,
    Building2,
    Calendar,
    AlertTriangle,
    CheckCircle2,
    XCircle,
    HelpCircle,
    Clock,
    Shield,
    Users,
} from "lucide-react"

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

// Types matching the API response
interface ContributorAlias {
    id: string
    profile_id: string
    alias_type: string  // 'email', 'github_username', 'name'
    alias_value: string
    is_primary: boolean
    source: string | null
    match_confidence: number | null
    match_reason: string | null
    first_seen_at: string | null
    last_seen_at: string | null
    created_at: string
}

interface ContributorProfile {
    id: string
    display_name: string
    primary_email: string | null
    primary_github_username: string | null
    
    // Entra ID fields
    entra_id_object_id: string | null
    entra_id_upn: string | null
    entra_id_employee_id: string | null
    entra_id_job_title: string | null
    entra_id_department: string | null
    entra_id_manager_upn: string | null
    
    // Employment
    employment_status: string
    employment_start_date: string | null
    employment_end_date: string | null
    employment_verified_at: string | null
    
    // Stats
    total_repos: number
    total_commits: number
    last_activity_at: string | null
    first_activity_at: string | null
    risk_score: number
    is_stale: boolean
    has_elevated_access: boolean
    files_with_findings: number
    critical_files_count: number
    ai_identity_confidence: number | null
    ai_summary: string | null
    is_verified: boolean
    verified_at: string | null
    notes: string | null
    created_at: string
    updated_at: string
    
    // Related data
    aliases: ContributorAlias[]
    alias_count: number
    repo_names: string[]
}

interface ContributorProfileModalProps {
    email: string | null
    isOpen: boolean
    onClose: () => void
}

function getEmploymentStatusIcon(status: string) {
    switch (status) {
        case 'active':
            return <CheckCircle2 className="h-4 w-4 text-green-500" />
        case 'terminated':
            return <XCircle className="h-4 w-4 text-red-500" />
        case 'inactive':
            return <Clock className="h-4 w-4 text-yellow-500" />
        case 'contractor':
            return <Building2 className="h-4 w-4 text-blue-500" />
        default:
            return <HelpCircle className="h-4 w-4 text-gray-500" />
    }
}

function getEmploymentStatusBadge(status: string) {
    const variants: Record<string, "default" | "destructive" | "secondary" | "outline"> = {
        active: "default",
        terminated: "destructive",
        inactive: "secondary",
        contractor: "outline",
        unknown: "outline"
    }
    return variants[status] || "outline"
}

function getAliasTypeIcon(type: string) {
    switch (type) {
        case 'email':
            return <Mail className="h-4 w-4 text-blue-500" />
        case 'github_username':
            return <GitBranch className="h-4 w-4 text-purple-500" />
        case 'name':
            return <User className="h-4 w-4 text-green-500" />
        default:
            return <HelpCircle className="h-4 w-4 text-gray-500" />
    }
}

export function ContributorProfileModal({
    email,
    isOpen,
    onClose
}: ContributorProfileModalProps) {
    const [profile, setProfile] = useState<ContributorProfile | null>(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [notFound, setNotFound] = useState(false)

    useEffect(() => {
        if (isOpen && email) {
            setLoading(true)
            setError(null)
            setNotFound(false)
            
            fetch(`${API_BASE}/contributor-profiles/lookup-by-email?email=${encodeURIComponent(email)}`)
                .then(res => {
                    if (!res.ok) {
                        throw new Error(`HTTP ${res.status}`)
                    }
                    return res.json()
                })
                .then(data => {
                    if (data === null) {
                        setNotFound(true)
                        setProfile(null)
                    } else {
                        setProfile(data)
                        setNotFound(false)
                    }
                })
                .catch(err => {
                    console.error("Failed to fetch profile:", err)
                    setError(err.message)
                })
                .finally(() => setLoading(false))
        }
    }, [isOpen, email])

    if (!isOpen) return null

    const emailAliases = profile?.aliases.filter(a => a.alias_type === 'email') || []
    const githubAliases = profile?.aliases.filter(a => a.alias_type === 'github_username') || []
    const nameAliases = profile?.aliases.filter(a => a.alias_type === 'name') || []

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="!w-[75vw] !h-[80vh] !max-w-none flex flex-col">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <DialogHeader>
                            <DialogTitle className="sr-only">Loading contributor profile</DialogTitle>
                        </DialogHeader>
                        <Loader2 className="h-8 w-8 animate-spin" />
                    </div>
                ) : error ? (
                    <div className="flex flex-col items-center justify-center h-64 gap-4">
                        <DialogHeader>
                            <DialogTitle className="sr-only">Error loading profile</DialogTitle>
                        </DialogHeader>
                        <AlertTriangle className="h-12 w-12 text-red-500" />
                        <p className="text-muted-foreground">Failed to load profile: {error}</p>
                    </div>
                ) : notFound ? (
                    <div className="flex flex-col items-center justify-center h-64 gap-4">
                        <DialogHeader>
                            <DialogTitle className="text-xl">No Unified Profile Found</DialogTitle>
                        </DialogHeader>
                        <Users className="h-12 w-12 text-muted-foreground" />
                        <p className="text-muted-foreground text-center">
                            No contributor profile exists for <span className="font-mono">{email}</span>
                            <br />
                            <span className="text-sm">Build profiles from contributors to create unified identities.</span>
                        </p>
                    </div>
                ) : profile ? (
                    <>
                        <DialogHeader>
                            <div className="flex items-center gap-4">
                                <Avatar className="h-16 w-16">
                                    {profile.primary_github_username && (
                                        <AvatarImage
                                            src={`https://github.com/${profile.primary_github_username}.png`}
                                            alt={profile.display_name}
                                        />
                                    )}
                                    <AvatarFallback className="text-xl">
                                        {profile.display_name.split(" ").map(n => n[0]).join("").toUpperCase().slice(0, 2)}
                                    </AvatarFallback>
                                </Avatar>
                                <div className="flex-1">
                                    <DialogTitle className="text-2xl flex items-center gap-2">
                                        {profile.display_name}
                                        {profile.is_verified && (
                                            <CheckCircle2 className="h-5 w-5 text-green-500" />
                                        )}
                                    </DialogTitle>
                                    <div className="text-sm text-muted-foreground flex flex-wrap items-center gap-2 mt-1">
                                        <span>{profile.primary_email}</span>
                                        {profile.primary_github_username && (
                                            <span className="text-blue-500">@{profile.primary_github_username}</span>
                                        )}
                                    </div>
                                </div>
                                <div className="flex flex-col items-end gap-2">
                                    <div className="flex items-center gap-2">
                                        {getEmploymentStatusIcon(profile.employment_status)}
                                        <Badge variant={getEmploymentStatusBadge(profile.employment_status)}>
                                            {profile.employment_status.charAt(0).toUpperCase() + profile.employment_status.slice(1)}
                                        </Badge>
                                    </div>
                                    <Badge variant={profile.risk_score >= 50 ? "destructive" : "secondary"}>
                                        Risk Score: {profile.risk_score}
                                    </Badge>
                                </div>
                            </div>
                        </DialogHeader>

                        {/* Stats Cards */}
                        <div className="grid grid-cols-5 gap-4 my-4">
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold">{profile.alias_count}</div>
                                    <div className="text-xs text-muted-foreground">Known Aliases</div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold">{profile.total_repos}</div>
                                    <div className="text-xs text-muted-foreground">Repositories</div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold">{profile.total_commits}</div>
                                    <div className="text-xs text-muted-foreground">Total Commits</div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold text-red-600">{profile.critical_files_count}</div>
                                    <div className="text-xs text-muted-foreground">Critical Files</div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold text-orange-500">{profile.files_with_findings}</div>
                                    <div className="text-xs text-muted-foreground">Files w/ Findings</div>
                                </CardContent>
                            </Card>
                        </div>

                        {/* AI Summary if available */}
                        {profile.ai_summary && (
                            <Card className="mb-4 bg-gradient-to-r from-purple-50 to-blue-50 dark:from-purple-950 dark:to-blue-950">
                                <CardHeader className="pb-2">
                                    <CardTitle className="text-sm flex items-center gap-2">
                                        <Shield className="h-4 w-4" />
                                        AI Identity Analysis
                                    </CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-sm">{profile.ai_summary}</p>
                                </CardContent>
                            </Card>
                        )}

                        {/* Tabs for Aliases, Repos, Entra ID */}
                        <Tabs defaultValue="aliases" className="flex-1">
                            <TabsList className="grid w-full grid-cols-3">
                                <TabsTrigger value="aliases">
                                    <Users className="h-4 w-4 mr-2" />
                                    Aliases ({profile.alias_count})
                                </TabsTrigger>
                                <TabsTrigger value="repos">
                                    <GitBranch className="h-4 w-4 mr-2" />
                                    Repositories ({profile.total_repos})
                                </TabsTrigger>
                                <TabsTrigger value="entra">
                                    <Building2 className="h-4 w-4 mr-2" />
                                    Entra ID
                                </TabsTrigger>
                            </TabsList>

                            <TabsContent value="aliases" className="mt-4">
                                <ScrollArea className="h-[300px] pr-4">
                                    <div className="space-y-4">
                                        {/* Email Aliases */}
                                        {emailAliases.length > 0 && (
                                            <div>
                                                <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                                                    <Mail className="h-4 w-4" />
                                                    Email Addresses ({emailAliases.length})
                                                </h4>
                                                <div className="space-y-1">
                                                    {emailAliases.map((alias, idx) => (
                                                        <div
                                                            key={idx}
                                                            className="flex items-center justify-between p-2 rounded hover:bg-muted"
                                                        >
                                                            <div className="flex items-center gap-2">
                                                                {getAliasTypeIcon(alias.alias_type)}
                                                                <span className="font-mono text-sm">{alias.alias_value}</span>
                                                                {alias.is_primary && (
                                                                    <Badge variant="default" className="text-[10px]">Primary</Badge>
                                                                )}
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                {alias.match_confidence && (
                                                                    <span className="text-xs text-muted-foreground">
                                                                        {Math.round(alias.match_confidence * 100)}% match
                                                                    </span>
                                                                )}
                                                                {alias.match_reason && (
                                                                    <Badge variant="outline" className="text-[10px]">
                                                                        {alias.match_reason}
                                                                    </Badge>
                                                                )}
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {/* GitHub Aliases */}
                                        {githubAliases.length > 0 && (
                                            <div>
                                                <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                                                    <GitBranch className="h-4 w-4" />
                                                    GitHub Usernames ({githubAliases.length})
                                                </h4>
                                                <div className="space-y-1">
                                                    {githubAliases.map((alias, idx) => (
                                                        <div
                                                            key={idx}
                                                            className="flex items-center justify-between p-2 rounded hover:bg-muted"
                                                        >
                                                            <div className="flex items-center gap-2">
                                                                {getAliasTypeIcon(alias.alias_type)}
                                                                <span className="text-sm text-blue-500">@{alias.alias_value}</span>
                                                                {alias.is_primary && (
                                                                    <Badge variant="default" className="text-[10px]">Primary</Badge>
                                                                )}
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                {alias.match_reason && (
                                                                    <Badge variant="outline" className="text-[10px]">
                                                                        {alias.match_reason}
                                                                    </Badge>
                                                                )}
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {/* Name Aliases */}
                                        {nameAliases.length > 0 && (
                                            <div>
                                                <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                                                    <User className="h-4 w-4" />
                                                    Name Variations ({nameAliases.length})
                                                </h4>
                                                <div className="space-y-1">
                                                    {nameAliases.map((alias, idx) => (
                                                        <div
                                                            key={idx}
                                                            className="flex items-center justify-between p-2 rounded hover:bg-muted"
                                                        >
                                                            <div className="flex items-center gap-2">
                                                                {getAliasTypeIcon(alias.alias_type)}
                                                                <span className="text-sm">{alias.alias_value}</span>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                {alias.match_reason && (
                                                                    <Badge variant="outline" className="text-[10px]">
                                                                        {alias.match_reason}
                                                                    </Badge>
                                                                )}
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {profile.alias_count === 0 && (
                                            <div className="text-center text-muted-foreground py-8">
                                                No aliases recorded for this contributor
                                            </div>
                                        )}
                                    </div>
                                </ScrollArea>
                            </TabsContent>

                            <TabsContent value="repos" className="mt-4">
                                <ScrollArea className="h-[300px] pr-4">
                                    <div className="grid grid-cols-3 gap-2">
                                        {profile.repo_names.map((repo, idx) => (
                                            <div
                                                key={idx}
                                                className="flex items-center gap-2 p-3 rounded-lg bg-muted"
                                            >
                                                <GitBranch className="h-5 w-5 text-blue-500" />
                                                <span className="text-sm font-medium truncate">{repo}</span>
                                            </div>
                                        ))}
                                        {profile.repo_names.length === 0 && (
                                            <div className="col-span-3 text-center text-muted-foreground py-8">
                                                No repositories linked to this profile
                                            </div>
                                        )}
                                    </div>
                                </ScrollArea>
                            </TabsContent>

                            <TabsContent value="entra" className="mt-4">
                                <div className="grid grid-cols-2 gap-4">
                                    <Card>
                                        <CardHeader className="pb-2">
                                            <CardTitle className="text-sm">Identity</CardTitle>
                                        </CardHeader>
                                        <CardContent className="space-y-2">
                                            <div className="flex justify-between">
                                                <span className="text-muted-foreground text-sm">Object ID</span>
                                                <span className="font-mono text-sm">{profile.entra_id_object_id || '—'}</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-muted-foreground text-sm">UPN</span>
                                                <span className="font-mono text-sm">{profile.entra_id_upn || '—'}</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-muted-foreground text-sm">Employee ID</span>
                                                <span className="font-mono text-sm">{profile.entra_id_employee_id || '—'}</span>
                                            </div>
                                        </CardContent>
                                    </Card>
                                    <Card>
                                        <CardHeader className="pb-2">
                                            <CardTitle className="text-sm">Organization</CardTitle>
                                        </CardHeader>
                                        <CardContent className="space-y-2">
                                            <div className="flex justify-between">
                                                <span className="text-muted-foreground text-sm">Job Title</span>
                                                <span className="text-sm">{profile.entra_id_job_title || '—'}</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-muted-foreground text-sm">Department</span>
                                                <span className="text-sm">{profile.entra_id_department || '—'}</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-muted-foreground text-sm">Manager</span>
                                                <span className="text-sm">{profile.entra_id_manager_upn || '—'}</span>
                                            </div>
                                        </CardContent>
                                    </Card>
                                    <Card className="col-span-2">
                                        <CardHeader className="pb-2">
                                            <CardTitle className="text-sm">Employment Status</CardTitle>
                                        </CardHeader>
                                        <CardContent className="space-y-2">
                                            <div className="flex justify-between items-center">
                                                <span className="text-muted-foreground text-sm">Status</span>
                                                <div className="flex items-center gap-2">
                                                    {getEmploymentStatusIcon(profile.employment_status)}
                                                    <Badge variant={getEmploymentStatusBadge(profile.employment_status)}>
                                                        {profile.employment_status.charAt(0).toUpperCase() + profile.employment_status.slice(1)}
                                                    </Badge>
                                                </div>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-muted-foreground text-sm">Start Date</span>
                                                <span className="text-sm">
                                                    {profile.employment_start_date 
                                                        ? new Date(profile.employment_start_date).toLocaleDateString()
                                                        : '—'
                                                    }
                                                </span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-muted-foreground text-sm">End Date</span>
                                                <span className="text-sm">
                                                    {profile.employment_end_date 
                                                        ? new Date(profile.employment_end_date).toLocaleDateString()
                                                        : '—'
                                                    }
                                                </span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-muted-foreground text-sm">Last Verified</span>
                                                <span className="text-sm">
                                                    {profile.employment_verified_at 
                                                        ? new Date(profile.employment_verified_at).toLocaleDateString()
                                                        : 'Never'
                                                    }
                                                </span>
                                            </div>
                                        </CardContent>
                                    </Card>
                                    
                                    {!profile.entra_id_object_id && (
                                        <div className="col-span-2 text-center text-muted-foreground py-4 bg-muted rounded-lg">
                                            <HelpCircle className="h-8 w-8 mx-auto mb-2" />
                                            <p>Not linked to Entra ID</p>
                                            <p className="text-xs">Use the Entra ID sync to link this contributor to their Azure AD identity</p>
                                        </div>
                                    )}
                                </div>
                            </TabsContent>
                        </Tabs>

                        {/* Activity Timeline */}
                        <div className="mt-4 pt-4 border-t text-sm text-muted-foreground flex justify-between">
                            <div className="flex items-center gap-4">
                                <span className="flex items-center gap-1">
                                    <Calendar className="h-4 w-4" />
                                    First Activity: {profile.first_activity_at 
                                        ? new Date(profile.first_activity_at).toLocaleDateString()
                                        : 'Unknown'
                                    }
                                </span>
                                <span className="flex items-center gap-1">
                                    <Clock className="h-4 w-4" />
                                    Last Activity: {profile.last_activity_at 
                                        ? new Date(profile.last_activity_at).toLocaleDateString()
                                        : 'Unknown'
                                    }
                                </span>
                            </div>
                            <div>
                                Profile created: {new Date(profile.created_at).toLocaleDateString()}
                            </div>
                        </div>
                    </>
                ) : null}
            </DialogContent>
        </Dialog>
    )
}
