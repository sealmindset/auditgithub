"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Users, UserPlus, Mail, Shield, Loader2, AlertCircle, Search, CheckCircle2, AlertTriangle } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { formatDistanceToNow } from "date-fns"
import { API_BASE, apiFetch } from "@/lib/api"

interface User {
  id: string
  email: string
  username: string
  full_name: string | null
  role: string
  access_type: string
  auth_provider: string
  is_active: boolean
  last_login_at: string | null
  created_at: string
}

interface Invitation {
  id: string
  email: string
  role: string
  access_type: string
  status: string
  invited_by_email: string
  created_at: string
  expires_at: string
}

interface DirectoryUser {
  sub: string
  email: string
  name: string
  provider: string
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [invitations, setInvitations] = useState<Invitation[]>([])
  const [loading, setLoading] = useState(true)
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState("user")
  const [inviteAccessType, setInviteAccessType] = useState("ui_only")
  const [inviteLoading, setInviteLoading] = useState(false)
  const [directoryUsers, setDirectoryUsers] = useState<DirectoryUser[]>([])
  const [directorySearch, setDirectorySearch] = useState("")
  const [directoryLoading, setDirectoryLoading] = useState(false)
  const [directoryAvailable, setDirectoryAvailable] = useState(false)
  const [directoryEmails, setDirectoryEmails] = useState<Set<string>>(new Set())
  const [inviteTab, setInviteTab] = useState<"directory" | "manual">("directory")
  const { toast } = useToast()

  useEffect(() => {
    fetchUsers()
    fetchInvitations()
    fetchDirectoryEmails()
  }, [])

  const fetchUsers = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/api/users`, {
        credentials: "include"
      })

      if (res.ok) {
        const data = await res.json()
        setUsers(data)
      } else {
        toast({
          title: "Failed to load users",
          description: "Please try again later",
          variant: "destructive"
        })
      }
    } catch (error) {
      console.error("Failed to fetch users:", error)
      toast({
        title: "Connection error",
        description: "Could not connect to API",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  const fetchInvitations = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/api/invitations`, {
        credentials: "include"
      })

      if (res.ok) {
        const data = await res.json()
        setInvitations(data)
      }
    } catch (error) {
      console.error("Failed to fetch invitations:", error)
    }
  }

  const fetchDirectoryEmails = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/auth/directory/users?all=true`, {
        credentials: "include"
      })
      if (res.ok) {
        const data = await res.json()
        if (data.source === "oidc") {
          setDirectoryAvailable(true)
          setDirectoryEmails(new Set(data.users.map((u: DirectoryUser) => u.email.toLowerCase())))
        }
      }
    } catch {
      // Directory not available, that's fine
    }
  }

  const searchDirectory = async (query: string) => {
    setDirectorySearch(query)
    if (!query.trim()) {
      setDirectoryUsers([])
      return
    }
    setDirectoryLoading(true)
    try {
      const res = await apiFetch(`${API_BASE}/auth/directory/users?q=${encodeURIComponent(query)}`, {
        credentials: "include"
      })
      if (res.ok) {
        const data = await res.json()
        setDirectoryUsers(data.users || [])
      }
    } catch {
      setDirectoryUsers([])
    } finally {
      setDirectoryLoading(false)
    }
  }

  const selectDirectoryUser = (dirUser: DirectoryUser) => {
    setInviteEmail(dirUser.email)
    setDirectoryUsers([])
    setDirectorySearch("")
  }

  const handleSendInvite = async () => {
    if (!inviteEmail.trim()) return

    setInviteLoading(true)

    try {
      const res = await apiFetch(`${API_BASE}/api/invitations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          email: inviteEmail,
          role: inviteRole,
          access_type: inviteAccessType
        })
      })

      if (res.ok) {
        const data = await res.json()

        toast({
          title: "Invitation sent successfully",
          description: `Invitation link: ${data.invitation_link}`
        })

        setInviteDialogOpen(false)
        setInviteEmail("")
        setInviteRole("user")
        setInviteAccessType("ui_only")
        fetchInvitations()
      } else {
        const data = await res.json()
        toast({
          title: "Failed to send invitation",
          description: data.detail || "Please try again",
          variant: "destructive"
        })
      }
    } catch (error) {
      toast({
        title: "Connection error",
        description: "Could not connect to API",
        variant: "destructive"
      })
    } finally {
      setInviteLoading(false)
    }
  }

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case "super_admin":
        return "bg-purple-600"
      case "admin":
        return "bg-red-600"
      case "manager":
        return "bg-orange-600"
      case "analyst":
        return "bg-blue-600"
      case "developer":
        return "bg-green-600"
      default:
        return "bg-gray-600"
    }
  }

  const getAccessTypeBadge = (accessType: string) => {
    switch (accessType) {
      case "both":
        return <Badge variant="default" className="bg-green-600">Full Access</Badge>
      case "ui_only":
        return <Badge variant="outline">UI Only</Badge>
      case "api_only":
        return <Badge variant="outline">API Only</Badge>
      default:
        return <Badge variant="outline">{accessType}</Badge>
    }
  }

  if (loading) {
    return (
      <div className="container mx-auto py-8 px-4">
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
        </div>
      </div>
    )
  }

  return (
    <div className="container mx-auto py-8 px-4 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Users className="h-8 w-8" />
            User Management
          </h1>
          <p className="text-gray-600 mt-1">Manage users, roles, and invitations</p>
        </div>
        <Button onClick={() => setInviteDialogOpen(true)} className="bg-blue-600 hover:bg-blue-700">
          <UserPlus className="h-4 w-4 mr-2" />
          Invite User
        </Button>
      </div>

      {/* Pending Invitations */}
      {invitations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Mail className="h-5 w-5" />
              Pending Invitations
            </CardTitle>
            <CardDescription>Invitations awaiting acceptance</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {invitations.map((inv) => (
                <div
                  key={inv.id}
                  className="flex items-center justify-between p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <Mail className="h-4 w-4 text-yellow-600" />
                    <div>
                      <p className="font-medium text-sm">{inv.email}</p>
                      <p className="text-xs text-gray-600">
                        Invited by {inv.invited_by_email} •{" "}
                        {formatDistanceToNow(new Date(inv.created_at), { addSuffix: true })}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="default" className={getRoleBadgeColor(inv.role)}>
                      {inv.role}
                    </Badge>
                    {getAccessTypeBadge(inv.access_type)}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Users Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Active Users
          </CardTitle>
          <CardDescription>All registered users and their roles</CardDescription>
        </CardHeader>
        <CardContent>
          {users.length === 0 ? (
            <div className="text-center py-12">
              <AlertCircle className="h-12 w-12 mx-auto mb-4 text-gray-400" />
              <p className="text-gray-600 font-medium mb-2">No users found</p>
              <p className="text-sm text-gray-500">Invite users to get started</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Access Type</TableHead>
                    <TableHead>Auth Provider</TableHead>
                    {directoryAvailable && <TableHead>Directory</TableHead>}
                    <TableHead>Last Login</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell>
                        <div>
                          <p className="font-medium">{user.full_name || user.username}</p>
                          <p className="text-xs text-gray-500">@{user.username}</p>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm">{user.email}</TableCell>
                      <TableCell>
                        <Badge variant="default" className={getRoleBadgeColor(user.role)}>
                          {user.role.replace("_", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>{getAccessTypeBadge(user.access_type)}</TableCell>
                      <TableCell className="capitalize">{user.auth_provider}</TableCell>
                      {directoryAvailable && (
                        <TableCell>
                          {directoryEmails.has(user.email.toLowerCase()) ? (
                            <Badge variant="outline" className="text-green-600 border-green-300">
                              <CheckCircle2 className="h-3 w-3 mr-1" />
                              Verified
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-amber-600 border-amber-300">
                              <AlertTriangle className="h-3 w-3 mr-1" />
                              Not in IdP
                            </Badge>
                          )}
                        </TableCell>
                      )}
                      <TableCell className="text-sm text-gray-600">
                        {user.last_login_at
                          ? formatDistanceToNow(new Date(user.last_login_at), { addSuffix: true })
                          : "Never"}
                      </TableCell>
                      <TableCell>
                        {user.is_active ? (
                          <Badge variant="default" className="bg-green-600">
                            Active
                          </Badge>
                        ) : (
                          <Badge variant="destructive">Inactive</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Invite Dialog */}
      <Dialog open={inviteDialogOpen} onOpenChange={(open) => {
        setInviteDialogOpen(open)
        if (!open) {
          setInviteEmail("")
          setDirectorySearch("")
          setDirectoryUsers([])
          setInviteTab("directory")
        }
      }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Invite New User</DialogTitle>
            <DialogDescription>
              Send an invitation to a new user. They&apos;ll receive a link to join the platform.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {/* Tab selector */}
            {directoryAvailable && (
              <div className="flex border-b">
                <button
                  onClick={() => setInviteTab("directory")}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                    inviteTab === "directory"
                      ? "border-blue-600 text-blue-600"
                      : "border-transparent text-gray-500 hover:text-gray-700"
                  }`}
                >
                  Directory
                </button>
                <button
                  onClick={() => setInviteTab("manual")}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                    inviteTab === "manual"
                      ? "border-blue-600 text-blue-600"
                      : "border-transparent text-gray-500 hover:text-gray-700"
                  }`}
                >
                  Pre-stage (Manual)
                </button>
              </div>
            )}

            {/* Directory search tab */}
            {inviteTab === "directory" && directoryAvailable ? (
              <div>
                <Label>Search Directory</Label>
                <div className="relative mt-2">
                  <Search className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                  <Input
                    value={directorySearch}
                    onChange={(e) => searchDirectory(e.target.value)}
                    placeholder="Search by name or email..."
                    className="pl-9"
                    disabled={inviteLoading}
                  />
                </div>
                {directoryLoading && (
                  <div className="flex justify-center py-3">
                    <Loader2 className="h-4 w-4 animate-spin text-gray-400" />
                  </div>
                )}
                {directoryUsers.length > 0 && (
                  <div className="mt-2 max-h-40 overflow-y-auto border rounded-md">
                    {directoryUsers.map((dirUser) => (
                      <button
                        key={dirUser.sub}
                        onClick={() => selectDirectoryUser(dirUser)}
                        className="w-full text-left px-3 py-2 hover:bg-gray-100 dark:hover:bg-gray-800 border-b last:border-b-0"
                      >
                        <p className="font-medium text-sm">{dirUser.name}</p>
                        <p className="text-xs text-gray-500">{dirUser.email}</p>
                      </button>
                    ))}
                  </div>
                )}
                {inviteEmail && (
                  <div className="mt-2 flex items-center gap-2 p-2 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-md">
                    <CheckCircle2 className="h-4 w-4 text-blue-600" />
                    <span className="text-sm font-medium">{inviteEmail}</span>
                    <button
                      onClick={() => setInviteEmail("")}
                      className="ml-auto text-xs text-gray-500 hover:text-gray-700"
                    >
                      Clear
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div>
                {inviteTab === "manual" && (
                  <div className="mb-3 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 flex-shrink-0" />
                    <p className="text-xs text-amber-700 dark:text-amber-400">
                      Pre-staging requires IdP enrollment. This user must be added to
                      the identity provider before they can sign in. Use Directory mode
                      if the user already exists in your IdP.
                    </p>
                  </div>
                )}
                <Label htmlFor="email">Email Address</Label>
                <Input
                  id="email"
                  type="email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="user@example.com"
                  className="mt-2"
                  disabled={inviteLoading}
                />
              </div>
            )}
            <div>
              <Label htmlFor="role">Role</Label>
              <Select value={inviteRole} onValueChange={setInviteRole} disabled={inviteLoading}>
                <SelectTrigger className="mt-2">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">User (View Only)</SelectItem>
                  <SelectItem value="developer">Developer (Run Scans)</SelectItem>
                  <SelectItem value="analyst">Analyst (Manage Findings)</SelectItem>
                  <SelectItem value="manager">Manager (Power User)</SelectItem>
                  <SelectItem value="admin">Admin (Full Access)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="access-type">Access Type</Label>
              <Select
                value={inviteAccessType}
                onValueChange={setInviteAccessType}
                disabled={inviteLoading}
              >
                <SelectTrigger className="mt-2">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ui_only">UI Only</SelectItem>
                  <SelectItem value="api_only">API Only</SelectItem>
                  <SelectItem value="both">Full Access (UI + API)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setInviteDialogOpen(false)}
              disabled={inviteLoading}
            >
              Cancel
            </Button>
            <Button
              onClick={handleSendInvite}
              disabled={inviteLoading || !inviteEmail.trim()}
            >
              {inviteLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Send Invitation
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
