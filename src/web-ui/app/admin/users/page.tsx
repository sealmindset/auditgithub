"use client"

import { useState, useEffect, useMemo } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import {
  Users, UserPlus, Mail, Shield, Loader2, AlertCircle, Search,
  CheckCircle2, AlertTriangle, UserCog, ShieldCheck, ShieldAlert,
  Clock, MoreHorizontal, Pencil, UserX, UserCheck,
} from "lucide-react"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useToast } from "@/components/ui/use-toast"
import { formatDistanceToNow } from "date-fns"
import { API_BASE, apiFetch } from "@/lib/api"
import { useAuth } from "@/contexts/AuthContext"

interface User {
  id: string
  email: string
  username: string
  full_name: string | null
  role: string
  access_type: string
  auth_provider: string
  is_active: boolean
  is_invited: boolean
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

const ROLES = [
  { value: "user", label: "User", description: "View Only", color: "bg-gray-600" },
  { value: "analyst", label: "Analyst", description: "Manage Findings", color: "bg-blue-600" },
  { value: "manager", label: "Manager", description: "Power User", color: "bg-orange-600" },
  { value: "admin", label: "Admin", description: "Full Access", color: "bg-red-600" },
  { value: "super_admin", label: "Super Admin", description: "System Access", color: "bg-purple-600" },
]

const ACCESS_TYPES = [
  { value: "ui_only", label: "UI Only" },
  { value: "api_only", label: "API Only" },
  { value: "both", label: "Full Access (UI + API)" },
]

export default function AdminUsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [invitations, setInvitations] = useState<Invitation[]>([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState("")
  const { toast } = useToast()
  const { user: currentUser } = useAuth()

  // Invite dialog
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState("user")
  const [inviteAccessType, setInviteAccessType] = useState("both")
  const [inviteLoading, setInviteLoading] = useState(false)
  const [directoryUsers, setDirectoryUsers] = useState<DirectoryUser[]>([])
  const [directorySearch, setDirectorySearch] = useState("")
  const [directoryLoading, setDirectoryLoading] = useState(false)
  const [directoryAvailable, setDirectoryAvailable] = useState(false)
  const [directoryEmails, setDirectoryEmails] = useState<Set<string>>(new Set())
  const [inviteTab, setInviteTab] = useState<"directory" | "manual">("directory")
  const [selectedDirUser, setSelectedDirUser] = useState<DirectoryUser | null>(null)
  const [inviteNotes, setInviteNotes] = useState("")

  // Edit dialog
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [editUser, setEditUser] = useState<User | null>(null)
  const [editRole, setEditRole] = useState("")
  const [editAccessType, setEditAccessType] = useState("")
  const [editLoading, setEditLoading] = useState(false)

  // Deactivate dialog
  const [deactivateDialogOpen, setDeactivateDialogOpen] = useState(false)
  const [deactivateUser, setDeactivateUser] = useState<User | null>(null)
  const [deactivateLoading, setDeactivateLoading] = useState(false)

  useEffect(() => {
    fetchUsers()
    fetchInvitations()
    fetchDirectoryEmails()
  }, [])

  const fetchUsers = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/api/users?include_inactive=true`, {
        credentials: "include"
      })
      if (res.ok) {
        setUsers(await res.json())
      } else {
        toast({ title: "Failed to load users", variant: "destructive" })
      }
    } catch {
      toast({ title: "Connection error", description: "Could not connect to API", variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  const fetchInvitations = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/api/invitations`, { credentials: "include" })
      if (res.ok) setInvitations(await res.json())
    } catch { /* ignore */ }
  }

  const fetchDirectoryEmails = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/auth/directory/users?all=true`, { credentials: "include" })
      if (res.ok) {
        const data = await res.json()
        if (data.source === "oidc") {
          setDirectoryAvailable(true)
          setDirectoryEmails(new Set(data.users.map((u: DirectoryUser) => u.email.toLowerCase())))
        }
      }
    } catch { /* not available */ }
  }

  const searchDirectory = async (query: string) => {
    setDirectorySearch(query)
    if (!query.trim()) { setDirectoryUsers([]); return }
    setDirectoryLoading(true)
    try {
      const res = await apiFetch(`${API_BASE}/auth/directory/users?q=${encodeURIComponent(query)}`, { credentials: "include" })
      if (res.ok) {
        const data = await res.json()
        setDirectoryUsers(data.users || [])
      }
    } catch { setDirectoryUsers([]) }
    finally { setDirectoryLoading(false) }
  }

  const handleSendInvite = async () => {
    if (!inviteEmail.trim()) return
    setInviteLoading(true)
    try {
      const res = await apiFetch(`${API_BASE}/api/invitations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email: inviteEmail, role: inviteRole, access_type: inviteAccessType })
      })
      if (res.ok) {
        const data = await res.json()
        toast({ title: "Invitation sent", description: `Link: ${data.invitation_link}` })
        setInviteDialogOpen(false)
        setInviteEmail("")
        setInviteRole("user")
        setInviteAccessType("both")
        fetchInvitations()
      } else {
        const data = await res.json()
        toast({ title: "Failed to send invitation", description: data.detail, variant: "destructive" })
      }
    } catch {
      toast({ title: "Connection error", variant: "destructive" })
    } finally { setInviteLoading(false) }
  }

  const handleAddFromDirectory = async () => {
    if (!inviteEmail.trim()) return
    setInviteLoading(true)
    try {
      const res = await apiFetch(`${API_BASE}/api/users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          email: inviteEmail,
          full_name: selectedDirUser?.name || null,
          oidc_subject: selectedDirUser?.sub || null,
          role: inviteRole,
          access_type: inviteAccessType,
        })
      })
      if (res.ok) {
        toast({ title: "User added", description: `${inviteEmail} has been added with ${inviteRole} role` })
        setInviteDialogOpen(false)
        setInviteEmail("")
        setSelectedDirUser(null)
        setInviteRole("user")
        setInviteAccessType("both")
        fetchUsers()
      } else {
        const data = await res.json()
        toast({ title: "Failed to add user", description: data.detail, variant: "destructive" })
      }
    } catch {
      toast({ title: "Connection error", variant: "destructive" })
    } finally { setInviteLoading(false) }
  }

  const handleEditUser = (user: User) => {
    setEditUser(user)
    setEditRole(user.role)
    setEditAccessType(user.access_type)
    setEditDialogOpen(true)
  }

  const handleSaveEdit = async () => {
    if (!editUser) return
    setEditLoading(true)
    try {
      // Update role if changed
      if (editRole !== editUser.role) {
        const res = await apiFetch(`${API_BASE}/api/users/${editUser.id}/role`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ role: editRole })
        })
        if (!res.ok) {
          const data = await res.json()
          toast({ title: "Failed to update role", description: data.detail, variant: "destructive" })
          setEditLoading(false)
          return
        }
      }
      // Update access type if changed
      if (editAccessType !== editUser.access_type) {
        const res = await apiFetch(`${API_BASE}/api/users/${editUser.id}/access-type`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ access_type: editAccessType })
        })
        if (!res.ok) {
          const data = await res.json()
          toast({ title: "Failed to update access type", description: data.detail, variant: "destructive" })
          setEditLoading(false)
          return
        }
      }
      toast({ title: "User updated successfully" })
      setEditDialogOpen(false)
      fetchUsers()
    } catch {
      toast({ title: "Connection error", variant: "destructive" })
    } finally { setEditLoading(false) }
  }

  const handleRevokeInvitation = async (id: string) => {
    try {
      const res = await apiFetch(`${API_BASE}/api/invitations/${id}`, {
        method: "DELETE",
        credentials: "include"
      })
      if (res.ok || res.status === 204) {
        toast({ title: "Invitation revoked" })
        fetchInvitations()
      } else {
        toast({ title: "Failed to revoke invitation", variant: "destructive" })
      }
    } catch {
      toast({ title: "Connection error", variant: "destructive" })
    }
  }

  const getRoleInfo = (role: string) => ROLES.find(r => r.value === role) || ROLES[0]

  // Stats
  const stats = useMemo(() => {
    const active = users.filter(u => u.is_active)
    const admins = active.filter(u => u.role === "admin" || u.role === "super_admin")
    const recentLogins = active.filter(u => {
      if (!u.last_login_at) return false
      const diff = Date.now() - new Date(u.last_login_at).getTime()
      return diff < 7 * 24 * 60 * 60 * 1000 // 7 days
    })
    return {
      total: users.length,
      active: active.length,
      admins: admins.length,
      recentLogins: recentLogins.length,
      pending: invitations.length,
    }
  }, [users, invitations])

  // Filtered users
  const filteredUsers = useMemo(() => {
    if (!searchQuery.trim()) return users
    const q = searchQuery.toLowerCase()
    return users.filter(u =>
      u.email.toLowerCase().includes(q) ||
      u.username.toLowerCase().includes(q) ||
      (u.full_name && u.full_name.toLowerCase().includes(q)) ||
      u.role.toLowerCase().includes(q)
    )
  }, [users, searchQuery])

  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="flex flex-1 flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Users className="h-8 w-8" />
            User Management
          </h1>
          <p className="text-muted-foreground mt-1">Manage users, roles, and access</p>
        </div>
        <Button onClick={() => setInviteDialogOpen(true)}>
          <UserPlus className="h-4 w-4 mr-2" />
          Invite User
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-blue-100 dark:bg-blue-900/30 p-2">
                <Users className="h-5 w-5 text-blue-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Total Users</p>
                <p className="text-2xl font-bold">{stats.total}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-green-100 dark:bg-green-900/30 p-2">
                <UserCheck className="h-5 w-5 text-green-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Active Users</p>
                <p className="text-2xl font-bold">{stats.active}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-purple-100 dark:bg-purple-900/30 p-2">
                <ShieldCheck className="h-5 w-5 text-purple-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Admins</p>
                <p className="text-2xl font-bold">{stats.admins}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-amber-100 dark:bg-amber-900/30 p-2">
                <Clock className="h-5 w-5 text-amber-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Active (7d)</p>
                <p className="text-2xl font-bold">{stats.recentLogins}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Pending Invitations */}
      {invitations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Mail className="h-5 w-5" />
              Pending Invitations ({invitations.length})
            </CardTitle>
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
                      <p className="text-xs text-muted-foreground">
                        By {inv.invited_by_email} &bull;{" "}
                        {formatDistanceToNow(new Date(inv.created_at), { addSuffix: true })}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={getRoleInfo(inv.role).color}>
                      {inv.role.replace("_", " ")}
                    </Badge>
                    <Button size="sm" variant="ghost" className="text-red-600 hover:text-red-700 h-8" onClick={() => handleRevokeInvitation(inv.id)}>
                      Revoke
                    </Button>
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
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Users
              </CardTitle>
              <CardDescription>All registered users and their roles</CardDescription>
            </div>
            <div className="relative w-72">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search users..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filteredUsers.length === 0 ? (
            <div className="text-center py-12">
              <AlertCircle className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="font-medium mb-2">No users found</p>
              <p className="text-sm text-muted-foreground">
                {searchQuery ? "Try a different search term" : "Invite users to get started"}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Access</TableHead>
                    <TableHead>Provider</TableHead>
                    {directoryAvailable && <TableHead>Directory</TableHead>}
                    <TableHead>Last Login</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-[50px]"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredUsers.map((user) => {
                    const roleInfo = getRoleInfo(user.role)
                    return (
                      <TableRow key={user.id} className={!user.is_active ? "opacity-50" : ""}>
                        <TableCell>
                          <div>
                            <p className="font-medium">{user.full_name || user.username}</p>
                            <p className="text-xs text-muted-foreground">{user.email}</p>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge className={roleInfo.color}>
                            {user.role.replace("_", " ")}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {user.access_type === "both" ? (
                            <Badge variant="default" className="bg-green-600">Full</Badge>
                          ) : (
                            <Badge variant="outline">{user.access_type === "ui_only" ? "UI" : "API"}</Badge>
                          )}
                        </TableCell>
                        <TableCell className="capitalize text-sm">{user.auth_provider}</TableCell>
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
                        <TableCell className="text-sm text-muted-foreground">
                          {user.last_login_at
                            ? formatDistanceToNow(new Date(user.last_login_at), { addSuffix: true })
                            : "Never"}
                        </TableCell>
                        <TableCell>
                          {user.is_active ? (
                            <Badge variant="default" className="bg-green-600">Active</Badge>
                          ) : (
                            <Badge variant="destructive">Inactive</Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" className="h-8 w-8">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleEditUser(user)}>
                                <Pencil className="h-4 w-4 mr-2" />
                                Edit User
                              </DropdownMenuItem>
                              {user.is_active && user.email !== currentUser?.email && (
                                <DropdownMenuItem
                                  className="text-red-600"
                                  onClick={() => { setDeactivateUser(user); setDeactivateDialogOpen(true) }}
                                >
                                  <UserX className="h-4 w-4 mr-2" />
                                  Deactivate
                                </DropdownMenuItem>
                              )}
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Invite / Add User Dialog */}
      <Dialog open={inviteDialogOpen} onOpenChange={(open) => {
        setInviteDialogOpen(open)
        if (!open) {
          setInviteEmail("")
          setSelectedDirUser(null)
          setDirectorySearch("")
          setDirectoryUsers([])
          setInviteTab("directory")
          setInviteRole("user")
          setInviteNotes("")
        }
      }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Invite User</DialogTitle>
          </DialogHeader>
          <div className="space-y-5 py-2">
            {/* Tab toggle buttons — full-width pill style */}
            {directoryAvailable && (
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => setInviteTab("directory")}
                  className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border text-sm font-medium transition-colors ${
                    inviteTab === "directory"
                      ? "bg-white dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-foreground shadow-sm"
                      : "bg-gray-100 dark:bg-gray-900 border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Users className="h-4 w-4" />
                  Directory
                </button>
                <button
                  onClick={() => setInviteTab("manual")}
                  className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border text-sm font-medium transition-colors ${
                    inviteTab === "manual"
                      ? "bg-white dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-foreground shadow-sm"
                      : "bg-gray-100 dark:bg-gray-900 border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <AlertTriangle className="h-4 w-4" />
                  Pre-stage
                </button>
              </div>
            )}

            {/* Directory search tab */}
            {inviteTab === "directory" && directoryAvailable ? (
              <div>
                <Label className="font-semibold">Search Directory</Label>
                <div className="relative mt-2">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    value={directorySearch}
                    onChange={(e) => searchDirectory(e.target.value)}
                    placeholder="Search by name or email..."
                    className="pl-9"
                    disabled={inviteLoading}
                  />
                </div>
                {directoryLoading && (
                  <div className="flex justify-center py-4">
                    <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                  </div>
                )}
                {/* Directory user results with avatars */}
                {directoryUsers.length > 0 && (
                  <div className="mt-3 max-h-48 overflow-y-auto border rounded-lg">
                    {directoryUsers.map((dirUser) => {
                      const initials = dirUser.name
                        .split(" ")
                        .map(w => w[0])
                        .join("")
                        .toUpperCase()
                        .slice(0, 2)
                      return (
                        <button
                          key={dirUser.sub}
                          onClick={() => {
                            setInviteEmail(dirUser.email)
                            setSelectedDirUser(dirUser)
                            setDirectoryUsers([])
                            setDirectorySearch("")
                          }}
                          className="w-full flex items-center gap-3 px-4 py-3 hover:bg-muted border-b last:border-b-0 transition-colors"
                        >
                          <div className="h-10 w-10 rounded-full bg-blue-100 dark:bg-blue-900/40 text-blue-600 flex items-center justify-center text-sm font-semibold flex-shrink-0">
                            {initials}
                          </div>
                          <div className="text-left min-w-0">
                            <p className="font-semibold text-sm truncate">{dirUser.name}</p>
                            <p className="text-xs text-muted-foreground truncate">{dirUser.email}</p>
                          </div>
                        </button>
                      )
                    })}
                  </div>
                )}
                {/* Empty state when search returns nothing */}
                {directorySearch.trim() && !directoryLoading && directoryUsers.length === 0 && !inviteEmail && (
                  <p className="mt-3 text-center text-sm text-muted-foreground">
                    All directory users have already been invited
                  </p>
                )}
                {/* Selected user card */}
                {inviteEmail && selectedDirUser && (
                  <div className="mt-3 flex items-center gap-3 p-3 bg-blue-50 dark:bg-blue-900/20 border-2 border-blue-200 dark:border-blue-700 rounded-lg">
                    <div className="min-w-0 flex-1">
                      <p className="font-semibold text-sm text-blue-700 dark:text-blue-300 truncate">
                        {selectedDirUser.name}
                      </p>
                      <p className="text-sm text-blue-600 dark:text-blue-400 truncate">
                        {inviteEmail}
                      </p>
                    </div>
                    <button
                      onClick={() => { setInviteEmail(""); setSelectedDirUser(null) }}
                      className="text-blue-400 hover:text-blue-600 dark:hover:text-blue-300 flex-shrink-0"
                    >
                      <UserX className="h-5 w-5" />
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div>
                {inviteTab === "manual" && (
                  <div className="mb-4 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 flex-shrink-0" />
                    <p className="text-xs text-amber-700 dark:text-amber-400">
                      Pre-staging requires IdP enrollment. This user must be added to
                      the identity provider before they can sign in.
                    </p>
                  </div>
                )}
                <Label htmlFor="email" className="font-semibold">Email Address</Label>
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

            {/* Roles — toggle pill buttons */}
            <div>
              <Label className="font-semibold">Roles *</Label>
              <div className="flex flex-wrap gap-2 mt-2">
                {ROLES.map(r => (
                  <button
                    key={r.value}
                    onClick={() => setInviteRole(r.value)}
                    disabled={inviteLoading}
                    className={`px-4 py-1.5 rounded-lg border text-sm font-medium transition-colors ${
                      inviteRole === r.value
                        ? "bg-purple-100 dark:bg-purple-900/40 border-purple-300 dark:border-purple-600 text-purple-700 dark:text-purple-300"
                        : "bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 text-foreground hover:bg-gray-50 dark:hover:bg-gray-750"
                    }`}
                  >
                    {r.label}
                  </button>
                ))}
              </div>
              {!inviteRole && (
                <p className="text-xs text-muted-foreground mt-1">Select at least one role</p>
              )}
            </div>

            {/* Notes */}
            <div>
              <Label className="font-semibold">Notes (optional)</Label>
              <Textarea
                value={inviteNotes}
                onChange={(e) => setInviteNotes(e.target.value)}
                placeholder="Team, department, or reason for access..."
                className="mt-2 resize-y"
                rows={3}
                disabled={inviteLoading}
              />
            </div>
          </div>

          {/* Footer — full-width buttons */}
          <div className="grid grid-cols-2 gap-3 pt-2">
            <Button
              variant="outline"
              className="w-full"
              onClick={() => setInviteDialogOpen(false)}
              disabled={inviteLoading}
            >
              Cancel
            </Button>
            {inviteTab === "directory" && selectedDirUser ? (
              <Button
                className="w-full"
                onClick={handleAddFromDirectory}
                disabled={inviteLoading || !inviteEmail.trim() || !inviteRole}
              >
                {inviteLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Add User
              </Button>
            ) : (
              <Button
                className="w-full"
                onClick={handleSendInvite}
                disabled={inviteLoading || !inviteEmail.trim() || !inviteRole}
              >
                {inviteLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Send Invitation
              </Button>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Edit User Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserCog className="h-5 w-5" />
              Edit User
            </DialogTitle>
            <DialogDescription>
              {editUser && `Update role and access for ${editUser.full_name || editUser.email}`}
            </DialogDescription>
          </DialogHeader>
          {editUser && (
            <div className="space-y-4 py-4">
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">{editUser.full_name || editUser.username}</p>
                <p className="text-sm text-muted-foreground">{editUser.email}</p>
              </div>
              <div>
                <Label>Role</Label>
                <Select value={editRole} onValueChange={setEditRole} disabled={editLoading}>
                  <SelectTrigger className="mt-2">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ROLES.map(r => (
                      <SelectItem key={r.value} value={r.value}>
                        {r.label} ({r.description})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Access Type</Label>
                <Select value={editAccessType} onValueChange={setEditAccessType} disabled={editLoading}>
                  <SelectTrigger className="mt-2">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ACCESS_TYPES.map(at => (
                      <SelectItem key={at.value} value={at.value}>{at.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialogOpen(false)} disabled={editLoading}>
              Cancel
            </Button>
            <Button onClick={handleSaveEdit} disabled={editLoading || (editRole === editUser?.role && editAccessType === editUser?.access_type)}>
              {editLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Deactivate Confirmation Dialog */}
      <Dialog open={deactivateDialogOpen} onOpenChange={setDeactivateDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-600">
              <ShieldAlert className="h-5 w-5" />
              Deactivate User
            </DialogTitle>
            <DialogDescription>
              This will prevent the user from logging in. This action can be reversed.
            </DialogDescription>
          </DialogHeader>
          {deactivateUser && (
            <div className="py-4">
              <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="font-medium">{deactivateUser.full_name || deactivateUser.username}</p>
                <p className="text-sm text-muted-foreground">{deactivateUser.email}</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Role: {deactivateUser.role.replace("_", " ")}
                </p>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeactivateDialogOpen(false)} disabled={deactivateLoading}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={async () => {
                if (!deactivateUser) return
                setDeactivateLoading(true)
                // There's no dedicated deactivate endpoint, so we can use role change as a placeholder
                // In a real implementation, you'd want a PATCH /users/{id}/status endpoint
                toast({ title: "User deactivation", description: "Feature requires backend endpoint implementation" })
                setDeactivateDialogOpen(false)
                setDeactivateLoading(false)
              }}
              disabled={deactivateLoading}
            >
              {deactivateLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Deactivate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
