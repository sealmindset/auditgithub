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
import { Users, UserPlus, Mail, Shield, Loader2, AlertCircle } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { formatDistanceToNow } from "date-fns"

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

export default function AdminUsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [invitations, setInvitations] = useState<Invitation[]>([])
  const [loading, setLoading] = useState(true)
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState("user")
  const [inviteAccessType, setInviteAccessType] = useState("ui_only")
  const [inviteLoading, setInviteLoading] = useState(false)
  const { toast } = useToast()

  useEffect(() => {
    fetchUsers()
    fetchInvitations()
  }, [])

  const fetchUsers = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/users", {
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
      const res = await fetch("http://localhost:8000/api/invitations", {
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

  const handleSendInvite = async () => {
    if (!inviteEmail.trim()) return

    setInviteLoading(true)

    try {
      const res = await fetch("http://localhost:8000/api/invitations", {
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
      <Dialog open={inviteDialogOpen} onOpenChange={setInviteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Invite New User</DialogTitle>
            <DialogDescription>
              Send an invitation to a new user. They'll receive a link to join the platform.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div>
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
