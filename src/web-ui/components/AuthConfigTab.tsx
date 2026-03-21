"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Loader2, CheckCircle2, XCircle, Plus, Trash2, Users, Key, Shield } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog"
import { API_BASE, apiFetch } from "@/lib/api"

interface OIDCProvider {
    id: string
    name: string
    provider_type: "entra" | "okta"
    client_id: string
    client_secret_set: boolean
    tenant_id?: string
    authority?: string
    discovery_url?: string
    enabled: boolean
    created_at: string
}

interface User {
    id: string
    email: string
    name: string
    provider: string
    roles: string[]
    organizations: string[]
    is_active: boolean
    last_login_at: string | null
    created_at: string
}

interface Role {
    id: string
    name: string
    level: number
    description: string
    permissions: string[]
}

export default function AuthConfigTab() {
    const { toast } = useToast()
    const [loading, setLoading] = useState(true)
    const [providers, setProviders] = useState<OIDCProvider[]>([])
    const [users, setUsers] = useState<User[]>([])
    const [roles, setRoles] = useState<Role[]>([])

    // Provider form state
    const [showProviderDialog, setShowProviderDialog] = useState(false)
    const [editingProvider, setEditingProvider] = useState<OIDCProvider | null>(null)
    const [providerName, setProviderName] = useState("")
    const [providerType, setProviderType] = useState<"entra" | "okta">("entra")
    const [clientId, setClientId] = useState("")
    const [clientSecret, setClientSecret] = useState("")
    const [tenantId, setTenantId] = useState("")
    const [authority, setAuthority] = useState("")
    const [providerEnabled, setProviderEnabled] = useState(true)
    const [savingProvider, setSavingProvider] = useState(false)
    const [testingProvider, setTestingProvider] = useState(false)

    // User invite form state
    const [showUserDialog, setShowUserDialog] = useState(false)
    const [inviteEmail, setInviteEmail] = useState("")
    const [inviteName, setInviteName] = useState("")
    const [inviteRole, setInviteRole] = useState("")
    const [invitingUser, setInvitingUser] = useState(false)

    useEffect(() => {
        loadData()
    }, [])

    const loadData = async () => {
        setLoading(true)
        try {
            await Promise.all([
                loadProviders(),
                loadUsers(),
                loadRoles()
            ])
        } finally {
            setLoading(false)
        }
    }

    const loadProviders = async () => {
        try {
            const res = await apiFetch(`${API_BASE}/auth/providers`)
            if (res.ok) {
                const data = await res.json()
                setProviders(data.providers || [])
            }
        } catch (error) {
            console.error("Failed to load OIDC providers:", error)
        }
    }

    const loadUsers = async () => {
        try {
            const res = await apiFetch(`${API_BASE}/auth/users`)
            if (res.ok) {
                const data = await res.json()
                setUsers(data.users || [])
            }
        } catch (error) {
            console.error("Failed to load users:", error)
        }
    }

    const loadRoles = async () => {
        try {
            const res = await apiFetch(`${API_BASE}/rbac/roles`)
            if (res.ok) {
                const data = await res.json()
                setRoles(data.roles || [])
            }
        } catch (error) {
            console.error("Failed to load roles:", error)
        }
    }

    const handleSaveProvider = async () => {
        setSavingProvider(true)
        try {
            const payload = {
                name: providerName,
                provider_type: providerType,
                client_id: clientId,
                client_secret: clientSecret || undefined,
                tenant_id: tenantId || undefined,
                authority: authority || undefined,
                enabled: providerEnabled
            }

            const url = editingProvider
                ? `${API_BASE}/auth/providers/${editingProvider.id}`
                : `${API_BASE}/auth/providers`

            const method = editingProvider ? "PUT" : "POST"

            const res = await fetch(url, {
                method,
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            })

            if (res.ok) {
                toast({
                    title: "Success",
                    description: `OIDC provider ${editingProvider ? "updated" : "created"} successfully`
                })
                setShowProviderDialog(false)
                resetProviderForm()
                loadProviders()
            } else {
                const error = await res.json()
                toast({
                    title: "Error",
                    description: error.detail || "Failed to save provider",
                    variant: "destructive"
                })
            }
        } catch (error) {
            toast({
                title: "Error",
                description: "Failed to save OIDC provider",
                variant: "destructive"
            })
        } finally {
            setSavingProvider(false)
        }
    }

    const handleTestProvider = async (providerId: string) => {
        setTestingProvider(true)
        try {
            const res = await apiFetch(`${API_BASE}/auth/providers/${providerId}/test`, {
                method: "POST"
            })
            const data = await res.json()

            toast({
                title: data.success ? "Success" : "Error",
                description: data.message,
                variant: data.success ? "default" : "destructive"
            })
        } catch (error) {
            toast({
                title: "Error",
                description: "Failed to test provider connection",
                variant: "destructive"
            })
        } finally {
            setTestingProvider(false)
        }
    }

    const handleDeleteProvider = async (providerId: string) => {
        if (!confirm("Are you sure you want to delete this OIDC provider?")) return

        try {
            const res = await apiFetch(`${API_BASE}/auth/providers/${providerId}`, {
                method: "DELETE"
            })

            if (res.ok) {
                toast({
                    title: "Success",
                    description: "Provider deleted successfully"
                })
                loadProviders()
            }
        } catch (error) {
            toast({
                title: "Error",
                description: "Failed to delete provider",
                variant: "destructive"
            })
        }
    }

    const handleInviteUser = async () => {
        setInvitingUser(true)
        try {
            const res = await apiFetch(`${API_BASE}/auth/users/invite`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email: inviteEmail,
                    name: inviteName,
                    role: inviteRole
                })
            })

            if (res.ok) {
                toast({
                    title: "Success",
                    description: "User invitation sent successfully"
                })
                setShowUserDialog(false)
                resetUserForm()
                loadUsers()
            } else {
                const error = await res.json()
                toast({
                    title: "Error",
                    description: error.detail || "Failed to invite user",
                    variant: "destructive"
                })
            }
        } catch (error) {
            toast({
                title: "Error",
                description: "Failed to invite user",
                variant: "destructive"
            })
        } finally {
            setInvitingUser(false)
        }
    }

    const handleToggleUserActive = async (userId: string, isActive: boolean) => {
        try {
            const res = await apiFetch(`${API_BASE}/auth/users/${userId}`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ is_active: !isActive })
            })

            if (res.ok) {
                toast({
                    title: "Success",
                    description: `User ${!isActive ? "activated" : "deactivated"} successfully`
                })
                loadUsers()
            }
        } catch (error) {
            toast({
                title: "Error",
                description: "Failed to update user status",
                variant: "destructive"
            })
        }
    }

    const resetProviderForm = () => {
        setEditingProvider(null)
        setProviderName("")
        setProviderType("entra")
        setClientId("")
        setClientSecret("")
        setTenantId("")
        setAuthority("")
        setProviderEnabled(true)
    }

    const resetUserForm = () => {
        setInviteEmail("")
        setInviteName("")
        setInviteRole("")
    }

    const openEditProvider = (provider: OIDCProvider) => {
        setEditingProvider(provider)
        setProviderName(provider.name)
        setProviderType(provider.provider_type)
        setClientId(provider.client_id)
        setTenantId(provider.tenant_id || "")
        setAuthority(provider.authority || "")
        setProviderEnabled(provider.enabled)
        setShowProviderDialog(true)
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center p-8">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    return (
        <div className="space-y-6">
            {/* New Admin Panel Alert */}
            <Alert className="border-blue-200 bg-blue-50">
                <Shield className="h-5 w-5 text-blue-600" />
                <AlertTitle className="text-blue-900 font-semibold">
                    Enhanced User & Role Management Available
                </AlertTitle>
                <AlertDescription className="text-blue-800">
                    <p className="mb-2">
                        A new comprehensive admin panel is now available with advanced user management,
                        invitation system, and role-based access control (RBAC).
                    </p>
                    <Button
                        onClick={() => window.location.href = '/admin/users'}
                        variant="outline"
                        className="border-blue-300 text-blue-700 hover:bg-blue-100"
                    >
                        <Users className="h-4 w-4 mr-2" />
                        Go to Admin Panel
                    </Button>
                </AlertDescription>
            </Alert>

            {/* OIDC Providers Section */}
            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <div>
                            <CardTitle className="flex items-center gap-2">
                                <Key className="h-5 w-5" />
                                OIDC / SSO Providers
                            </CardTitle>
                            <CardDescription>
                                Configure authentication providers for Single Sign-On (SSO)
                            </CardDescription>
                        </div>
                        <Dialog open={showProviderDialog} onOpenChange={setShowProviderDialog}>
                            <DialogTrigger asChild>
                                <Button onClick={resetProviderForm}>
                                    <Plus className="h-4 w-4 mr-2" />
                                    Add Provider
                                </Button>
                            </DialogTrigger>
                            <DialogContent className="max-w-2xl">
                                <DialogHeader>
                                    <DialogTitle>
                                        {editingProvider ? "Edit" : "Add"} OIDC Provider
                                    </DialogTitle>
                                    <DialogDescription>
                                        Configure an OIDC/OAuth2 provider for authentication
                                    </DialogDescription>
                                </DialogHeader>
                                <div className="grid gap-4 py-4">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="grid gap-2">
                                            <Label htmlFor="provider-name">Provider Name</Label>
                                            <Input
                                                id="provider-name"
                                                placeholder="e.g., Corporate SSO"
                                                value={providerName}
                                                onChange={(e) => setProviderName(e.target.value)}
                                            />
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="provider-type">Provider Type</Label>
                                            <Select value={providerType} onValueChange={(v) => setProviderType(v as "entra" | "okta")}>
                                                <SelectTrigger>
                                                    <SelectValue />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    <SelectItem value="entra">Microsoft Entra ID</SelectItem>
                                                    <SelectItem value="okta">Okta</SelectItem>
                                                </SelectContent>
                                            </Select>
                                        </div>
                                    </div>

                                    <div className="grid gap-2">
                                        <Label htmlFor="client-id">Client ID</Label>
                                        <Input
                                            id="client-id"
                                            placeholder="Application (client) ID"
                                            value={clientId}
                                            onChange={(e) => setClientId(e.target.value)}
                                        />
                                    </div>

                                    <div className="grid gap-2">
                                        <Label htmlFor="client-secret">Client Secret</Label>
                                        <Input
                                            id="client-secret"
                                            type="password"
                                            placeholder={editingProvider?.client_secret_set ? "••••••••••••••••" : "Client secret"}
                                            value={clientSecret}
                                            onChange={(e) => setClientSecret(e.target.value)}
                                        />
                                        {editingProvider?.client_secret_set && (
                                            <p className="text-xs text-muted-foreground">
                                                Leave blank to keep existing secret
                                            </p>
                                        )}
                                    </div>

                                    {providerType === "entra" && (
                                        <div className="grid gap-2">
                                            <Label htmlFor="tenant-id">Tenant ID</Label>
                                            <Input
                                                id="tenant-id"
                                                placeholder="Directory (tenant) ID or domain"
                                                value={tenantId}
                                                onChange={(e) => setTenantId(e.target.value)}
                                            />
                                        </div>
                                    )}

                                    {providerType === "okta" && (
                                        <div className="grid gap-2">
                                            <Label htmlFor="authority">Okta Domain</Label>
                                            <Input
                                                id="authority"
                                                placeholder="https://your-domain.okta.com"
                                                value={authority}
                                                onChange={(e) => setAuthority(e.target.value)}
                                            />
                                        </div>
                                    )}

                                    <div className="flex items-center justify-between">
                                        <div className="space-y-0.5">
                                            <Label>Enable Provider</Label>
                                            <p className="text-sm text-muted-foreground">
                                                Allow users to authenticate with this provider
                                            </p>
                                        </div>
                                        <Switch
                                            checked={providerEnabled}
                                            onCheckedChange={setProviderEnabled}
                                        />
                                    </div>
                                </div>
                                <DialogFooter>
                                    <Button variant="outline" onClick={() => setShowProviderDialog(false)}>
                                        Cancel
                                    </Button>
                                    <Button onClick={handleSaveProvider} disabled={savingProvider || !providerName || !clientId}>
                                        {savingProvider && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                        {editingProvider ? "Update" : "Create"} Provider
                                    </Button>
                                </DialogFooter>
                            </DialogContent>
                        </Dialog>
                    </div>
                </CardHeader>
                <CardContent>
                    {providers.length === 0 ? (
                        <div className="text-center py-8 text-muted-foreground">
                            No OIDC providers configured. Add one to enable SSO authentication.
                        </div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Name</TableHead>
                                    <TableHead>Type</TableHead>
                                    <TableHead>Client ID</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead className="text-right">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {providers.map((provider) => (
                                    <TableRow key={provider.name || provider.id}>
                                        <TableCell className="font-medium">{provider.name}</TableCell>
                                        <TableCell>
                                            {provider.provider_type === "entra" ? "Microsoft Entra ID" : "Okta"}
                                        </TableCell>
                                        <TableCell className="font-mono text-xs">{provider.client_id}</TableCell>
                                        <TableCell>
                                            <Badge variant={provider.enabled ? "default" : "secondary"}>
                                                {provider.enabled ? "Enabled" : "Disabled"}
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="text-right">
                                            <div className="flex justify-end gap-2">
                                                <Button
                                                    variant="outline"
                                                    size="sm"
                                                    onClick={() => handleTestProvider(provider.id || provider.name)}
                                                    disabled={testingProvider}
                                                >
                                                    Test
                                                </Button>
                                                <Button
                                                    variant="outline"
                                                    size="sm"
                                                    onClick={() => openEditProvider(provider)}
                                                >
                                                    Edit
                                                </Button>
                                                <Button
                                                    variant="outline"
                                                    size="sm"
                                                    onClick={() => handleDeleteProvider(provider.id || provider.name)}
                                                >
                                                    <Trash2 className="h-4 w-4" />
                                                </Button>
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>

            {/* User Management Section */}
            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <div>
                            <CardTitle className="flex items-center gap-2">
                                <Users className="h-5 w-5" />
                                User Management
                            </CardTitle>
                            <CardDescription>
                                Manage user access and permissions
                            </CardDescription>
                        </div>
                        <Dialog open={showUserDialog} onOpenChange={setShowUserDialog}>
                            <DialogTrigger asChild>
                                <Button onClick={resetUserForm}>
                                    <Plus className="h-4 w-4 mr-2" />
                                    Invite User
                                </Button>
                            </DialogTrigger>
                            <DialogContent>
                                <DialogHeader>
                                    <DialogTitle>Invite User</DialogTitle>
                                    <DialogDescription>
                                        Send an invitation to grant a user access to the platform
                                    </DialogDescription>
                                </DialogHeader>
                                <div className="grid gap-4 py-4">
                                    <div className="grid gap-2">
                                        <Label htmlFor="user-email">Email</Label>
                                        <Input
                                            id="user-email"
                                            type="email"
                                            placeholder="user@example.com"
                                            value={inviteEmail}
                                            onChange={(e) => setInviteEmail(e.target.value)}
                                        />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="user-name">Name</Label>
                                        <Input
                                            id="user-name"
                                            placeholder="Full name"
                                            value={inviteName}
                                            onChange={(e) => setInviteName(e.target.value)}
                                        />
                                    </div>
                                    <div className="grid gap-2">
                                        <Label htmlFor="user-role">Role</Label>
                                        <Select value={inviteRole} onValueChange={setInviteRole}>
                                            <SelectTrigger>
                                                <SelectValue placeholder="Select role" />
                                            </SelectTrigger>
                                            <SelectContent>
                                                {roles.map((role) => (
                                                    <SelectItem key={role.id} value={role.name}>
                                                        {role.name} - {role.description}
                                                    </SelectItem>
                                                ))}
                                            </SelectContent>
                                        </Select>
                                    </div>
                                </div>
                                <DialogFooter>
                                    <Button variant="outline" onClick={() => setShowUserDialog(false)}>
                                        Cancel
                                    </Button>
                                    <Button onClick={handleInviteUser} disabled={invitingUser || !inviteEmail || !inviteRole}>
                                        {invitingUser && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                        Send Invitation
                                    </Button>
                                </DialogFooter>
                            </DialogContent>
                        </Dialog>
                    </div>
                </CardHeader>
                <CardContent>
                    {users.length === 0 ? (
                        <div className="text-center py-8 text-muted-foreground">
                            No users found. Invite users to grant them access.
                        </div>
                    ) : (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Name</TableHead>
                                    <TableHead>Email</TableHead>
                                    <TableHead>Roles</TableHead>
                                    <TableHead>Provider</TableHead>
                                    <TableHead>Last Login</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead className="text-right">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {users.map((user) => (
                                    <TableRow key={user.id}>
                                        <TableCell className="font-medium">{user.name}</TableCell>
                                        <TableCell>{user.email}</TableCell>
                                        <TableCell>
                                            <div className="flex gap-1">
                                                {user.roles.map((role) => (
                                                    <Badge key={role} variant="outline" className="text-xs">
                                                        {role}
                                                    </Badge>
                                                ))}
                                            </div>
                                        </TableCell>
                                        <TableCell className="capitalize">{user.provider}</TableCell>
                                        <TableCell className="text-sm text-muted-foreground">
                                            {user.last_login_at
                                                ? new Date(user.last_login_at).toLocaleDateString()
                                                : "Never"
                                            }
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant={user.is_active ? "default" : "secondary"}>
                                                {user.is_active ? "Active" : "Inactive"}
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="text-right">
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={() => handleToggleUserActive(user.id, user.is_active)}
                                            >
                                                {user.is_active ? "Deactivate" : "Activate"}
                                            </Button>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>

            {/* Roles & Permissions Section */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        Roles & Permissions
                    </CardTitle>
                    <CardDescription>
                        View and manage role-based access control (RBAC)
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Role</TableHead>
                                <TableHead>Level</TableHead>
                                <TableHead>Description</TableHead>
                                <TableHead>Permissions</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {roles.map((role) => (
                                <TableRow key={role.id}>
                                    <TableCell className="font-medium">{role.name}</TableCell>
                                    <TableCell>
                                        <Badge variant="outline">Level {role.level}</Badge>
                                    </TableCell>
                                    <TableCell className="text-sm text-muted-foreground">
                                        {role.description}
                                    </TableCell>
                                    <TableCell>
                                        <div className="flex flex-wrap gap-1">
                                            {role.permissions.slice(0, 3).map((perm) => (
                                                <Badge key={perm} variant="secondary" className="text-xs">
                                                    {perm}
                                                </Badge>
                                            ))}
                                            {role.permissions.length > 3 && (
                                                <Badge variant="secondary" className="text-xs">
                                                    +{role.permissions.length - 3} more
                                                </Badge>
                                            )}
                                        </div>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    )
}
