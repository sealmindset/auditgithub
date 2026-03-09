"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { KeyRound, Plus, RotateCw, Trash2, Loader2, AlertCircle, ShieldCheck, Clock, Search } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { formatDistanceToNow } from "date-fns"
import { CreateApiKeyDialog } from "@/components/api-keys/CreateApiKeyDialog"
import { RevokeApiKeyDialog } from "@/components/api-keys/RevokeApiKeyDialog"
import { RotateApiKeyDialog } from "@/components/api-keys/RotateApiKeyDialog"
import { Input } from "@/components/ui/input"
import { API_BASE, apiFetch } from "@/lib/api"

interface ApiKeyItem {
  id: string
  name: string
  key_prefix: string
  user_id: string
  user_email: string
  is_service_account: boolean
  organization_id: string
  allowed_tool_categories: string[] | null
  allowed_tools: string[] | null
  allowed_repository_ids: string[] | null
  permission_overrides: string[] | null
  rate_limit_per_hour: number
  is_active: boolean
  expires_at: string | null
  last_used_at: string | null
  created_at: string
  updated_at: string
}

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([])
  const [loading, setLoading] = useState(true)
  const [createOpen, setCreateOpen] = useState(false)
  const [revokeTarget, setRevokeTarget] = useState<ApiKeyItem | null>(null)
  const [rotateTarget, setRotateTarget] = useState<ApiKeyItem | null>(null)
  const [showRevoked, setShowRevoked] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")
  const { toast } = useToast()

  const fetchKeys = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/api/api-keys`, { credentials: "include" })
      if (res.ok) {
        const data = await res.json()
        setKeys(data)
      } else {
        toast({
          title: "Failed to load API keys",
          description: "Please try again later",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error("Failed to fetch API keys:", error)
      toast({
        title: "Connection error",
        description: "Could not connect to API",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchKeys()
  }, [])

  const filteredKeys = searchQuery.trim()
    ? keys.filter(k => k.name.toLowerCase().includes(searchQuery.toLowerCase()) || k.key_prefix.toLowerCase().includes(searchQuery.toLowerCase()) || k.user_email.toLowerCase().includes(searchQuery.toLowerCase()))
    : keys
  const activeKeys = filteredKeys.filter((k) => k.is_active)
  const revokedKeys = filteredKeys.filter((k) => !k.is_active)

  const expiringSoon = keys.filter(k => {
    if (!k.is_active || !k.expires_at) return false
    const diff = new Date(k.expires_at).getTime() - Date.now()
    return diff > 0 && diff < 7 * 24 * 60 * 60 * 1000
  })

  const isExpired = (key: ApiKeyItem) => {
    if (!key.expires_at) return false
    return new Date(key.expires_at) < new Date()
  }

  const getStatusBadge = (key: ApiKeyItem) => {
    if (!key.is_active) return <Badge variant="destructive">Revoked</Badge>
    if (isExpired(key)) return <Badge variant="secondary">Expired</Badge>
    return <Badge variant="default">Active</Badge>
  }

  const getToolScopeDisplay = (key: ApiKeyItem) => {
    if (!key.allowed_tool_categories && !key.allowed_tools) {
      return <span className="text-muted-foreground">All Tools</span>
    }
    const badges: string[] = []
    if (key.allowed_tool_categories) badges.push(...key.allowed_tool_categories)
    if (key.allowed_tools) badges.push(...key.allowed_tools)
    return (
      <div className="flex flex-wrap gap-1">
        {badges.slice(0, 3).map((b) => (
          <Badge key={b} variant="outline" className="text-xs">
            {b}
          </Badge>
        ))}
        {badges.length > 3 && (
          <Badge variant="outline" className="text-xs">
            +{badges.length - 3}
          </Badge>
        )}
      </div>
    )
  }

  const getRepoScopeDisplay = (key: ApiKeyItem) => {
    if (!key.allowed_repository_ids) {
      return <span className="text-muted-foreground">All Repos</span>
    }
    return <span>{key.allowed_repository_ids.length} repo{key.allowed_repository_ids.length !== 1 ? "s" : ""}</span>
  }

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "Never"
    try {
      return formatDistanceToNow(new Date(dateStr), { addSuffix: true })
    } catch {
      return dateStr
    }
  }

  const renderKeyTable = (keyList: ApiKeyItem[]) => (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Key Prefix</TableHead>
          <TableHead>Tool Scope</TableHead>
          <TableHead>Repo Scope</TableHead>
          <TableHead>Rate Limit</TableHead>
          <TableHead>Expires</TableHead>
          <TableHead>Last Used</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {keyList.map((key) => (
          <TableRow key={key.id}>
            <TableCell className="font-medium">
              <div>
                {key.name}
                {key.is_service_account && (
                  <Badge variant="secondary" className="ml-2 text-xs">
                    Service
                  </Badge>
                )}
              </div>
              <div className="text-xs text-muted-foreground">{key.user_email}</div>
            </TableCell>
            <TableCell>
              <code className="text-xs bg-gray-100 px-1 rounded">{key.key_prefix}...</code>
            </TableCell>
            <TableCell>{getToolScopeDisplay(key)}</TableCell>
            <TableCell>{getRepoScopeDisplay(key)}</TableCell>
            <TableCell>{key.rate_limit_per_hour}/hr</TableCell>
            <TableCell>
              {key.expires_at ? formatDate(key.expires_at) : (
                <span className="text-muted-foreground">Never</span>
              )}
            </TableCell>
            <TableCell>{formatDate(key.last_used_at)}</TableCell>
            <TableCell>{getStatusBadge(key)}</TableCell>
            <TableCell className="text-right">
              {key.is_active && (
                <div className="flex justify-end gap-1">
                  <Button
                    size="sm"
                    variant="ghost"
                    title="Rotate key"
                    onClick={() => setRotateTarget(key)}
                  >
                    <RotateCw className="h-4 w-4" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    title="Revoke key"
                    onClick={() => setRevokeTarget(key)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )

  return (
    <div className="flex flex-1 flex-col gap-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">API Keys</h1>
          <p className="text-muted-foreground">
            Manage API keys for programmatic access to AuditGitHub
          </p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Generate New Key
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-blue-100 dark:bg-blue-900/30 p-2">
                <KeyRound className="h-5 w-5 text-blue-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Total Keys</p>
                <p className="text-2xl font-bold">{keys.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-green-100 dark:bg-green-900/30 p-2">
                <ShieldCheck className="h-5 w-5 text-green-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Active</p>
                <p className="text-2xl font-bold">{keys.filter(k => k.is_active).length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-red-100 dark:bg-red-900/30 p-2">
                <Trash2 className="h-5 w-5 text-red-600" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Revoked</p>
                <p className="text-2xl font-bold">{keys.filter(k => !k.is_active).length}</p>
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
                <p className="text-sm text-muted-foreground">Expiring Soon</p>
                <p className="text-2xl font-bold">{expiringSoon.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Keys */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <KeyRound className="h-5 w-5" />
                Active Keys
              </CardTitle>
              <CardDescription>
                API keys currently in use. Keys authenticate via the X-API-Key header.
              </CardDescription>
            </div>
            <div className="relative w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search keys..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
            </div>
          ) : activeKeys.length === 0 ? (
            <div className="text-center py-12">
              <AlertCircle className="h-12 w-12 mx-auto mb-4 text-gray-400" />
              <p className="text-gray-600 font-medium mb-2">No active API keys</p>
              <p className="text-sm text-muted-foreground mb-4">
                Generate a key to enable programmatic access
              </p>
              <Button variant="outline" onClick={() => setCreateOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Generate New Key
              </Button>
            </div>
          ) : (
            renderKeyTable(activeKeys)
          )}
        </CardContent>
      </Card>

      {/* Revoked Keys (collapsible) */}
      {revokedKeys.length > 0 && (
        <Card>
          <CardHeader
            className="cursor-pointer"
            onClick={() => setShowRevoked(!showRevoked)}
          >
            <CardTitle className="text-sm flex items-center gap-2">
              Revoked Keys ({revokedKeys.length})
              <span className="text-xs text-muted-foreground">
                {showRevoked ? "Click to collapse" : "Click to expand"}
              </span>
            </CardTitle>
          </CardHeader>
          {showRevoked && (
            <CardContent>{renderKeyTable(revokedKeys)}</CardContent>
          )}
        </Card>
      )}

      {/* Dialogs */}
      <CreateApiKeyDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={fetchKeys}
      />

      {revokeTarget && (
        <RevokeApiKeyDialog
          open={!!revokeTarget}
          onOpenChange={(open) => !open && setRevokeTarget(null)}
          keyId={revokeTarget.id}
          keyName={revokeTarget.name}
          keyPrefix={revokeTarget.key_prefix}
          onRevoked={fetchKeys}
        />
      )}

      {rotateTarget && (
        <RotateApiKeyDialog
          open={!!rotateTarget}
          onOpenChange={(open) => !open && setRotateTarget(null)}
          keyId={rotateTarget.id}
          keyName={rotateTarget.name}
          keyPrefix={rotateTarget.key_prefix}
          onRotated={fetchKeys}
        />
      )}
    </div>
  )
}
