"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Monitor, Trash2, Edit2, AlertCircle, Loader2 } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { formatDistanceToNow } from "date-fns"
import { API_BASE, apiFetch } from "@/lib/api"

interface DeviceAuthorization {
  id: string
  device_name: string
  client_name: string
  created_at: string
  last_used_at: string
  is_active: boolean
  provider: string
  user_agent: string | null
  token_refresh_count: number
}

export default function MyDevicesPage() {
  const [devices, setDevices] = useState<DeviceAuthorization[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedDevice, setSelectedDevice] = useState<DeviceAuthorization | null>(null)
  const [newName, setNewName] = useState("")
  const [renameDialogOpen, setRenameDialogOpen] = useState(false)
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false)
  const [actionLoading, setActionLoading] = useState(false)
  const { toast } = useToast()

  const fetchDevices = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/auth/device/authorizations`, {
        credentials: "include"
      })

      if (res.ok) {
        const data = await res.json()
        setDevices(data)
      } else {
        toast({
          title: "Failed to load devices",
          description: "Please try again later",
          variant: "destructive"
        })
      }
    } catch (error) {
      console.error("Failed to fetch devices:", error)
      toast({
        title: "Connection error",
        description: "Could not connect to API",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDevices()

    // Poll every 30 seconds for updates
    const interval = setInterval(fetchDevices, 30000)
    return () => clearInterval(interval)
  }, [])

  const handleRevoke = async () => {
    if (!selectedDevice) return

    setActionLoading(true)

    try {
      const res = await fetch(
        `${API_BASE}/auth/device/authorizations/${selectedDevice.id}`,
        {
          method: "DELETE",
          credentials: "include"
        }
      )

      if (res.ok) {
        toast({
          title: "Device revoked successfully",
          description: "The device will no longer have access to your account"
        })
        setRevokeDialogOpen(false)
        setSelectedDevice(null)
        fetchDevices()
      } else {
        toast({
          title: "Failed to revoke device",
          description: "Please try again",
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
      setActionLoading(false)
    }
  }

  const handleRename = async () => {
    if (!selectedDevice || !newName.trim()) return

    setActionLoading(true)

    try {
      const res = await fetch(
        `${API_BASE}/auth/device/authorizations/${selectedDevice.id}`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ device_name: newName.trim() })
        }
      )

      if (res.ok) {
        toast({
          title: "Device renamed successfully"
        })
        setRenameDialogOpen(false)
        setSelectedDevice(null)
        setNewName("")
        fetchDevices()
      } else {
        toast({
          title: "Failed to rename device",
          description: "Please try again",
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
      setActionLoading(false)
    }
  }

  const openRenameDialog = (device: DeviceAuthorization) => {
    setSelectedDevice(device)
    setNewName(device.device_name)
    setRenameDialogOpen(true)
  }

  const openRevokeDialog = (device: DeviceAuthorization) => {
    setSelectedDevice(device)
    setRevokeDialogOpen(true)
  }

  return (
    <div className="container mx-auto py-8 px-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Monitor className="h-5 w-5" />
            My Authorized Devices
          </CardTitle>
          <CardDescription>
            Manage devices and applications that have access to your account.
            You can rename or revoke access at any time.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
            </div>
          ) : devices.length === 0 ? (
            <div className="text-center py-12">
              <AlertCircle className="h-12 w-12 mx-auto mb-4 text-gray-400" />
              <p className="text-gray-600 font-medium mb-2">No authorized devices yet</p>
              <p className="text-sm text-gray-500">
                Use the AuditGitHub CLI or other tools to authorize devices
              </p>
              <div className="mt-6 p-4 bg-gray-50 rounded-lg max-w-md mx-auto">
                <p className="text-sm text-gray-700 font-mono">
                  ./cli/auditgh-cli.py login
                </p>
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Device Name</TableHead>
                    <TableHead>Application</TableHead>
                    <TableHead>Provider</TableHead>
                    <TableHead>Authorized</TableHead>
                    <TableHead>Last Used</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {devices.map((device) => (
                    <TableRow key={device.id}>
                      <TableCell className="font-medium">
                        {device.device_name}
                      </TableCell>
                      <TableCell>{device.client_name}</TableCell>
                      <TableCell className="capitalize">{device.provider}</TableCell>
                      <TableCell className="text-sm text-gray-600">
                        {formatDistanceToNow(new Date(device.created_at), {
                          addSuffix: true
                        })}
                      </TableCell>
                      <TableCell className="text-sm text-gray-600">
                        {formatDistanceToNow(new Date(device.last_used_at), {
                          addSuffix: true
                        })}
                      </TableCell>
                      <TableCell>
                        {device.is_active ? (
                          <Badge variant="default" className="bg-green-600">
                            Active
                          </Badge>
                        ) : (
                          <Badge variant="destructive">Revoked</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex gap-2 justify-end">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => openRenameDialog(device)}
                            disabled={!device.is_active}
                            title="Rename device"
                          >
                            <Edit2 className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => openRevokeDialog(device)}
                            disabled={!device.is_active}
                            title="Revoke device"
                            className="text-red-600 hover:text-red-700 hover:bg-red-50"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Rename Dialog */}
      <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Device</DialogTitle>
            <DialogDescription>
              Give this device a more recognizable name
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div>
              <Label htmlFor="device-name">Device Name</Label>
              <Input
                id="device-name"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="My Laptop"
                className="mt-2"
                disabled={actionLoading}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRenameDialogOpen(false)}
              disabled={actionLoading}
            >
              Cancel
            </Button>
            <Button onClick={handleRename} disabled={actionLoading || !newName.trim()}>
              {actionLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Revoke Dialog */}
      <Dialog open={revokeDialogOpen} onOpenChange={setRevokeDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke Device Access</DialogTitle>
            <DialogDescription>
              Are you sure you want to revoke access for this device?
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <AlertCircle className="h-5 w-5 text-yellow-600 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-yellow-900 mb-1">
                    This action cannot be undone
                  </p>
                  <p className="text-sm text-yellow-700">
                    The device will lose access to your account and will need to
                    re-authorize to regain access.
                  </p>
                </div>
              </div>
            </div>
            {selectedDevice && (
              <div className="mt-4 space-y-2">
                <div className="text-sm">
                  <span className="font-medium">Device:</span>{" "}
                  <span className="text-gray-600">{selectedDevice.device_name}</span>
                </div>
                <div className="text-sm">
                  <span className="font-medium">Application:</span>{" "}
                  <span className="text-gray-600">{selectedDevice.client_name}</span>
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRevokeDialogOpen(false)}
              disabled={actionLoading}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRevoke}
              disabled={actionLoading}
            >
              {actionLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Revoke Access
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
