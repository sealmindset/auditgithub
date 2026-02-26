"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { AlertTriangle, Loader2 } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

interface RevokeApiKeyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  keyId: string
  keyName: string
  keyPrefix: string
  onRevoked: () => void
}

export function RevokeApiKeyDialog({
  open,
  onOpenChange,
  keyId,
  keyName,
  keyPrefix,
  onRevoked,
}: RevokeApiKeyDialogProps) {
  const [loading, setLoading] = useState(false)
  const { toast } = useToast()

  const handleRevoke = async () => {
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/api/api-keys/${keyId}`, {
        method: "DELETE",
        credentials: "include",
      })
      if (res.ok) {
        toast({ title: "API key revoked", description: `Key "${keyName}" has been revoked` })
        onRevoked()
        onOpenChange(false)
      } else {
        const err = await res.json().catch(() => ({}))
        toast({
          title: "Failed to revoke key",
          description: err.detail || "Please try again",
          variant: "destructive",
        })
      }
    } catch {
      toast({
        title: "Connection error",
        description: "Could not connect to API",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Revoke API Key</DialogTitle>
          <DialogDescription>
            This action cannot be undone. Any systems using this key will lose access immediately.
          </DialogDescription>
        </DialogHeader>

        <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 flex items-start gap-2">
          <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5 shrink-0" />
          <div className="text-sm text-yellow-800">
            <p className="font-medium">You are about to revoke:</p>
            <p className="mt-1">
              <strong>{keyName}</strong> ({keyPrefix}...)
            </p>
            <p className="mt-1">
              All API calls using this key will immediately receive 401 Unauthorized responses.
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={loading}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleRevoke} disabled={loading}>
            {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Revoke Key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
