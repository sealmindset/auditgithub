"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { AlertTriangle, Copy, Check, Loader2 } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { API_BASE, apiFetch } from "@/lib/api"

interface RotateApiKeyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  keyId: string
  keyName: string
  keyPrefix: string
  onRotated: () => void
}

export function RotateApiKeyDialog({
  open,
  onOpenChange,
  keyId,
  keyName,
  keyPrefix,
  onRotated,
}: RotateApiKeyDialogProps) {
  const [loading, setLoading] = useState(false)
  const [newKey, setNewKey] = useState<string | null>(null)
  const [newKeyPrefix, setNewKeyPrefix] = useState("")
  const [copied, setCopied] = useState(false)
  const { toast } = useToast()

  const handleRotate = async () => {
    setLoading(true)
    try {
      const res = await apiFetch(`${API_BASE}/api/api-keys/${keyId}/rotate`, {
        method: "POST",
        credentials: "include",
      })
      if (res.ok) {
        const data = await res.json()
        setNewKey(data.key)
        setNewKeyPrefix(data.key_prefix)
        onRotated()
        toast({ title: "API key rotated successfully" })
      } else {
        const err = await res.json().catch(() => ({}))
        toast({
          title: "Failed to rotate key",
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

  const handleCopy = () => {
    if (newKey) {
      navigator.clipboard.writeText(newKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const handleClose = (isOpen: boolean) => {
    if (!isOpen) {
      setNewKey(null)
      setNewKeyPrefix("")
      setCopied(false)
    }
    onOpenChange(isOpen)
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{newKey ? "New Key Generated" : "Rotate API Key"}</DialogTitle>
          <DialogDescription>
            {newKey
              ? "Copy your new API key now. It will not be shown again."
              : "This will immediately invalidate the old key and generate a new one with the same configuration."}
          </DialogDescription>
        </DialogHeader>

        {!newKey ? (
          <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 flex items-start gap-2">
            <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5 shrink-0" />
            <div className="text-sm text-yellow-800">
              <p className="font-medium">Rotating key:</p>
              <p className="mt-1">
                <strong>{keyName}</strong> ({keyPrefix}...)
              </p>
              <p className="mt-1">
                The old key will stop working immediately. A new key will be generated with the same
                tool scope, repository scope, and rate limit settings.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 flex items-start gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5 shrink-0" />
              <p className="text-sm text-yellow-800">
                This key will only be shown once. Copy it now and store it securely.
              </p>
            </div>
            <div className="space-y-2">
              <Label>New API Key</Label>
              <div className="flex gap-2">
                <Input
                  readOnly
                  value={newKey}
                  className="font-mono text-sm bg-gray-50"
                />
                <Button variant="outline" size="icon" onClick={handleCopy}>
                  {copied ? (
                    <Check className="h-4 w-4 text-green-600" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
            </div>
            <p className="text-sm text-muted-foreground">
              New key prefix: <code className="bg-gray-100 px-1 rounded">{newKeyPrefix}</code>
            </p>
          </div>
        )}

        <DialogFooter>
          {!newKey ? (
            <>
              <Button variant="outline" onClick={() => handleClose(false)} disabled={loading}>
                Cancel
              </Button>
              <Button onClick={handleRotate} disabled={loading}>
                {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Rotate Key
              </Button>
            </>
          ) : (
            <Button onClick={() => handleClose(false)}>Done</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
