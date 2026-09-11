"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Settings, Clock, Shield, Loader2, CheckCircle2 } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { API_BASE, apiFetch } from "@/lib/api"
import { PageHeader, PageShell } from "@/components/ui/page-header"
import { Badge } from "@/components/ui/badge"

interface SessionSettings {
  inactivity_timeout_minutes: number
  absolute_timeout_hours: number
  bounds: {
    inactivity_timeout_minutes: { min: number; max: number }
    absolute_timeout_hours: { min: number; max: number }
  }
}

export default function AdminSettingsPage() {
  const [settings, setSettings] = useState<SessionSettings | null>(null)
  const [inactivity, setInactivity] = useState(30)
  const [absolute, setAbsolute] = useState(8)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const { toast } = useToast()

  useEffect(() => {
    fetchSettings()
  }, [])

  const fetchSettings = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/settings/session`, {
        credentials: "include"
      })
      if (res.ok) {
        const data: SessionSettings = await res.json()
        setSettings(data)
        setInactivity(data.inactivity_timeout_minutes)
        setAbsolute(data.absolute_timeout_hours)
      } else if (res.status === 403) {
        toast({
          title: "Access denied",
          description: "Super Admin role required to manage session settings",
          variant: "destructive"
        })
      }
    } catch {
      toast({
        title: "Connection error",
        description: "Could not load session settings",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    setSaved(false)
    try {
      const res = await apiFetch(`${API_BASE}/settings/session`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          inactivity_timeout_minutes: inactivity,
          absolute_timeout_hours: absolute,
        })
      })
      if (res.ok) {
        const data = await res.json()
        setSettings({ ...settings!, ...data })
        setSaved(true)
        toast({ title: "Settings saved", description: "Session timeout settings updated" })
        setTimeout(() => setSaved(false), 3000)
      } else {
        const err = await res.json()
        toast({
          title: "Failed to save",
          description: err.detail || "Please check the values and try again",
          variant: "destructive"
        })
      }
    } catch {
      toast({
        title: "Connection error",
        description: "Could not save settings",
        variant: "destructive"
      })
    } finally {
      setSaving(false)
    }
  }

  const formatDuration = (minutes: number): string => {
    if (minutes < 60) return `${minutes} minutes`
    const hrs = Math.floor(minutes / 60)
    const mins = minutes % 60
    return mins > 0 ? `${hrs}h ${mins}m` : `${hrs} hours`
  }

  if (loading) {
    return (
      <div className="container mx-auto py-8 px-4">
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    )
  }

  if (!settings) {
    return (
      <div className="container mx-auto py-8 px-4">
        <p className="text-muted-foreground">Unable to load session settings.</p>
      </div>
    )
  }

  const bounds = settings.bounds

  return (
    <PageShell>
      <PageHeader
        icon={Settings}
        eyebrow="Administration"
        title="Session settings"
        description="Session timeout policy for the whole platform."
        actions={<Badge variant="ai">Super admin only</Badge>}
      />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Session Timeouts
          </CardTitle>
          <CardDescription>
            Control how long user sessions remain active
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Inactivity Timeout */}
          <div className="space-y-2">
            <Label htmlFor="inactivity">
              Inactivity Timeout (minutes)
            </Label>
            <div className="flex items-center gap-4">
              <input aria-label="Inactivity timeout in minutes"
                type="range"
                min={bounds.inactivity_timeout_minutes.min}
                max={bounds.inactivity_timeout_minutes.max}
                value={inactivity}
                onChange={(e) => setInactivity(Number(e.target.value))}
                className="flex-1"
              />
              <Input
                id="inactivity"
                type="number"
                min={bounds.inactivity_timeout_minutes.min}
                max={bounds.inactivity_timeout_minutes.max}
                value={inactivity}
                onChange={(e) => setInactivity(Number(e.target.value))}
                className="w-24"
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Sessions expire after {formatDuration(inactivity)} of inactivity.
              Range: {bounds.inactivity_timeout_minutes.min}-{bounds.inactivity_timeout_minutes.max} minutes.
            </p>
          </div>

          {/* Absolute Timeout */}
          <div className="space-y-2">
            <Label htmlFor="absolute">
              Maximum Session Duration (hours)
            </Label>
            <div className="flex items-center gap-4">
              <input aria-label="Maximum session duration in hours"
                type="range"
                min={bounds.absolute_timeout_hours.min}
                max={bounds.absolute_timeout_hours.max}
                value={absolute}
                onChange={(e) => setAbsolute(Number(e.target.value))}
                className="flex-1"
              />
              <Input
                id="absolute"
                type="number"
                min={bounds.absolute_timeout_hours.min}
                max={bounds.absolute_timeout_hours.max}
                value={absolute}
                onChange={(e) => setAbsolute(Number(e.target.value))}
                className="w-24"
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Sessions expire after {absolute} hours regardless of activity.
              Range: {bounds.absolute_timeout_hours.min}-{bounds.absolute_timeout_hours.max} hours.
            </p>
          </div>

          {/* Effective Policy Summary */}
          <div className="p-4 bg-info-soft dark:bg-info-soft/20 border border-info-line rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="h-4 w-4 text-info-text" />
              <span className="text-sm font-semibold text-info-text">Effective Policy</span>
            </div>
            <ul className="text-sm text-info-text space-y-1">
              <li>Users will be logged out after {formatDuration(inactivity)} of inactivity</li>
              <li>Sessions will expire after {absolute} hours maximum, even if active</li>
            </ul>
          </div>

          {/* Save Button */}
          <div className="flex justify-end">
            <Button
              onClick={handleSave}
              disabled={saving}
              className={saved ? "bg-success hover:bg-success" : ""}
            >
              {saving ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : saved ? (
                <CheckCircle2 className="h-4 w-4 mr-2" />
              ) : null}
              {saving ? "Saving..." : saved ? "Saved" : "Save Settings"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </PageShell>
  )
}
