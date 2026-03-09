"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Slider } from "@/components/ui/slider"
import { ShieldAlert, Loader2, Clock, Timer, Save, RotateCcw } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { API_BASE, apiFetch } from "@/lib/api"

interface SessionSettings {
  inactivity_timeout_minutes: number
  absolute_timeout_hours: number
  bounds: {
    inactivity_timeout_minutes: { min: number; max: number }
    absolute_timeout_hours: { min: number; max: number }
  }
}

export default function SessionSettingsPage() {
  const [settings, setSettings] = useState<SessionSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [inactivityMinutes, setInactivityMinutes] = useState(30)
  const [absoluteHours, setAbsoluteHours] = useState(24)
  const [hasChanges, setHasChanges] = useState(false)
  const { toast } = useToast()

  useEffect(() => {
    fetchSettings()
  }, [])

  const fetchSettings = async () => {
    try {
      const res = await apiFetch(`${API_BASE}/settings/session`, { credentials: "include" })
      if (res.ok) {
        const data: SessionSettings = await res.json()
        setSettings(data)
        setInactivityMinutes(data.inactivity_timeout_minutes)
        setAbsoluteHours(data.absolute_timeout_hours)
        setHasChanges(false)
      } else if (res.status === 403) {
        toast({ title: "Access denied", description: "Super admin role required", variant: "destructive" })
      } else {
        toast({ title: "Failed to load session settings", variant: "destructive" })
      }
    } catch {
      toast({ title: "Connection error", variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      const res = await apiFetch(`${API_BASE}/settings/session`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          inactivity_timeout_minutes: inactivityMinutes,
          absolute_timeout_hours: absoluteHours,
        }),
      })
      if (res.ok) {
        const data = await res.json()
        setSettings(prev => prev ? { ...prev, ...data } : prev)
        setHasChanges(false)
        toast({ title: "Session settings saved" })
      } else {
        const err = await res.json().catch(() => ({}))
        toast({ title: "Failed to save", description: err.detail || "Try again", variant: "destructive" })
      }
    } catch {
      toast({ title: "Connection error", variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  const handleReset = () => {
    if (settings) {
      setInactivityMinutes(settings.inactivity_timeout_minutes)
      setAbsoluteHours(settings.absolute_timeout_hours)
      setHasChanges(false)
    }
  }

  const updateInactivity = (val: number) => {
    setInactivityMinutes(val)
    setHasChanges(true)
  }

  const updateAbsolute = (val: number) => {
    setAbsoluteHours(val)
    setHasChanges(true)
  }

  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (!settings) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center py-12">
        <ShieldAlert className="h-12 w-12 text-muted-foreground mb-4" />
        <p className="text-lg font-medium">Access Denied</p>
        <p className="text-muted-foreground">Super admin role required to manage session settings</p>
      </div>
    )
  }

  const bounds = settings.bounds

  return (
    <div className="flex flex-1 flex-col gap-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-8 w-8" />
            Session Settings
          </h1>
          <p className="text-muted-foreground mt-1">
            Configure session timeout policies for all users
          </p>
        </div>
        <Badge variant="outline" className="text-purple-600 border-purple-300">
          Super Admin Only
        </Badge>
      </div>

      <div className="grid gap-6 max-w-2xl">
        {/* Inactivity Timeout */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Timer className="h-5 w-5" />
              Inactivity Timeout
            </CardTitle>
            <CardDescription>
              Sessions expire after this period of inactivity. Users must re-authenticate.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label>Timeout Duration</Label>
              <span className="text-sm font-mono font-medium">
                {inactivityMinutes} min{inactivityMinutes !== 1 ? "s" : ""}
                {inactivityMinutes >= 60 && (
                  <span className="text-muted-foreground ml-1">
                    ({Math.floor(inactivityMinutes / 60)}h {inactivityMinutes % 60}m)
                  </span>
                )}
              </span>
            </div>
            <Slider
              min={bounds.inactivity_timeout_minutes.min}
              max={bounds.inactivity_timeout_minutes.max}
              step={5}
              value={[inactivityMinutes]}
              onValueChange={([val]) => updateInactivity(val)}
            />
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>{bounds.inactivity_timeout_minutes.min} min</span>
              <span>{bounds.inactivity_timeout_minutes.max} min (8 hours)</span>
            </div>
          </CardContent>
        </Card>

        {/* Absolute Timeout */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Clock className="h-5 w-5" />
              Absolute Session Timeout
            </CardTitle>
            <CardDescription>
              Maximum session lifetime regardless of activity. Forces re-authentication.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label>Maximum Duration</Label>
              <span className="text-sm font-mono font-medium">
                {absoluteHours} hour{absoluteHours !== 1 ? "s" : ""}
                {absoluteHours >= 24 && (
                  <span className="text-muted-foreground ml-1">
                    ({Math.floor(absoluteHours / 24)}d {absoluteHours % 24}h)
                  </span>
                )}
              </span>
            </div>
            <Slider
              min={bounds.absolute_timeout_hours.min}
              max={bounds.absolute_timeout_hours.max}
              step={1}
              value={[absoluteHours]}
              onValueChange={([val]) => updateAbsolute(val)}
            />
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>{bounds.absolute_timeout_hours.min} hour</span>
              <span>{bounds.absolute_timeout_hours.max} hours (3 days)</span>
            </div>
          </CardContent>
        </Card>

        {/* Actions */}
        <div className="flex gap-3">
          <Button onClick={handleSave} disabled={saving || !hasChanges}>
            {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
            Save Changes
          </Button>
          <Button variant="outline" onClick={handleReset} disabled={saving || !hasChanges}>
            <RotateCcw className="h-4 w-4 mr-2" />
            Reset
          </Button>
        </div>
      </div>
    </div>
  )
}
