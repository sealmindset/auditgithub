"use client"

import { useEffect, useState } from "react"
import { useParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Mail, User, Shield, Clock, AlertCircle, Loader2, CheckCircle2 } from "lucide-react"
import { formatDistanceToNow } from "date-fns"
import { API_BASE, apiFetch } from "@/lib/api"

interface Invitation {
  valid: boolean
  email?: string
  role?: string
  access_type?: string
  expires_at?: string
  invited_by_email?: string
  message?: string
}

export default function InviteAcceptPage() {
  const { token } = useParams()
  const [invitation, setInvitation] = useState<Invitation | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!token) return

    const fetchInvitation = async () => {
      try {
        const res = await apiFetch(`${API_BASE}/api/invitations/validate/${token}`)

        if (res.ok) {
          const data = await res.json()
          setInvitation(data)

          if (data.valid) {
            // Store invitation token in session storage for OAuth callback
            sessionStorage.setItem('invite_token', token as string)
          }
        } else {
          setError("Failed to load invitation")
        }
      } catch (err) {
        setError("Connection error. Please try again.")
      } finally {
        setLoading(false)
      }
    }

    fetchInvitation()
  }, [token])

  const handleAccept = async () => {
    // Fetch first available provider and redirect to its login
    try {
      const res = await apiFetch(`${API_BASE}/auth/providers`)
      const data = await res.json()
      const provider = data.providers?.[0]?.name
      if (provider) {
        window.location.href = `${API_BASE}/auth/accept-invite?token=${token}&provider=${provider}`
      } else {
        window.location.href = "/login"
      }
    } catch {
      window.location.href = "/login"
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-info-soft to-info-soft dark:from-muted dark:to-muted">
        <Card className="w-full max-w-md shadow-xl">
          <CardContent className="pt-6">
            <div className="flex flex-col items-center justify-center py-8">
              <Loader2 className="h-12 w-12 text-info-text animate-spin mb-4" />
              <p className="text-muted-foreground">Loading invitation...</p>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error || !invitation) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-danger-soft to-warning-soft dark:from-muted dark:to-muted">
        <Card className="w-full max-w-md shadow-xl border-danger-line">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-2">
              <AlertCircle className="h-12 w-12 text-danger-text" />
            </div>
            <CardTitle className="text-2xl text-danger-text">
              Invitation Error
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-center text-muted-foreground mb-6">
              {error || "Could not load invitation"}
            </p>
            <Button
              onClick={() => (window.location.href = "/login")}
              className="w-full"
              variant="outline"
            >
              Return to Login
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!invitation.valid) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-warning-soft to-warning-soft dark:from-muted dark:to-muted">
        <Card className="w-full max-w-md shadow-xl border-warning-line">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-2">
              <AlertCircle className="h-12 w-12 text-warning-text" />
            </div>
            <CardTitle className="text-2xl text-warning-text">
              Invalid Invitation
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-center text-muted-foreground mb-6">
              {invitation.message || "This invitation is no longer valid."}
            </p>
            <p className="text-sm text-center text-muted-foreground mb-6">
              Please contact your administrator for a new invitation.
            </p>
            <Button
              onClick={() => (window.location.href = "/login")}
              className="w-full"
              variant="outline"
            >
              Return to Login
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-success-soft to-info-soft dark:from-muted dark:to-muted">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center space-y-2">
          <div className="flex justify-center mb-2">
            <CheckCircle2 className="h-12 w-12 text-success-text" />
          </div>
          <CardTitle className="text-3xl font-bold">You're Invited!</CardTitle>
          <CardDescription className="text-base">
            Join the AuditGitHub Security Platform
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Invitation Details */}
          <div className="bg-info-soft dark:bg-info-soft/20 border border-info-line rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-3">
              <Mail className="h-5 w-5 text-info-text flex-shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-muted-foreground">Email</p>
                <p className="text-sm font-semibold text-foreground dark:text-muted-foreground">
                  {invitation.email}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <User className="h-5 w-5 text-info-text flex-shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-muted-foreground">Role</p>
                <div className="flex items-center gap-2 mt-1">
                  <Badge variant="default" className="bg-info">
                    {invitation.role}
                  </Badge>
                  <Badge variant="outline">
                    {invitation.access_type === "ui_only"
                      ? "UI Access"
                      : invitation.access_type === "api_only"
                      ? "API Access"
                      : "Full Access"}
                  </Badge>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Shield className="h-5 w-5 text-info-text flex-shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-muted-foreground">Invited By</p>
                <p className="text-sm font-medium text-foreground dark:text-muted-foreground">
                  {invitation.invited_by_email}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Clock className="h-5 w-5 text-info-text flex-shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-muted-foreground">Expires</p>
                <p className="text-sm font-medium text-foreground dark:text-muted-foreground">
                  {invitation.expires_at
                    ? formatDistanceToNow(new Date(invitation.expires_at), {
                        addSuffix: true
                      })
                    : "Unknown"}
                </p>
              </div>
            </div>
          </div>

          {/* Call to Action */}
          <div className="space-y-4">
            <Button onClick={handleAccept} className="w-full bg-info hover:bg-info py-6 text-lg">
              <svg
                className="w-5 h-5 mr-2"
                fill="currentColor"
                viewBox="0 0 23 23"
              >
                <path d="M11.4 24H0V12.6h11.4V24zM24 24H12.6V12.6H24V24zM11.4 11.4H0V0h11.4v11.4zm12.6 0H12.6V0H24v11.4z" />
              </svg>
              Accept Invitation & Sign In
            </Button>

            <p className="text-xs text-center text-muted-foreground">
              By accepting, you'll be redirected to Microsoft to sign in with your work account.
            </p>
          </div>

          {/* Info Box */}
          <div className="bg-muted rounded-lg p-4">
            <p className="text-xs text-muted-foreground">
              <span className="font-semibold">Note:</span> You must sign in with the email address{" "}
              <span className="font-mono text-info-text">{invitation.email}</span> to
              accept this invitation.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
