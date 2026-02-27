"use client"

import { useEffect, useState } from "react"
import { useParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Mail, User, Shield, Clock, AlertCircle, Loader2, CheckCircle2 } from "lucide-react"
import { formatDistanceToNow } from "date-fns"
import { API_BASE } from "@/lib/api"

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
        const res = await fetch(`${API_BASE}/api/invitations/validate/${token}`)

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

  const handleAccept = () => {
    // Redirect to Entra ID OAuth flow
    // The callback will check for invite_token in session storage
    window.location.href = `${API_BASE}/auth/login/entra`
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        <Card className="w-full max-w-md shadow-xl">
          <CardContent className="pt-6">
            <div className="flex flex-col items-center justify-center py-8">
              <Loader2 className="h-12 w-12 text-blue-600 animate-spin mb-4" />
              <p className="text-gray-600 dark:text-gray-400">Loading invitation...</p>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error || !invitation) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-red-50 to-orange-100 dark:from-gray-900 dark:to-gray-800">
        <Card className="w-full max-w-md shadow-xl border-red-200 dark:border-red-800">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-2">
              <AlertCircle className="h-12 w-12 text-red-600" />
            </div>
            <CardTitle className="text-2xl text-red-900 dark:text-red-300">
              Invitation Error
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-center text-gray-700 dark:text-gray-300 mb-6">
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
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-yellow-50 to-orange-100 dark:from-gray-900 dark:to-gray-800">
        <Card className="w-full max-w-md shadow-xl border-yellow-200 dark:border-yellow-800">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-2">
              <AlertCircle className="h-12 w-12 text-yellow-600" />
            </div>
            <CardTitle className="text-2xl text-yellow-900 dark:text-yellow-300">
              Invalid Invitation
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-center text-gray-700 dark:text-gray-300 mb-6">
              {invitation.message || "This invitation is no longer valid."}
            </p>
            <p className="text-sm text-center text-gray-600 dark:text-gray-400 mb-6">
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
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-green-50 to-blue-100 dark:from-gray-900 dark:to-gray-800">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center space-y-2">
          <div className="flex justify-center mb-2">
            <CheckCircle2 className="h-12 w-12 text-green-600" />
          </div>
          <CardTitle className="text-3xl font-bold">You're Invited!</CardTitle>
          <CardDescription className="text-base">
            Join the AuditGitHub Security Platform
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Invitation Details */}
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-3">
              <Mail className="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-gray-600 dark:text-gray-400">Email</p>
                <p className="text-sm font-semibold text-gray-900 dark:text-gray-100">
                  {invitation.email}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <User className="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-gray-600 dark:text-gray-400">Role</p>
                <div className="flex items-center gap-2 mt-1">
                  <Badge variant="default" className="bg-blue-600">
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
              <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-gray-600 dark:text-gray-400">Invited By</p>
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                  {invitation.invited_by_email}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Clock className="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0" />
              <div className="flex-1">
                <p className="text-xs text-gray-600 dark:text-gray-400">Expires</p>
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
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
            <Button onClick={handleAccept} className="w-full bg-blue-600 hover:bg-blue-700 py-6 text-lg">
              <svg
                className="w-5 h-5 mr-2"
                fill="currentColor"
                viewBox="0 0 23 23"
              >
                <path d="M11.4 24H0V12.6h11.4V24zM24 24H12.6V12.6H24V24zM11.4 11.4H0V0h11.4v11.4zm12.6 0H12.6V0H24v11.4z" />
              </svg>
              Accept Invitation & Sign In
            </Button>

            <p className="text-xs text-center text-gray-600 dark:text-gray-400">
              By accepting, you'll be redirected to Microsoft to sign in with your work account.
            </p>
          </div>

          {/* Info Box */}
          <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
            <p className="text-xs text-gray-600 dark:text-gray-400">
              <span className="font-semibold">Note:</span> You must sign in with the email address{" "}
              <span className="font-mono text-blue-600 dark:text-blue-400">{invitation.email}</span> to
              accept this invitation.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
