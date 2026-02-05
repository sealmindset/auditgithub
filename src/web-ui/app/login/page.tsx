"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { AlertCircle, Shield } from "lucide-react"

export default function LoginPage() {
  const [showBreakGlass, setShowBreakGlass] = useState(false)
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  const handleEntraLogin = () => {
    // Redirect to Entra ID OAuth flow
    window.location.href = "http://localhost:8000/auth/login/entra"
  }

  const handleBreakGlassLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const formData = new FormData()
      formData.append("email", email)
      formData.append("password", password)

      const res = await fetch("http://localhost:8000/auth/break-glass/login", {
        method: "POST",
        body: formData,
        credentials: "include"
      })

      if (res.ok) {
        // Redirect to homepage
        window.location.href = "/"
      } else {
        const data = await res.json()
        setError(data.detail || "Invalid credentials")
      }
    } catch (err) {
      setError("Connection error. Please try again.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center space-y-2">
          <div className="flex justify-center mb-2">
            <Shield className="h-12 w-12 text-blue-600" />
          </div>
          <CardTitle className="text-3xl font-bold">AuditGitHub</CardTitle>
          <CardDescription className="text-base">
            Security Scanning & Analysis Platform
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {!showBreakGlass ? (
            <>
              {/* Normal Login */}
              <div className="space-y-4">
                <Button
                  onClick={handleEntraLogin}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white py-6 text-lg"
                  size="lg"
                >
                  <svg
                    className="w-5 h-5 mr-2"
                    fill="currentColor"
                    viewBox="0 0 23 23"
                  >
                    <path d="M11.4 24H0V12.6h11.4V24zM24 24H12.6V12.6H24V24zM11.4 11.4H0V0h11.4v11.4zm12.6 0H12.6V0H24v11.4z" />
                  </svg>
                  Sign in with Microsoft
                </Button>

                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t border-gray-300" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-white dark:bg-gray-800 px-2 text-gray-500">
                      Need help?
                    </span>
                  </div>
                </div>

                <div className="text-center">
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                    Don't have access? Contact your administrator for an invitation.
                  </p>
                  <button
                    onClick={() => setShowBreakGlass(true)}
                    className="text-xs text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
                  >
                    Emergency Access
                  </button>
                </div>
              </div>
            </>
          ) : (
            <>
              {/* Break Glass Login */}
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex items-start gap-3">
                <AlertCircle className="h-5 w-5 text-red-600 dark:text-red-400 mt-0.5 flex-shrink-0" />
                <div className="flex-1">
                  <p className="text-sm font-semibold text-red-900 dark:text-red-300 mb-1">
                    Emergency Break Glass Access
                  </p>
                  <p className="text-xs text-red-700 dark:text-red-400">
                    This is emergency access only for when Entra ID is unavailable.
                    All actions will be audited and logged.
                  </p>
                </div>
              </div>

              <form onSubmit={handleBreakGlassLogin} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-sm font-medium">
                    Email Address
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="ravance@gmail.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    disabled={loading}
                    className="w-full"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password" className="text-sm font-medium">
                    Local Password
                  </Label>
                  <Input
                    id="password"
                    type="password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    disabled={loading}
                    className="w-full"
                  />
                </div>

                {error && (
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                    <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
                  </div>
                )}

                <div className="space-y-3 pt-2">
                  <Button
                    type="submit"
                    className="w-full bg-red-600 hover:bg-red-700 text-white"
                    disabled={loading}
                  >
                    {loading ? "Signing In..." : "Sign In (Emergency Access)"}
                  </Button>

                  <Button
                    type="button"
                    onClick={() => {
                      setShowBreakGlass(false)
                      setError("")
                      setEmail("")
                      setPassword("")
                    }}
                    className="w-full"
                    variant="outline"
                    disabled={loading}
                  >
                    Back to Normal Login
                  </Button>
                </div>
              </form>
            </>
          )}

          {/* Footer */}
          <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
            <p className="text-xs text-center text-gray-500 dark:text-gray-400">
              By signing in, you agree to our security policies and terms of use.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
