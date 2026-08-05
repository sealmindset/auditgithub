"use client"

import { useState, useEffect, Suspense } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { AlertCircle, Shield, Loader2 } from "lucide-react"
import { API_BASE, apiFetch } from "@/lib/api"
import { useAuth } from "@/contexts/AuthContext"

interface Provider {
  name: string
  display_name: string
}

function LoginForm() {
  const { isAuthenticated, isLoading } = useAuth()
  const router = useRouter()
  const searchParams = useSearchParams()
  const redirectTo = searchParams.get("redirect") || "/"

  const [providers, setProviders] = useState<Provider[]>([])
  const [providersLoading, setProvidersLoading] = useState(true)
  const [showBreakGlass, setShowBreakGlass] = useState(false)
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  // If already authenticated, redirect away from login
  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      router.replace(redirectTo)
    }
  }, [isAuthenticated, isLoading, redirectTo, router])

  // Fetch available OIDC providers
  useEffect(() => {
    apiFetch(`${API_BASE}/auth/providers`)
      .then(res => res.json())
      .then(data => setProviders(data.providers || []))
      .catch(() => setProviders([]))
      .finally(() => setProvidersLoading(false))
  }, [])

  const handleProviderLogin = (providerName: string) => {
    window.location.href = `/api/proxy/auth/login/${providerName}`
  }

  const handleBreakGlassLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const formData = new FormData()
      formData.append("email", email)
      formData.append("password", password)

      const res = await apiFetch(`${API_BASE}/auth/break-glass/login`, {
        method: "POST",
        body: formData,
        redirect: "manual",
      })

      if (res.ok || res.type === "opaqueredirect" || res.status === 303) {
        window.location.href = redirectTo
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

  // Don't render the login form if already authenticated (redirect in flight)
  if (!isLoading && isAuthenticated) {
    return null
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
                {providersLoading ? (
                  <div className="flex justify-center py-4">
                    <Loader2 className="h-6 w-6 animate-spin text-blue-600" />
                  </div>
                ) : providers.length > 0 ? (
                  providers.map((provider) => (
                    <Button
                      key={provider.name}
                      onClick={() => handleProviderLogin(provider.name)}
                      className="w-full bg-blue-600 hover:bg-blue-700 text-white py-6 text-lg"
                      size="lg"
                    >
                      Sign in with {provider.display_name}
                    </Button>
                  ))
                ) : (
                  <p className="text-center text-sm text-gray-500">
                    No SSO providers configured. Use emergency access below.
                  </p>
                )}

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
                    Don&apos;t have access? Contact your administrator for an invitation.
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
                    This is emergency access only for when SSO is unavailable.
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
                    placeholder="admin@example.com"
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

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  )
}
