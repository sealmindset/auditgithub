"use client"

import { useState, useEffect, Suspense } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { AlertCircle, ShieldCheck, Loader2, LockKeyhole, ScanSearch, Bot } from "lucide-react"
import { API_BASE, apiFetch } from "@/lib/api"
import { useAuth } from "@/contexts/AuthContext"

interface Provider {
  name: string
  display_name: string
}

/** What the product does, said once, on the only page a signed-out user sees. */
const PITCH = [
  { icon: ScanSearch, title: "Continuous scanning", body: "Secrets, SAST, IaC and dependency findings across every repository in the organization." },
  { icon: Bot, title: "AI triage", body: "Findings arrive ranked and explained, so the queue starts at the part that matters." },
  { icon: LockKeyhole, title: "Audited access", body: "Every session, override and export is attributed and logged." },
]

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
    <div className="relative min-h-screen overflow-hidden bg-background">
      {/* Two soft brand washes rather than a flat gradient: they read as depth in
          both themes, where a light-mode gradient tends to read as a smudge. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 [background:radial-gradient(60rem_40rem_at_15%_-10%,var(--primary-soft),transparent_60%),radial-gradient(50rem_35rem_at_100%_110%,var(--ai-soft),transparent_55%)]"
      />

      <div className="relative mx-auto grid min-h-screen w-full max-w-6xl items-center gap-12 px-4 py-10 sm:px-6 lg:grid-cols-2 lg:gap-16">
        {/* Brand panel — hidden on small screens, where the form is the whole job */}
        <section className="hidden lg:block">
          <div className="flex items-center gap-3">
            <span className="flex size-11 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
              <ShieldCheck className="size-6" />
            </span>
            <div className="leading-tight">
              <p className="text-lg font-semibold tracking-tight">AuditGH</p>
              <p className="text-sm text-muted-foreground">Security Platform</p>
            </div>
          </div>

          <h1 className="mt-8 text-4xl font-semibold tracking-tight text-balance">
            Every repository, every finding, one queue.
          </h1>
          <p className="mt-3 max-w-md text-base text-muted-foreground">
            Sign in to review the current security posture of your GitHub organization.
          </p>

          <ul className="mt-10 space-y-6">
            {PITCH.map(({ icon: Icon, title, body }) => (
              <li key={title} className="flex gap-4">
                <span className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary-soft text-primary-text">
                  <Icon className="size-4.5" />
                </span>
                <div>
                  <p className="text-sm font-medium">{title}</p>
                  <p className="mt-0.5 max-w-sm text-sm text-muted-foreground">{body}</p>
                </div>
              </li>
            ))}
          </ul>
        </section>

        {/* Auth panel */}
        <div className="mx-auto w-full max-w-md">
          {/* Small-screen brand lockup: the panel above is hidden there. */}
          <div className="mb-6 flex items-center justify-center gap-3 lg:hidden">
            <span className="flex size-10 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
              <ShieldCheck className="size-5" />
            </span>
            <div className="leading-tight">
              <p className="font-semibold tracking-tight">AuditGH</p>
              <p className="text-xs text-muted-foreground">Security Platform</p>
            </div>
          </div>

          <Card elevation="md" className="backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-xl">
                {showBreakGlass ? "Emergency access" : "Sign in"}
              </CardTitle>
              <CardDescription>
                {showBreakGlass
                  ? "Use only while single sign-on is unavailable."
                  : "Use your organization account to continue."}
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-6">
              {!showBreakGlass ? (
                <div className="space-y-4">
                  {providersLoading ? (
                    <div className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
                      <Loader2 className="size-4 animate-spin" aria-hidden />
                      Loading sign-in options
                    </div>
                  ) : providers.length > 0 ? (
                    providers.map((provider) => (
                      <Button
                        key={provider.name}
                        onClick={() => handleProviderLogin(provider.name)}
                        className="w-full"
                        size="lg"
                      >
                        Sign in with {provider.display_name}
                      </Button>
                    ))
                  ) : (
                    <p className="rounded-lg border border-warning-line bg-warning-soft px-3 py-2.5 text-sm text-warning-text">
                      No single sign-on providers are configured. Use emergency access below.
                    </p>
                  )}

                  <div className="relative py-1">
                    <div className="absolute inset-0 flex items-center" aria-hidden>
                      <span className="w-full border-t" />
                    </div>
                    <div className="relative flex justify-center">
                      <span className="eyebrow bg-card px-2">Need help?</span>
                    </div>
                  </div>

                  <div className="space-y-2 text-center">
                    <p className="text-sm text-muted-foreground">
                      Don&apos;t have access? Contact your administrator for an invitation.
                    </p>
                    <Button
                      variant="link"
                      size="sm"
                      onClick={() => setShowBreakGlass(true)}
                      className="text-muted-foreground hover:text-foreground"
                    >
                      Emergency access
                    </Button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="flex items-start gap-3 rounded-lg border border-danger-line bg-danger-soft p-3">
                    <AlertCircle className="mt-0.5 size-5 shrink-0 text-danger-text" aria-hidden />
                    <div>
                      <p className="text-sm font-semibold text-danger-text">Break-glass credentials</p>
                      <p className="mt-1 text-xs text-danger-text/90">
                        For use only when single sign-on is unavailable. Every action in this
                        session is attributed and logged.
                      </p>
                    </div>
                  </div>

                  <form onSubmit={handleBreakGlassLogin} className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="email">Email address</Label>
                      <Input
                        id="email"
                        type="email"
                        autoComplete="username"
                        placeholder="admin@example.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        disabled={loading}
                        aria-invalid={!!error}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="password">Local password</Label>
                      <Input
                        id="password"
                        type="password"
                        autoComplete="current-password"
                        placeholder="••••••••"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        disabled={loading}
                        aria-invalid={!!error}
                      />
                    </div>

                    {error && (
                      <p
                        role="alert"
                        className="flex items-start gap-2 rounded-lg border border-danger-line bg-danger-soft p-3 text-sm text-danger-text"
                      >
                        <AlertCircle className="mt-px size-4 shrink-0" aria-hidden />
                        {error}
                      </p>
                    )}

                    <div className="space-y-2 pt-1">
                      <Button
                        type="submit"
                        variant="destructive"
                        className="w-full"
                        loading={loading}
                      >
                        {loading ? "Signing in" : "Sign in with emergency access"}
                      </Button>

                      <Button
                        type="button"
                        variant="ghost"
                        className="w-full"
                        disabled={loading}
                        onClick={() => {
                          setShowBreakGlass(false)
                          setError("")
                          setEmail("")
                          setPassword("")
                        }}
                      >
                        Back to normal sign-in
                      </Button>
                    </div>
                  </form>
                </>
              )}
            </CardContent>
          </Card>

          <p className="mt-6 text-center text-xs text-muted-foreground">
            By signing in you agree to the organization&apos;s security policies and terms of use.
          </p>
        </div>
      </div>
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
