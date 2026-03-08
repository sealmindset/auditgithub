"use client"

import { useEffect, useState, useCallback } from "react"
import { useParams, useRouter } from "next/navigation"
import Link from "next/link"
import { apiFetch, API_BASE } from "@/lib/api"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { ScrollArea } from "@/components/ui/scroll-area"

import {
  ArrowLeft,
  Loader2,
  Pencil,
  Lock,
  Unlock,
  XCircle,
  X,
  Plus,
  Play,
  RotateCcw,
  Eye,
  Clock,
  User,
  Tag,
  Zap,
  FlaskConical,
  FileCode,
  Activity,
  Hash,
  Network,
} from "lucide-react"

import { OrchestrationTab } from "./orchestration-tab"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Prompt {
  id: string
  slug: string
  name: string
  description: string | null
  category: string
  subcategory: string | null
  agent_id: string | null
  provider: string | null
  model: string | null
  current_version: number
  is_active: boolean
  is_locked: boolean
  locked_by: string | null
  locked_reason: string | null
  source_file: string | null
  created_by: string | null
  updated_by: string | null
  created_at: string
  updated_at: string
  tags: string[]
  usage_count: number | null
  version_count: number | null
}

interface PromptVersion {
  id: string
  prompt_id: string
  version: number
  content: string
  system_message: string | null
  parameters: Record<string, any> | null
  model: string | null
  input_schema: Record<string, any> | null
  output_schema: Record<string, any> | null
  change_summary: string | null
  created_by: string | null
  created_at: string
}

interface PromptUsage {
  id: string
  prompt_id: string
  usage_type: string
  location: string
  description: string | null
  is_primary: boolean
  last_called_at: string | null
  call_count: number
  avg_latency_ms: number | null
  avg_tokens_in: number | null
  avg_tokens_out: number | null
  total_tokens: number
  error_count: number
  last_model_used: string | null
  last_provider_used: string | null
  created_at: string
  updated_at: string
}

interface TestResult {
  output: string
  model_used: string
  tokens_in: number
  tokens_out: number
  latency_ms: number
}

interface TestCase {
  id: string
  name: string
  input_data: Record<string, any>
  expected_output: string | null
  created_at: string
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CATEGORY_COLORS: Record<string, string> = {
  system: "bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30",
  user: "bg-blue-500/15 text-blue-700 dark:text-blue-300 border-blue-500/30",
  template: "bg-green-500/15 text-green-700 dark:text-green-300 border-green-500/30",
  agent: "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30",
  skill: "bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/30",
  mcp: "bg-pink-500/15 text-pink-700 dark:text-pink-300 border-pink-500/30",
}

function categoryBadge(category: string) {
  const colors = CATEGORY_COLORS[category] ?? "bg-gray-500/15 text-gray-700 dark:text-gray-300 border-gray-500/30"
  return (
    <Badge variant="outline" className={colors}>
      {category}
    </Badge>
  )
}

function modelBadge(model: string | null) {
  if (!model) return null
  return (
    <Badge variant="outline" className="bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 border-indigo-500/30 font-mono text-xs">
      {model}
    </Badge>
  )
}

function statusBadge(active: boolean) {
  return active ? (
    <Badge className="bg-emerald-500 hover:bg-emerald-600 text-white">Active</Badge>
  ) : (
    <Badge variant="secondary" className="text-muted-foreground">Inactive</Badge>
  )
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function PromptDetailPage() {
  const params = useParams()
  const router = useRouter()
  const slug = params.slug as string

  // Core state
  const [prompt, setPrompt] = useState<Prompt | null>(null)
  const [latestVersion, setLatestVersion] = useState<PromptVersion | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Tab data
  const [versions, setVersions] = useState<PromptVersion[]>([])
  const [versionsLoading, setVersionsLoading] = useState(false)
  const [usages, setUsages] = useState<PromptUsage[]>([])
  const [usagesLoading, setUsagesLoading] = useState(false)

  // Version dialog
  const [viewVersion, setViewVersion] = useState<PromptVersion | null>(null)

  // Tags
  const [newTag, setNewTag] = useState("")
  const [tagsLoading, setTagsLoading] = useState(false)

  // Test
  const [testInput, setTestInput] = useState("{}")
  const [testProvider, setTestProvider] = useState("")
  const [testModel, setTestModel] = useState("")
  const [testRunning, setTestRunning] = useState(false)
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [testCases, setTestCases] = useState<TestCase[]>([])
  const [testCasesLoading, setTestCasesLoading] = useState(false)

  // -----------------------------------------------------------------------
  // Data fetching
  // -----------------------------------------------------------------------

  const fetchPrompt = useCallback(async () => {
    try {
      const res = await apiFetch(`${API_BASE}/prompts/${slug}`)
      if (!res.ok) throw new Error("Prompt not found")
      const data: Prompt = await res.json()
      setPrompt(data)
    } catch {
      setError("Failed to load prompt")
    } finally {
      setLoading(false)
    }
  }, [slug])

  const fetchLatestVersion = useCallback(async () => {
    try {
      const res = await apiFetch(`${API_BASE}/prompts/${slug}/versions`)
      if (res.ok) {
        const raw = await res.json()
        const data: PromptVersion[] = raw.items ?? raw
        if (data.length > 0) {
          const sorted = [...data].sort((a, b) => b.version - a.version)
          setLatestVersion(sorted[0])
        }
      }
    } catch {
      // non-critical
    }
  }, [slug])

  const fetchVersions = useCallback(async () => {
    setVersionsLoading(true)
    try {
      const res = await apiFetch(`${API_BASE}/prompts/${slug}/versions`)
      if (res.ok) {
        const raw = await res.json()
        const data: PromptVersion[] = raw.items ?? raw
        setVersions(data.sort((a, b) => b.version - a.version))
      }
    } catch {
      // silent
    } finally {
      setVersionsLoading(false)
    }
  }, [slug])

  const fetchUsages = useCallback(async () => {
    setUsagesLoading(true)
    try {
      const res = await apiFetch(`${API_BASE}/prompts/${slug}/usages`)
      if (res.ok) setUsages(await res.json())
    } catch {
      // silent
    } finally {
      setUsagesLoading(false)
    }
  }, [slug])

  const fetchTestCases = useCallback(async () => {
    setTestCasesLoading(true)
    try {
      const res = await apiFetch(`${API_BASE}/prompts/${slug}/test-cases`)
      if (res.ok) setTestCases(await res.json())
    } catch {
      // silent
    } finally {
      setTestCasesLoading(false)
    }
  }, [slug])

  useEffect(() => {
    if (slug) {
      fetchPrompt()
      fetchLatestVersion()
    }
  }, [slug, fetchPrompt, fetchLatestVersion])

  // -----------------------------------------------------------------------
  // Actions
  // -----------------------------------------------------------------------

  async function handleLockToggle() {
    if (!prompt) return
    const endpoint = prompt.is_locked
      ? `${API_BASE}/prompts/${slug}/unlock`
      : `${API_BASE}/prompts/${slug}/lock`
    const res = await apiFetch(endpoint, { method: "POST" })
    if (res.ok) fetchPrompt()
  }

  async function handleDeactivate() {
    if (!prompt) return
    const res = await apiFetch(`${API_BASE}/prompts/${slug}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ is_active: !prompt.is_active }),
    })
    if (res.ok) fetchPrompt()
  }

  async function handleRestore(version: number) {
    const res = await apiFetch(`${API_BASE}/prompts/${slug}/versions/${version}/restore`, {
      method: "POST",
    })
    if (res.ok) {
      fetchPrompt()
      fetchLatestVersion()
      fetchVersions()
    }
  }

  async function handleAddTag() {
    if (!newTag.trim()) return
    setTagsLoading(true)
    const res = await apiFetch(`${API_BASE}/prompts/${slug}/tags`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tag: newTag.trim() }),
    })
    if (res.ok) {
      setNewTag("")
      fetchPrompt()
    }
    setTagsLoading(false)
  }

  async function handleRemoveTag(tag: string) {
    setTagsLoading(true)
    const res = await apiFetch(`${API_BASE}/prompts/${slug}/tags/${encodeURIComponent(tag)}`, {
      method: "DELETE",
    })
    if (res.ok) fetchPrompt()
    setTagsLoading(false)
  }

  async function handleRunTest() {
    setTestRunning(true)
    setTestResult(null)
    try {
      const body: Record<string, any> = { input_data: JSON.parse(testInput) }
      if (testProvider) body.provider = testProvider
      if (testModel) body.model = testModel

      const res = await apiFetch(`${API_BASE}/prompts/${slug}/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
      if (res.ok) setTestResult(await res.json())
    } catch {
      // parse error or network error
    } finally {
      setTestRunning(false)
    }
  }

  // -----------------------------------------------------------------------
  // Tab change handler (lazy load)
  // -----------------------------------------------------------------------

  function onTabChange(value: string) {
    if (value === "versions" && versions.length === 0) fetchVersions()
    if (value === "usage" && usages.length === 0) fetchUsages()
    if (value === "test" && testCases.length === 0) fetchTestCases()
  }

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  if (error || !prompt) {
    return (
      <div className="flex h-screen flex-col items-center justify-center gap-4">
        <p className="text-red-500">{error || "Prompt not found"}</p>
        <Button variant="outline" onClick={() => router.push("/prompts")}>
          Back to Prompts
        </Button>
      </div>
    )
  }

  return (
    <TooltipProvider>
      <div className="flex flex-1 flex-col gap-6 p-6">
        {/* ---------------------------------------------------------------- */}
        {/* Header                                                           */}
        {/* ---------------------------------------------------------------- */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <Button variant="ghost" size="icon" asChild>
              <Link href="/prompts">
                <ArrowLeft className="h-4 w-4" />
              </Link>
            </Button>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">{prompt.name}</h1>
              <p className="text-sm text-muted-foreground font-mono">{prompt.slug}</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {categoryBadge(prompt.category)}
              {modelBadge(prompt.model)}
              {statusBadge(prompt.is_active)}
              {prompt.is_locked && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Badge variant="outline" className="bg-red-500/10 text-red-700 dark:text-red-300 border-red-500/30">
                      <Lock className="h-3 w-3 mr-1" />
                      Locked
                    </Badge>
                  </TooltipTrigger>
                  <TooltipContent>
                    {prompt.locked_by && <p>By: {prompt.locked_by}</p>}
                    {prompt.locked_reason && <p>Reason: {prompt.locked_reason}</p>}
                  </TooltipContent>
                </Tooltip>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => router.push(`/prompts/${slug}/edit`)}>
              <Pencil className="h-4 w-4 mr-1" />
              Edit
            </Button>
            <Button variant="outline" size="sm" onClick={handleLockToggle}>
              {prompt.is_locked ? (
                <>
                  <Unlock className="h-4 w-4 mr-1" />
                  Unlock
                </>
              ) : (
                <>
                  <Lock className="h-4 w-4 mr-1" />
                  Lock
                </>
              )}
            </Button>
            <Button variant="outline" size="sm" onClick={handleDeactivate}>
              <XCircle className="h-4 w-4 mr-1" />
              {prompt.is_active ? "Deactivate" : "Activate"}
            </Button>
          </div>
        </div>

        {/* Description */}
        {prompt.description && (
          <p className="text-sm text-muted-foreground max-w-3xl">{prompt.description}</p>
        )}

        {/* Meta row */}
        <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
          <span className="flex items-center gap-1">
            <Hash className="h-3.5 w-3.5" /> v{prompt.current_version}
          </span>
          {prompt.provider && (
            <span className="flex items-center gap-1">
              <Zap className="h-3.5 w-3.5" /> {prompt.provider}
            </span>
          )}
          {prompt.created_by && (
            <span className="flex items-center gap-1">
              <User className="h-3.5 w-3.5" /> {prompt.created_by}
            </span>
          )}
          <span className="flex items-center gap-1">
            <Clock className="h-3.5 w-3.5" /> Updated {fmtDate(prompt.updated_at)}
          </span>
          {prompt.source_file && (
            <span className="flex items-center gap-1">
              <FileCode className="h-3.5 w-3.5" /> {prompt.source_file}
            </span>
          )}
        </div>

        <Separator />

        {/* ---------------------------------------------------------------- */}
        {/* Tabs                                                             */}
        {/* ---------------------------------------------------------------- */}
        <Tabs defaultValue="content" className="space-y-4" onValueChange={onTabChange}>
          <TabsList>
            <TabsTrigger value="content" className="flex items-center gap-1">
              <FileCode className="h-4 w-4" /> Content
            </TabsTrigger>
            <TabsTrigger value="versions" className="flex items-center gap-1">
              <RotateCcw className="h-4 w-4" /> Versions
            </TabsTrigger>
            <TabsTrigger value="usage" className="flex items-center gap-1">
              <Activity className="h-4 w-4" /> Usage
            </TabsTrigger>
            <TabsTrigger value="tags" className="flex items-center gap-1">
              <Tag className="h-4 w-4" /> Tags
            </TabsTrigger>
            <TabsTrigger value="test" className="flex items-center gap-1">
              <FlaskConical className="h-4 w-4" /> Test
            </TabsTrigger>
            <TabsTrigger value="orchestration" className="flex items-center gap-1">
              <Network className="h-4 w-4" /> Orchestration
            </TabsTrigger>
          </TabsList>

          {/* -------------------------------------------------------------- */}
          {/* Content Tab                                                     */}
          {/* -------------------------------------------------------------- */}
          <TabsContent value="content" className="space-y-6">
            {latestVersion ? (
              <>
                {/* Prompt content */}
                <Card className="overflow-hidden">
                  <CardHeader>
                    <CardTitle className="text-base">Prompt Content</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="max-h-[500px] overflow-auto rounded-md bg-muted">
                      <pre className="whitespace-pre-wrap p-4 text-sm font-mono leading-relaxed">
                        {latestVersion.content}
                      </pre>
                    </div>
                  </CardContent>
                </Card>

                {/* System message */}
                {latestVersion.system_message && (
                  <Card className="overflow-hidden">
                    <CardHeader>
                      <CardTitle className="text-base">System Message</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="max-h-[300px] overflow-auto rounded-md bg-muted">
                        <pre className="whitespace-pre-wrap p-4 text-sm font-mono leading-relaxed">
                          {latestVersion.system_message}
                        </pre>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Parameters */}
                {latestVersion.parameters && Object.keys(latestVersion.parameters).length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Parameters</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 md:grid-cols-4">
                        {Object.entries(latestVersion.parameters).map(([key, value]) => (
                          <div key={key} className="rounded-md border p-3">
                            <p className="text-xs text-muted-foreground">{key}</p>
                            <p className="text-sm font-medium font-mono">{String(value)}</p>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Input / Output schemas */}
                <div className="grid gap-6 md:grid-cols-2">
                  {latestVersion.input_schema && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Input Schema</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="max-h-[300px]">
                          <pre className="whitespace-pre-wrap rounded-md bg-muted p-4 text-xs font-mono">
                            {JSON.stringify(latestVersion.input_schema, null, 2)}
                          </pre>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  )}
                  {latestVersion.output_schema && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Output Schema</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="max-h-[300px]">
                          <pre className="whitespace-pre-wrap rounded-md bg-muted p-4 text-xs font-mono">
                            {JSON.stringify(latestVersion.output_schema, null, 2)}
                          </pre>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  )}
                </div>

                {/* Model & Provider info */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Model & Provider</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-6 text-sm">
                      <div>
                        <p className="text-xs text-muted-foreground mb-1">Provider</p>
                        <p className="font-medium">{prompt.provider ?? "Default"}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground mb-1">Model (prompt-level)</p>
                        <p className="font-medium">{prompt.model ?? "Default"}</p>
                      </div>
                      {latestVersion.model && latestVersion.model !== prompt.model && (
                        <div>
                          <p className="text-xs text-muted-foreground mb-1">Model (version override)</p>
                          <p className="font-medium">{latestVersion.model}</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </>
            ) : (
              <Card>
                <CardContent className="py-12 text-center text-muted-foreground">
                  No version content available.
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* -------------------------------------------------------------- */}
          {/* Versions Tab                                                    */}
          {/* -------------------------------------------------------------- */}
          <TabsContent value="versions" className="space-y-4">
            {versionsLoading ? (
              <div className="flex justify-center py-12">
                <Loader2 className="h-6 w-6 animate-spin" />
              </div>
            ) : versions.length === 0 ? (
              <Card>
                <CardContent className="py-12 text-center text-muted-foreground">
                  No versions found.
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-20">Version</TableHead>
                        <TableHead>Change Summary</TableHead>
                        <TableHead>Model</TableHead>
                        <TableHead>Created By</TableHead>
                        <TableHead>Created At</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {versions.map((v) => (
                        <TableRow key={v.id}>
                          <TableCell className="font-mono font-medium">
                            v{v.version}
                            {v.version === prompt.current_version && (
                              <Badge className="ml-2 bg-emerald-500 text-white text-[10px]">
                                current
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell className="max-w-[300px] truncate text-sm text-muted-foreground">
                            {v.change_summary || "--"}
                          </TableCell>
                          <TableCell>{v.model ? modelBadge(v.model) : "--"}</TableCell>
                          <TableCell className="text-sm">{v.created_by || "--"}</TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {fmtDate(v.created_at)}
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex items-center justify-end gap-1">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setViewVersion(v)}
                              >
                                <Eye className="h-4 w-4 mr-1" />
                                View
                              </Button>
                              {v.version !== prompt.current_version && (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => handleRestore(v.version)}
                                >
                                  <RotateCcw className="h-4 w-4 mr-1" />
                                  Restore
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            )}

            {/* Version view dialog */}
            <Dialog open={!!viewVersion} onOpenChange={(open) => !open && setViewVersion(null)}>
              <DialogContent className="max-w-3xl max-h-[80vh]">
                <DialogHeader>
                  <DialogTitle>Version {viewVersion?.version}</DialogTitle>
                  <DialogDescription>
                    {viewVersion?.change_summary || "No change summary"}
                    {viewVersion?.created_by && ` - by ${viewVersion.created_by}`}
                  </DialogDescription>
                </DialogHeader>
                <ScrollArea className="max-h-[60vh]">
                  <div className="space-y-4">
                    <div>
                      <Label className="text-xs text-muted-foreground">Content</Label>
                      <pre className="whitespace-pre-wrap rounded-md bg-muted p-4 text-sm font-mono mt-1">
                        {viewVersion?.content}
                      </pre>
                    </div>
                    {viewVersion?.system_message && (
                      <div>
                        <Label className="text-xs text-muted-foreground">System Message</Label>
                        <pre className="whitespace-pre-wrap rounded-md bg-muted p-4 text-sm font-mono mt-1">
                          {viewVersion.system_message}
                        </pre>
                      </div>
                    )}
                    {viewVersion?.parameters && Object.keys(viewVersion.parameters).length > 0 && (
                      <div>
                        <Label className="text-xs text-muted-foreground">Parameters</Label>
                        <pre className="whitespace-pre-wrap rounded-md bg-muted p-4 text-xs font-mono mt-1">
                          {JSON.stringify(viewVersion.parameters, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </DialogContent>
            </Dialog>
          </TabsContent>

          {/* -------------------------------------------------------------- */}
          {/* Usage Tab                                                       */}
          {/* -------------------------------------------------------------- */}
          <TabsContent value="usage" className="space-y-4">
            {/* Source code location */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Source Location</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {prompt.source_file ? (
                  <div className="flex items-center gap-3 rounded-md border px-4 py-3 bg-muted/30">
                    <FileCode className="h-4 w-4 text-muted-foreground shrink-0" />
                    <span className="font-mono text-sm">{prompt.source_file}</span>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No source file recorded.</p>
                )}
                {prompt.agent_id && (
                  <div className="flex items-center gap-3 rounded-md border px-4 py-3 bg-muted/30">
                    <Zap className="h-4 w-4 text-muted-foreground shrink-0" />
                    <span className="text-sm">
                      Bound to agent: <span className="font-mono font-medium">{prompt.agent_id}</span>
                    </span>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Runtime call metrics */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Runtime Calls</CardTitle>
              </CardHeader>
              <CardContent>
                {usagesLoading ? (
                  <div className="flex justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin" />
                  </div>
                ) : usages.length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-6">
                    No runtime call data recorded yet.
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Type</TableHead>
                          <TableHead>Location</TableHead>
                          <TableHead className="text-right">Calls</TableHead>
                          <TableHead className="text-right">Avg Latency (ms)</TableHead>
                          <TableHead className="text-right">Total Tokens</TableHead>
                          <TableHead className="text-right">Errors</TableHead>
                          <TableHead>Last Model</TableHead>
                          <TableHead>Last Called</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {usages.map((u) => (
                          <TableRow key={u.id}>
                            <TableCell>
                              <Badge variant="outline">{u.usage_type}</Badge>
                            </TableCell>
                            <TableCell className="font-mono text-xs max-w-[200px] truncate">
                              {u.location}
                            </TableCell>
                            <TableCell className="text-right font-medium">
                              {u.call_count.toLocaleString()}
                            </TableCell>
                            <TableCell className="text-right text-muted-foreground">
                              {u.avg_latency_ms != null ? u.avg_latency_ms.toFixed(0) : "--"}
                            </TableCell>
                            <TableCell className="text-right text-muted-foreground">
                              {u.total_tokens.toLocaleString()}
                            </TableCell>
                            <TableCell className="text-right">
                              {u.error_count > 0 ? (
                                <span className="text-red-500 font-medium">{u.error_count}</span>
                              ) : (
                                <span className="text-muted-foreground">0</span>
                              )}
                            </TableCell>
                            <TableCell>{u.last_model_used ? modelBadge(u.last_model_used) : "--"}</TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {u.last_called_at ? fmtDate(u.last_called_at) : "--"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* -------------------------------------------------------------- */}
          {/* Tags Tab                                                        */}
          {/* -------------------------------------------------------------- */}
          <TabsContent value="tags" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Current Tags</CardTitle>
              </CardHeader>
              <CardContent>
                {prompt.tags && prompt.tags.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {prompt.tags.map((tag) => (
                      <Badge
                        key={tag}
                        variant="secondary"
                        className="flex items-center gap-1 pr-1"
                      >
                        {tag}
                        <button
                          onClick={() => handleRemoveTag(tag)}
                          disabled={tagsLoading}
                          className="ml-1 rounded-full p-0.5 hover:bg-destructive/20 transition-colors"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No tags assigned.</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Add Tag</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2 max-w-md">
                  <Input
                    placeholder="Enter tag name..."
                    value={newTag}
                    onChange={(e) => setNewTag(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleAddTag()}
                    disabled={tagsLoading}
                  />
                  <Button onClick={handleAddTag} disabled={tagsLoading || !newTag.trim()} size="sm">
                    <Plus className="h-4 w-4 mr-1" />
                    Add
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* -------------------------------------------------------------- */}
          {/* Test Tab                                                        */}
          {/* -------------------------------------------------------------- */}
          <TabsContent value="test" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Run Test</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="test-input" className="text-sm">
                    Input Data (JSON)
                  </Label>
                  <Textarea
                    id="test-input"
                    className="mt-1 font-mono text-sm min-h-[120px]"
                    value={testInput}
                    onChange={(e) => setTestInput(e.target.value)}
                    placeholder='{"key": "value"}'
                  />
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <Label htmlFor="test-provider" className="text-sm">
                      Provider Override
                    </Label>
                    <Select value={testProvider} onValueChange={setTestProvider}>
                      <SelectTrigger id="test-provider" className="mt-1">
                        <SelectValue placeholder="Default provider" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="default">Default</SelectItem>
                        <SelectItem value="openai">OpenAI</SelectItem>
                        <SelectItem value="anthropic">Anthropic</SelectItem>
                        <SelectItem value="azure">Azure</SelectItem>
                        <SelectItem value="google">Google</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="test-model" className="text-sm">
                      Model Override
                    </Label>
                    <Input
                      id="test-model"
                      className="mt-1"
                      placeholder="e.g. gpt-4o, claude-sonnet-4-20250514"
                      value={testModel}
                      onChange={(e) => setTestModel(e.target.value)}
                    />
                  </div>
                </div>

                <Button onClick={handleRunTest} disabled={testRunning}>
                  {testRunning ? (
                    <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4 mr-1" />
                  )}
                  Run Test
                </Button>
              </CardContent>
            </Card>

            {/* Test result */}
            {testResult && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Test Result</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label className="text-xs text-muted-foreground">Output</Label>
                    <ScrollArea className="max-h-[300px]">
                      <pre className="whitespace-pre-wrap rounded-md bg-muted p-4 text-sm font-mono mt-1">
                        {testResult.output}
                      </pre>
                    </ScrollArea>
                  </div>
                  <Separator />
                  <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    <div className="rounded-md border p-3">
                      <p className="text-xs text-muted-foreground">Model Used</p>
                      <p className="text-sm font-medium font-mono">{testResult.model_used}</p>
                    </div>
                    <div className="rounded-md border p-3">
                      <p className="text-xs text-muted-foreground">Tokens In</p>
                      <p className="text-sm font-medium">{testResult.tokens_in.toLocaleString()}</p>
                    </div>
                    <div className="rounded-md border p-3">
                      <p className="text-xs text-muted-foreground">Tokens Out</p>
                      <p className="text-sm font-medium">{testResult.tokens_out.toLocaleString()}</p>
                    </div>
                    <div className="rounded-md border p-3">
                      <p className="text-xs text-muted-foreground">Latency</p>
                      <p className="text-sm font-medium">{testResult.latency_ms.toFixed(0)} ms</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Saved test cases */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Saved Test Cases</CardTitle>
              </CardHeader>
              <CardContent>
                {testCasesLoading ? (
                  <div className="flex justify-center py-8">
                    <Loader2 className="h-5 w-5 animate-spin" />
                  </div>
                ) : testCases.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No saved test cases.</p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Input Data</TableHead>
                        <TableHead>Expected Output</TableHead>
                        <TableHead>Created</TableHead>
                        <TableHead className="text-right">Action</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {testCases.map((tc) => (
                        <TableRow key={tc.id}>
                          <TableCell className="font-medium">{tc.name}</TableCell>
                          <TableCell className="font-mono text-xs max-w-[200px] truncate">
                            {JSON.stringify(tc.input_data)}
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">
                            {tc.expected_output || "--"}
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {fmtDate(tc.created_at)}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setTestInput(JSON.stringify(tc.input_data, null, 2))
                              }}
                            >
                              <Play className="h-4 w-4 mr-1" />
                              Load
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* -------------------------------------------------------------- */}
          {/* Orchestration Tab                                               */}
          {/* -------------------------------------------------------------- */}
          <TabsContent value="orchestration">
            <OrchestrationTab prompt={prompt} />
          </TabsContent>
        </Tabs>
      </div>
    </TooltipProvider>
  )
}
