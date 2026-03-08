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
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { ArrowLeft, Loader2, Save } from "lucide-react"

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
  tags: string[]
}

interface PromptVersion {
  id: string
  version: number
  content: string
  system_message: string | null
  parameters: Record<string, any> | null
  input_schema: Record<string, any> | null
  output_schema: Record<string, any> | null
  model: string | null
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function PromptEditPage() {
  const params = useParams()
  const router = useRouter()
  const slug = params.slug as string

  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)

  // Form fields
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [category, setCategory] = useState("")
  const [subcategory, setSubcategory] = useState("")
  const [agentId, setAgentId] = useState("")
  const [provider, setProvider] = useState("")
  const [model, setModel] = useState("")
  const [content, setContent] = useState("")
  const [systemMessage, setSystemMessage] = useState("")
  const [parameters, setParameters] = useState("")
  const [inputSchema, setInputSchema] = useState("")
  const [outputSchema, setOutputSchema] = useState("")
  const [tags, setTags] = useState("")
  const [changeSummary, setChangeSummary] = useState("")

  // Original prompt for display
  const [prompt, setPrompt] = useState<Prompt | null>(null)

  const fetchData = useCallback(async () => {
    try {
      const [promptRes, versionsRes] = await Promise.all([
        apiFetch(`${API_BASE}/prompts/${slug}`),
        apiFetch(`${API_BASE}/prompts/${slug}/versions`),
      ])

      if (!promptRes.ok) throw new Error("Prompt not found")
      const promptData: Prompt = await promptRes.json()
      setPrompt(promptData)

      // Populate form fields from prompt metadata
      setName(promptData.name)
      setDescription(promptData.description ?? "")
      setCategory(promptData.category)
      setSubcategory(promptData.subcategory ?? "")
      setAgentId(promptData.agent_id ?? "")
      setProvider(promptData.provider ?? "")
      setModel(promptData.model ?? "")
      setTags(promptData.tags?.join(", ") ?? "")

      // Populate content from latest version
      if (versionsRes.ok) {
        const raw = await versionsRes.json()
        const versions: PromptVersion[] = raw.items ?? raw
        if (versions.length > 0) {
          const latest = [...versions].sort((a, b) => b.version - a.version)[0]
          setContent(latest.content)
          setSystemMessage(latest.system_message ?? "")
          setParameters(
            latest.parameters && Object.keys(latest.parameters).length > 0
              ? JSON.stringify(latest.parameters, null, 2)
              : ""
          )
          setInputSchema(
            latest.input_schema && Object.keys(latest.input_schema).length > 0
              ? JSON.stringify(latest.input_schema, null, 2)
              : ""
          )
          setOutputSchema(
            latest.output_schema && Object.keys(latest.output_schema).length > 0
              ? JSON.stringify(latest.output_schema, null, 2)
              : ""
          )
        }
      }
    } catch {
      setError("Failed to load prompt")
    } finally {
      setLoading(false)
    }
  }, [slug])

  useEffect(() => {
    if (slug) fetchData()
  }, [slug, fetchData])

  async function handleSave() {
    if (!changeSummary.trim()) {
      setSaveError("Change summary is required")
      return
    }
    if (!content.trim()) {
      setSaveError("Prompt content is required")
      return
    }

    setSaving(true)
    setSaveError(null)

    const body: Record<string, any> = {
      content: content.trim(),
      change_summary: changeSummary.trim(),
    }

    // Only include optional fields if they have values
    if (name.trim()) body.name = name.trim()
    if (description.trim()) body.description = description.trim()
    if (category.trim()) body.category = category.trim()
    if (subcategory.trim()) body.subcategory = subcategory.trim()
    if (agentId.trim()) body.agent_id = agentId.trim()
    if (provider.trim()) body.provider = provider.trim()
    if (model.trim()) body.model = model.trim()
    if (systemMessage.trim()) body.system_message = systemMessage.trim()
    if (tags.trim()) {
      body.tags = tags.split(",").map((t) => t.trim()).filter(Boolean)
    }

    // Parse JSON fields
    try {
      if (parameters.trim()) body.parameters = JSON.parse(parameters)
    } catch {
      setSaveError("Invalid JSON in Parameters field")
      setSaving(false)
      return
    }
    try {
      if (inputSchema.trim()) body.input_schema = JSON.parse(inputSchema)
    } catch {
      setSaveError("Invalid JSON in Input Schema field")
      setSaving(false)
      return
    }
    try {
      if (outputSchema.trim()) body.output_schema = JSON.parse(outputSchema)
    } catch {
      setSaveError("Invalid JSON in Output Schema field")
      setSaving(false)
      return
    }

    try {
      const res = await apiFetch(`${API_BASE}/prompts/${slug}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })

      if (res.ok) {
        router.push(`/prompts/${slug}`)
      } else {
        const errData = await res.json().catch(() => null)
        setSaveError(errData?.detail ?? `Save failed (${res.status})`)
      }
    } catch {
      setSaveError("Network error saving prompt")
    } finally {
      setSaving(false)
    }
  }

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

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
    <div className="flex flex-1 flex-col gap-6 p-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link href={`/prompts/${slug}`}>
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Edit: {prompt.name}</h1>
          <p className="text-sm text-muted-foreground font-mono">{prompt.slug}</p>
        </div>
        <Badge variant="outline" className="ml-2">v{prompt.current_version}</Badge>
      </div>

      <Separator />

      {/* Error banner */}
      {saveError && (
        <div className="rounded-md bg-red-500/10 border border-red-500/30 p-3 text-sm text-red-700 dark:text-red-300">
          {saveError}
        </div>
      )}

      {/* Metadata section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Prompt Metadata</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <Label htmlFor="name">Name</Label>
              <Input id="name" value={name} onChange={(e) => setName(e.target.value)} className="mt-1" />
            </div>
            <div>
              <Label htmlFor="category">Category</Label>
              <Select value={category} onValueChange={setCategory}>
                <SelectTrigger id="category" className="mt-1">
                  <SelectValue placeholder="Select category" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="system">system</SelectItem>
                  <SelectItem value="user">user</SelectItem>
                  <SelectItem value="template">template</SelectItem>
                  <SelectItem value="agent">agent</SelectItem>
                  <SelectItem value="skill">skill</SelectItem>
                  <SelectItem value="mcp">mcp</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="mt-1"
              rows={2}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <Label htmlFor="subcategory">Subcategory</Label>
              <Input id="subcategory" value={subcategory} onChange={(e) => setSubcategory(e.target.value)} className="mt-1" />
            </div>
            <div>
              <Label htmlFor="provider">Provider</Label>
              <Input id="provider" value={provider} onChange={(e) => setProvider(e.target.value)} className="mt-1" placeholder="e.g. anthropic, openai" />
            </div>
            <div>
              <Label htmlFor="model">Model</Label>
              <Input id="model" value={model} onChange={(e) => setModel(e.target.value)} className="mt-1" placeholder="e.g. claude-sonnet-4-20250514" />
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <Label htmlFor="agent_id">Agent ID</Label>
              <Input id="agent_id" value={agentId} onChange={(e) => setAgentId(e.target.value)} className="mt-1" />
            </div>
            <div>
              <Label htmlFor="tags">Tags (comma-separated)</Label>
              <Input id="tags" value={tags} onChange={(e) => setTags(e.target.value)} className="mt-1" placeholder="security, production, v2" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Content section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Prompt Content</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="content">Content *</Label>
            <Textarea
              id="content"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              className="mt-1 font-mono text-sm min-h-[300px]"
            />
          </div>

          <div>
            <Label htmlFor="system_message">System Message</Label>
            <Textarea
              id="system_message"
              value={systemMessage}
              onChange={(e) => setSystemMessage(e.target.value)}
              className="mt-1 font-mono text-sm min-h-[150px]"
            />
          </div>
        </CardContent>
      </Card>

      {/* Advanced section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Advanced (JSON)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="parameters">Parameters</Label>
            <Textarea
              id="parameters"
              value={parameters}
              onChange={(e) => setParameters(e.target.value)}
              className="mt-1 font-mono text-sm min-h-[100px]"
              placeholder='{"temperature": 0.7, "max_tokens": 4096}'
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <Label htmlFor="input_schema">Input Schema</Label>
              <Textarea
                id="input_schema"
                value={inputSchema}
                onChange={(e) => setInputSchema(e.target.value)}
                className="mt-1 font-mono text-sm min-h-[100px]"
              />
            </div>
            <div>
              <Label htmlFor="output_schema">Output Schema</Label>
              <Textarea
                id="output_schema"
                value={outputSchema}
                onChange={(e) => setOutputSchema(e.target.value)}
                className="mt-1 font-mono text-sm min-h-[100px]"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Save section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Save Changes</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="change_summary">Change Summary *</Label>
            <Input
              id="change_summary"
              value={changeSummary}
              onChange={(e) => setChangeSummary(e.target.value)}
              className="mt-1"
              placeholder="Describe what changed and why..."
            />
          </div>
          <div className="flex items-center gap-3">
            <Button onClick={handleSave} disabled={saving || !changeSummary.trim() || !content.trim()}>
              {saving ? (
                <Loader2 className="h-4 w-4 mr-1 animate-spin" />
              ) : (
                <Save className="h-4 w-4 mr-1" />
              )}
              Save New Version
            </Button>
            <Button variant="outline" asChild>
              <Link href={`/prompts/${slug}`}>Cancel</Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
