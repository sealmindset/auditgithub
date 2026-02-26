"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Loader2, Copy, Check, AlertTriangle, ChevronRight, ChevronLeft } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

interface ToolCategory {
  display_name: string
  tools: string[]
}

interface CreateApiKeyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: () => void
}

export function CreateApiKeyDialog({ open, onOpenChange, onCreated }: CreateApiKeyDialogProps) {
  const [step, setStep] = useState(1)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const { toast } = useToast()

  // Step 1 — Basics
  const [name, setName] = useState("")
  const [expiresInDays, setExpiresInDays] = useState<string>("90")
  const [rateLimit, setRateLimit] = useState("1000")

  // Step 2 — Tool Scope
  const [toolScopeMode, setToolScopeMode] = useState<"all" | "restrict">("all")
  const [selectedCategories, setSelectedCategories] = useState<string[]>([])
  const [selectedTools, setSelectedTools] = useState<string[]>([])
  const [toolCategories, setToolCategories] = useState<Record<string, ToolCategory>>({})

  // Step 3 — Repository Scope
  const [repoScopeMode, setRepoScopeMode] = useState<"all" | "restrict">("all")
  const [selectedRepoIds, setSelectedRepoIds] = useState<string[]>([])
  const [repositories, setRepositories] = useState<{ id: string; name: string }[]>([])
  const [repoSearch, setRepoSearch] = useState("")

  // Step 4 — Result
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [createdKeyPrefix, setCreatedKeyPrefix] = useState("")

  // Fetch tool categories on mount
  useEffect(() => {
    if (open) {
      fetch(`${API_BASE}/api/api-keys/tool-categories`, { credentials: "include" })
        .then((res) => res.json())
        .then(setToolCategories)
        .catch(() => {})

      fetch(`${API_BASE}/api/repositories`, { credentials: "include" })
        .then((res) => res.json())
        .then((data) => {
          const repos = Array.isArray(data) ? data : data.repositories || []
          setRepositories(repos.map((r: any) => ({ id: String(r.id), name: r.name || r.full_name || "" })))
        })
        .catch(() => {})
    }
  }, [open])

  const resetForm = () => {
    setStep(1)
    setName("")
    setExpiresInDays("90")
    setRateLimit("1000")
    setToolScopeMode("all")
    setSelectedCategories([])
    setSelectedTools([])
    setRepoScopeMode("all")
    setSelectedRepoIds([])
    setRepoSearch("")
    setCreatedKey(null)
    setCreatedKeyPrefix("")
    setCopied(false)
  }

  const handleClose = (isOpen: boolean) => {
    if (!isOpen) {
      resetForm()
    }
    onOpenChange(isOpen)
  }

  const handleCreate = async () => {
    setLoading(true)
    try {
      const body: any = {
        name,
        rate_limit_per_hour: parseInt(rateLimit) || 1000,
      }

      if (expiresInDays === "never") {
        body.expires_in_days = null
      } else {
        body.expires_in_days = parseInt(expiresInDays)
      }

      if (toolScopeMode === "restrict") {
        if (selectedCategories.length > 0) body.allowed_tool_categories = selectedCategories
        if (selectedTools.length > 0) body.allowed_tools = selectedTools
      }

      if (repoScopeMode === "restrict" && selectedRepoIds.length > 0) {
        body.allowed_repository_ids = selectedRepoIds
      }

      const res = await fetch(`${API_BASE}/api/api-keys`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(body),
      })

      if (res.ok) {
        const data = await res.json()
        setCreatedKey(data.key)
        setCreatedKeyPrefix(data.key_prefix)
        setStep(4)
        onCreated()
        toast({ title: "API key created successfully" })
      } else {
        const err = await res.json().catch(() => ({}))
        toast({
          title: "Failed to create API key",
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
    if (createdKey) {
      navigator.clipboard.writeText(createdKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const toggleCategory = (cat: string) => {
    setSelectedCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]
    )
  }

  const toggleTool = (tool: string) => {
    setSelectedTools((prev) =>
      prev.includes(tool) ? prev.filter((t) => t !== tool) : [...prev, tool]
    )
  }

  const toggleRepo = (repoId: string) => {
    setSelectedRepoIds((prev) =>
      prev.includes(repoId) ? prev.filter((r) => r !== repoId) : [...prev, repoId]
    )
  }

  const filteredRepos = repositories.filter((r) =>
    r.name.toLowerCase().includes(repoSearch.toLowerCase())
  )

  const canProceed = () => {
    if (step === 1) return name.trim().length > 0
    return true
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {step === 4 ? "API Key Created" : `Generate New API Key (Step ${step}/3)`}
          </DialogTitle>
          <DialogDescription>
            {step === 1 && "Set the key name, expiration, and rate limit."}
            {step === 2 && "Choose which security tools this key can access."}
            {step === 3 && "Choose which repositories this key can access."}
            {step === 4 && "Copy your API key now. It will not be shown again."}
          </DialogDescription>
        </DialogHeader>

        {/* Step 1 — Basics */}
        {step === 1 && (
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="key-name">Key Name</Label>
              <Input
                id="key-name"
                placeholder="e.g., CI Pipeline Key"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={255}
              />
            </div>
            <div className="space-y-2">
              <Label>Expiration</Label>
              <Select value={expiresInDays} onValueChange={setExpiresInDays}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="30">30 days</SelectItem>
                  <SelectItem value="90">90 days</SelectItem>
                  <SelectItem value="180">180 days</SelectItem>
                  <SelectItem value="365">1 year</SelectItem>
                  <SelectItem value="never">No expiration</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="rate-limit">Rate Limit (requests/hour)</Label>
              <Input
                id="rate-limit"
                type="number"
                min={100}
                max={100000}
                value={rateLimit}
                onChange={(e) => setRateLimit(e.target.value)}
              />
            </div>
          </div>
        )}

        {/* Step 2 — Tool Scope */}
        {step === 2 && (
          <div className="space-y-4 py-2">
            <div className="flex gap-4">
              <Button
                variant={toolScopeMode === "all" ? "default" : "outline"}
                size="sm"
                onClick={() => setToolScopeMode("all")}
              >
                All Tools
              </Button>
              <Button
                variant={toolScopeMode === "restrict" ? "default" : "outline"}
                size="sm"
                onClick={() => setToolScopeMode("restrict")}
              >
                Restrict Tools
              </Button>
            </div>
            {toolScopeMode === "restrict" && (
              <div className="max-h-60 overflow-y-auto space-y-3 border rounded-md p-3">
                {Object.entries(toolCategories).map(([catKey, cat]) => (
                  <div key={catKey}>
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id={`cat-${catKey}`}
                        checked={selectedCategories.includes(catKey)}
                        onCheckedChange={() => toggleCategory(catKey)}
                      />
                      <Label htmlFor={`cat-${catKey}`} className="font-medium text-sm">
                        {cat.display_name}
                      </Label>
                    </div>
                    <div className="ml-6 mt-1 space-y-1">
                      {cat.tools.map((tool) => (
                        <div key={tool} className="flex items-center space-x-2">
                          <Checkbox
                            id={`tool-${tool}`}
                            checked={selectedTools.includes(tool) || selectedCategories.includes(catKey)}
                            disabled={selectedCategories.includes(catKey)}
                            onCheckedChange={() => toggleTool(tool)}
                          />
                          <Label htmlFor={`tool-${tool}`} className="text-sm font-normal text-muted-foreground">
                            {tool}
                          </Label>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Step 3 — Repository Scope */}
        {step === 3 && (
          <div className="space-y-4 py-2">
            <div className="flex gap-4">
              <Button
                variant={repoScopeMode === "all" ? "default" : "outline"}
                size="sm"
                onClick={() => setRepoScopeMode("all")}
              >
                All Repositories
              </Button>
              <Button
                variant={repoScopeMode === "restrict" ? "default" : "outline"}
                size="sm"
                onClick={() => setRepoScopeMode("restrict")}
              >
                Restrict Repositories
              </Button>
            </div>
            {repoScopeMode === "restrict" && (
              <>
                <Input
                  placeholder="Search repositories..."
                  value={repoSearch}
                  onChange={(e) => setRepoSearch(e.target.value)}
                />
                <div className="max-h-48 overflow-y-auto space-y-1 border rounded-md p-3">
                  {filteredRepos.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No repositories found</p>
                  ) : (
                    filteredRepos.map((repo) => (
                      <div key={repo.id} className="flex items-center space-x-2">
                        <Checkbox
                          id={`repo-${repo.id}`}
                          checked={selectedRepoIds.includes(repo.id)}
                          onCheckedChange={() => toggleRepo(repo.id)}
                        />
                        <Label htmlFor={`repo-${repo.id}`} className="text-sm font-normal">
                          {repo.name}
                        </Label>
                      </div>
                    ))
                  )}
                </div>
                {selectedRepoIds.length > 0 && (
                  <p className="text-sm text-muted-foreground">
                    {selectedRepoIds.length} repositor{selectedRepoIds.length === 1 ? "y" : "ies"} selected
                  </p>
                )}
              </>
            )}
          </div>
        )}

        {/* Step 4 — Key Created */}
        {step === 4 && createdKey && (
          <div className="space-y-4 py-2">
            <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 flex items-start gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5 shrink-0" />
              <p className="text-sm text-yellow-800">
                This key will only be shown once. Copy it now and store it securely.
              </p>
            </div>
            <div className="space-y-2">
              <Label>API Key</Label>
              <div className="flex gap-2">
                <Input
                  readOnly
                  value={createdKey}
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
            <div className="text-sm text-muted-foreground">
              Key prefix: <code className="bg-gray-100 px-1 rounded">{createdKeyPrefix}</code>
            </div>
          </div>
        )}

        <DialogFooter>
          {step < 4 && (
            <div className="flex w-full justify-between">
              <Button
                variant="outline"
                onClick={() => (step === 1 ? handleClose(false) : setStep(step - 1))}
                disabled={loading}
              >
                {step === 1 ? (
                  "Cancel"
                ) : (
                  <>
                    <ChevronLeft className="h-4 w-4 mr-1" />
                    Back
                  </>
                )}
              </Button>
              {step < 3 ? (
                <Button onClick={() => setStep(step + 1)} disabled={!canProceed()}>
                  Next
                  <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              ) : (
                <Button onClick={handleCreate} disabled={loading || !canProceed()}>
                  {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Generate Key
                </Button>
              )}
            </div>
          )}
          {step === 4 && (
            <Button onClick={() => handleClose(false)}>Done</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
