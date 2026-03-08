"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { apiFetch, API_BASE } from "@/lib/api"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  Bot,
  ChevronDown,
  ChevronRight,
  FileText,
  Hash,
  Activity,
  Loader2,
  AlertCircle,
} from "lucide-react"

interface Prompt {
  id: string
  name: string
  slug: string
  model: string
  category: string
  is_active: boolean
}

interface AgentSummary {
  agent_id: string
  prompt_count: number
  active_count: number
  total_calls: number
  prompts: Prompt[]
}

const categoryColors: Record<string, string> = {
  system: "bg-purple-500/15 text-purple-700 dark:text-purple-400 border-purple-500/30",
  user: "bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30",
  template: "bg-green-500/15 text-green-700 dark:text-green-400 border-green-500/30",
  agent: "bg-orange-500/15 text-orange-700 dark:text-orange-400 border-orange-500/30",
  skill: "bg-cyan-500/15 text-cyan-700 dark:text-cyan-400 border-cyan-500/30",
  mcp: "bg-pink-500/15 text-pink-700 dark:text-pink-400 border-pink-500/30",
}

export default function AgentInventoryPage() {
  const router = useRouter()
  const [agents, setAgents] = useState<AgentSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expandedAgents, setExpandedAgents] = useState<Set<string>>(new Set())

  useEffect(() => {
    async function fetchAgents() {
      try {
        setLoading(true)
        const res = await apiFetch(`${API_BASE}/prompts/agents`)
        if (!res.ok) throw new Error(`Failed to fetch agents: ${res.status}`)
        const data = await res.json()
        setAgents(data.items ?? [])
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error")
      } finally {
        setLoading(false)
      }
    }
    fetchAgents()
  }, [])

  function toggleAgent(agentId: string) {
    setExpandedAgents((prev) => {
      const next = new Set(prev)
      if (next.has(agentId)) {
        next.delete(agentId)
      } else {
        next.add(agentId)
      }
      return next
    })
  }

  if (loading) {
    return (
      <div className="container mx-auto py-12 flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <span className="ml-3 text-muted-foreground">Loading agents...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="container mx-auto py-12">
        <div className="flex items-center gap-2 rounded-lg border border-destructive/50 bg-destructive/10 p-4">
          <AlertCircle className="h-5 w-5 text-destructive" />
          <p className="text-destructive">{error}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Agent Inventory</h1>
        <p className="text-muted-foreground mt-1">
          All AI agents and their bound prompt configurations.
        </p>
      </div>

      <Separator />

      {agents.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          <Bot className="h-12 w-12 mx-auto mb-3 opacity-40" />
          <p>No agents found.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {agents.map((agent) => {
            const isExpanded = expandedAgents.has(agent.agent_id)
            return (
              <Card key={agent.agent_id} className="transition-shadow hover:shadow-md">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                        <Bot className="h-5 w-5 text-muted-foreground" />
                      </div>
                      <div>
                        <CardTitle className="text-lg">{agent.agent_id}</CardTitle>
                        <CardDescription className="flex items-center gap-3 mt-1">
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="flex items-center gap-1">
                                  <FileText className="h-3.5 w-3.5" />
                                  {agent.prompt_count} prompts
                                </span>
                              </TooltipTrigger>
                              <TooltipContent>Total bound prompts</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="flex items-center gap-1">
                                  <Activity className="h-3.5 w-3.5" />
                                  {agent.active_count} active
                                </span>
                              </TooltipTrigger>
                              <TooltipContent>Active prompts</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="flex items-center gap-1">
                                  <Hash className="h-3.5 w-3.5" />
                                  {agent.total_calls.toLocaleString()} calls
                                </span>
                              </TooltipTrigger>
                              <TooltipContent>Total API calls</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        </CardDescription>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => toggleAgent(agent.agent_id)}
                    >
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                      <span className="ml-1 text-xs">
                        {isExpanded ? "Collapse" : "Expand"}
                      </span>
                    </Button>
                  </div>
                </CardHeader>

                {isExpanded && agent.prompts.length > 0 && (
                  <CardContent className="pt-0">
                    <Separator className="mb-4" />
                    <div className="space-y-2">
                      {agent.prompts.map((prompt) => (
                        <div
                          key={prompt.slug}
                          className="flex items-center justify-between rounded-md border px-4 py-3 transition-colors hover:bg-muted/50"
                        >
                          <div className="flex items-center gap-3">
                            <button
                              onClick={() => router.push(`/prompts/${prompt.slug}`)}
                              className="font-medium text-sm hover:underline text-left"
                            >
                              {prompt.name}
                            </button>
                            <Badge
                              variant="outline"
                              className={
                                categoryColors[prompt.category] ??
                                "bg-muted text-muted-foreground"
                              }
                            >
                              {prompt.category}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-xs text-muted-foreground font-mono">
                              {prompt.model}
                            </span>
                            <Badge
                              variant={prompt.is_active ? "default" : "secondary"}
                              className="text-xs"
                            >
                              {prompt.is_active ? "Active" : "Inactive"}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                )}

                {isExpanded && agent.prompts.length === 0 && (
                  <CardContent className="pt-0">
                    <Separator className="mb-4" />
                    <p className="text-sm text-muted-foreground text-center py-4">
                      No prompts bound to this agent.
                    </p>
                  </CardContent>
                )}
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
