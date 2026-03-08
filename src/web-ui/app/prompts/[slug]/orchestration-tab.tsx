"use client"

import { useEffect, useState, useCallback, useMemo } from "react"
import { useRouter } from "next/navigation"
import { apiFetch, API_BASE } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Loader2 } from "lucide-react"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface PromptNode {
  id: string
  slug: string
  name: string
  category: string
  subcategory: string | null
  agent_id: string | null
  provider: string | null
  model: string | null
  source_file: string | null
  is_active: boolean
}

// Orchestration layer definitions (top → bottom)
const LAYERS = [
  { key: "orchestrator", label: "Orchestrator", desc: "AI Agent coordinator" },
  { key: "agent", label: "Agent", desc: "Specialized execution agents" },
  { key: "system", label: "System Prompts", desc: "LLM persona & constraints" },
  { key: "template", label: "Templates", desc: "Parameterized prompts" },
  { key: "skill", label: "Skills", desc: "Reusable skill prompts" },
  { key: "mcp", label: "MCP", desc: "Model Context Protocol tools" },
] as const

type ViewMode = "tree" | "swimlane" | "radial"

const LAYER_COLORS: Record<string, string> = {
  orchestrator: "#8b5cf6",
  agent: "#f97316",
  system: "#a855f7",
  template: "#22c55e",
  skill: "#06b6d4",
  mcp: "#ec4899",
}

const LAYER_BG: Record<string, string> = {
  orchestrator: "bg-violet-500/15 border-violet-500/30 text-violet-700 dark:text-violet-300",
  agent: "bg-orange-500/15 border-orange-500/30 text-orange-700 dark:text-orange-300",
  system: "bg-purple-500/15 border-purple-500/30 text-purple-700 dark:text-purple-300",
  template: "bg-green-500/15 border-green-500/30 text-green-700 dark:text-green-300",
  skill: "bg-cyan-500/15 border-cyan-500/30 text-cyan-700 dark:text-cyan-300",
  mcp: "bg-pink-500/15 border-pink-500/30 text-pink-700 dark:text-pink-300",
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getLayerForPrompt(p: PromptNode): string {
  if (p.category === "agent") return "agent"
  if (p.category === "system") return "system"
  if (p.category === "template") return "template"
  if (p.category === "skill") return "skill"
  if (p.category === "mcp") return "mcp"
  return "template"
}

// Derive the service/orchestrator from the source_file
function getServiceName(sourceFile: string | null): string {
  if (!sourceFile) return "AI Agent"
  const file = sourceFile.split("/").pop()?.replace(".py", "").replace(/_/g, " ") ?? "AI Agent"
  return file
    .split(" ")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ")
}

// ---------------------------------------------------------------------------
// Tree View (SVG)
// ---------------------------------------------------------------------------

function TreeView({
  currentPrompt,
  relatedPrompts,
  agentId,
  onNavigate,
}: {
  currentPrompt: PromptNode
  relatedPrompts: PromptNode[]
  agentId: string
  onNavigate: (slug: string) => void
}) {
  const allPrompts = [currentPrompt, ...relatedPrompts.filter((p) => p.slug !== currentPrompt.slug)]

  // Group by layer
  const layerGroups = useMemo(() => {
    const groups: Record<string, PromptNode[]> = {}
    for (const p of allPrompts) {
      const layer = getLayerForPrompt(p)
      if (!groups[layer]) groups[layer] = []
      groups[layer].push(p)
    }
    return groups
  }, [allPrompts])

  const activeLayers = LAYERS.filter((l) => l.key === "orchestrator" || layerGroups[l.key]?.length)

  const nodeW = 180
  const nodeH = 48
  const layerGap = 80
  const nodeGap = 16
  const padX = 40
  const padY = 30

  // Calculate positions
  const layerPositions: { layer: typeof LAYERS[number]; y: number; nodes: { prompt: PromptNode | null; x: number; y: number; w: number; h: number }[] }[] = []
  let currentY = padY

  for (const layer of activeLayers) {
    const nodes = layer.key === "orchestrator"
      ? [null] // virtual orchestrator node
      : (layerGroups[layer.key] ?? [])

    const totalW = nodes.length * nodeW + (nodes.length - 1) * nodeGap
    const startX = padX + Math.max(0, (600 - totalW) / 2)

    const positioned = nodes.map((p, i) => ({
      prompt: p,
      x: startX + i * (nodeW + nodeGap),
      y: currentY,
      w: nodeW,
      h: nodeH,
    }))

    layerPositions.push({ layer, y: currentY, nodes: positioned })
    currentY += nodeH + layerGap
  }

  const svgW = Math.max(680, padX * 2 + Math.max(...layerPositions.map((lp) => lp.nodes.length)) * (nodeW + nodeGap))
  const svgH = currentY - layerGap + padY

  return (
    <div className="overflow-auto rounded-lg border bg-background">
      <svg width={svgW} height={svgH} className="block mx-auto">
        {/* Connection lines */}
        {layerPositions.map((lp, li) => {
          if (li === 0) return null
          const prevLayer = layerPositions[li - 1]
          return lp.nodes.map((node, ni) => {
            return prevLayer.nodes.map((pNode, pi) => (
              <line
                key={`${li}-${ni}-${pi}`}
                x1={pNode.x + pNode.w / 2}
                y1={pNode.y + pNode.h}
                x2={node.x + node.w / 2}
                y2={node.y}
                stroke={node.prompt?.slug === currentPrompt.slug ? LAYER_COLORS[lp.layer.key] : "#94a3b8"}
                strokeWidth={node.prompt?.slug === currentPrompt.slug ? 2.5 : 1}
                strokeDasharray={node.prompt?.slug === currentPrompt.slug ? undefined : "4 4"}
                opacity={node.prompt?.slug === currentPrompt.slug ? 1 : 0.4}
              />
            ))
          })
        })}

        {/* Nodes */}
        {layerPositions.map((lp) =>
          lp.nodes.map((node, ni) => {
            const isCurrent = node.prompt?.slug === currentPrompt.slug
            const isOrchestrator = node.prompt === null
            const color = LAYER_COLORS[lp.layer.key]
            const label = isOrchestrator
              ? agentId
              : (node.prompt?.name?.length ?? 0) > 22
                ? node.prompt!.name.slice(0, 20) + "..."
                : node.prompt!.name

            return (
              <g
                key={`${lp.layer.key}-${ni}`}
                className={!isOrchestrator ? "cursor-pointer" : ""}
                onClick={() => !isOrchestrator && node.prompt && onNavigate(node.prompt.slug)}
              >
                <rect
                  x={node.x}
                  y={node.y}
                  width={node.w}
                  height={node.h}
                  rx={8}
                  fill={isCurrent ? color : "var(--card)"}
                  stroke={color}
                  strokeWidth={isCurrent ? 2.5 : 1.5}
                  opacity={isCurrent || isOrchestrator ? 1 : 0.7}
                />
                {isCurrent && (
                  <rect
                    x={node.x - 3}
                    y={node.y - 3}
                    width={node.w + 6}
                    height={node.h + 6}
                    rx={10}
                    fill="none"
                    stroke={color}
                    strokeWidth={1}
                    strokeDasharray="4 4"
                    opacity={0.5}
                  />
                )}
                <text
                  x={node.x + node.w / 2}
                  y={node.y + 20}
                  textAnchor="middle"
                  fill={isCurrent ? "white" : "currentColor"}
                  fontSize={12}
                  fontWeight={isCurrent ? 700 : 500}
                  className="select-none"
                >
                  {label}
                </text>
                <text
                  x={node.x + node.w / 2}
                  y={node.y + 36}
                  textAnchor="middle"
                  fill={isCurrent ? "rgba(255,255,255,0.7)" : "#94a3b8"}
                  fontSize={10}
                  className="select-none"
                >
                  {isOrchestrator ? "orchestrator" : lp.layer.label}
                </text>
              </g>
            )
          })
        )}
      </svg>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Swimlane View (horizontal layers)
// ---------------------------------------------------------------------------

function SwimlaneView({
  currentPrompt,
  relatedPrompts,
  agentId,
  onNavigate,
}: {
  currentPrompt: PromptNode
  relatedPrompts: PromptNode[]
  agentId: string
  onNavigate: (slug: string) => void
}) {
  const allPrompts = [currentPrompt, ...relatedPrompts.filter((p) => p.slug !== currentPrompt.slug)]

  const layerGroups = useMemo(() => {
    const groups: Record<string, PromptNode[]> = {}
    for (const p of allPrompts) {
      const layer = getLayerForPrompt(p)
      if (!groups[layer]) groups[layer] = []
      groups[layer].push(p)
    }
    return groups
  }, [allPrompts])

  const activeLayers = LAYERS.filter((l) => l.key === "orchestrator" || layerGroups[l.key]?.length)

  return (
    <div className="space-y-3">
      {activeLayers.map((layer) => {
        const isOrchestrator = layer.key === "orchestrator"
        const prompts = isOrchestrator ? [] : (layerGroups[layer.key] ?? [])
        const bgClass = LAYER_BG[layer.key] ?? ""

        return (
          <div key={layer.key} className="rounded-lg border overflow-hidden">
            {/* Lane header */}
            <div className={`px-4 py-2 border-b flex items-center gap-3 ${bgClass}`}>
              <span className="font-semibold text-sm">{layer.label}</span>
              <span className="text-xs opacity-70">{layer.desc}</span>
            </div>

            {/* Lane content */}
            <div className="p-3 flex flex-wrap gap-2 min-h-[52px] bg-background">
              {isOrchestrator ? (
                <div
                  className={`rounded-md border-2 px-4 py-2 text-sm font-medium ${bgClass}`}
                >
                  {agentId}
                  <span className="ml-2 text-xs opacity-60">
                    ({getServiceName(currentPrompt.source_file)})
                  </span>
                </div>
              ) : (
                prompts.map((p) => {
                  const isCurrent = p.slug === currentPrompt.slug
                  return (
                    <button
                      key={p.slug}
                      onClick={() => onNavigate(p.slug)}
                      className={`rounded-md border px-3 py-2 text-sm text-left transition-all hover:shadow-md ${
                        isCurrent
                          ? `ring-2 ring-offset-1 font-bold ${bgClass}`
                          : "bg-muted/30 hover:bg-muted/60 text-foreground"
                      }`}
                    >
                      <div className="font-medium truncate max-w-[200px]">{p.name}</div>
                      <div className="text-[10px] opacity-60 font-mono mt-0.5">
                        {p.provider ?? "any"}{p.model ? ` / ${p.model}` : ""}
                      </div>
                    </button>
                  )
                })
              )}
            </div>
          </div>
        )
      })}

      {/* Connection legend */}
      <div className="flex items-center gap-4 text-xs text-muted-foreground pt-2">
        <span className="flex items-center gap-1">
          <span className="inline-block w-3 h-3 rounded border-2 border-violet-500 bg-violet-500/20" />
          Orchestrator
        </span>
        {Object.entries(layerGroups).map(([key]) => (
          <span key={key} className="flex items-center gap-1">
            <span
              className="inline-block w-3 h-3 rounded"
              style={{ backgroundColor: LAYER_COLORS[key] + "33", border: `2px solid ${LAYER_COLORS[key]}` }}
            />
            {LAYERS.find((l) => l.key === key)?.label ?? key}
          </span>
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Radial View (current prompt at center)
// ---------------------------------------------------------------------------

function RadialView({
  currentPrompt,
  relatedPrompts,
  agentId,
  onNavigate,
}: {
  currentPrompt: PromptNode
  relatedPrompts: PromptNode[]
  agentId: string
  onNavigate: (slug: string) => void
}) {
  const siblings = relatedPrompts.filter((p) => p.slug !== currentPrompt.slug)
  const centerX = 300
  const centerY = 260
  const innerRadius = 120
  const outerRadius = 200

  // Orchestrator node at top
  const orchX = centerX
  const orchY = centerY - outerRadius - 20

  // Sibling nodes in a ring
  const siblingPositions = siblings.map((p, i) => {
    const startAngle = -Math.PI / 2 + Math.PI / 6 // start from upper right
    const angle = startAngle + ((2 * Math.PI) / Math.max(siblings.length, 1)) * i
    return {
      prompt: p,
      x: centerX + innerRadius * Math.cos(angle),
      y: centerY + innerRadius * Math.sin(angle),
    }
  })

  const svgW = 600
  const svgH = centerY + outerRadius + 40

  return (
    <div className="overflow-auto rounded-lg border bg-background">
      <svg width={svgW} height={svgH} className="block mx-auto">
        {/* Line from orchestrator to center */}
        <line
          x1={orchX}
          y1={orchY + 20}
          x2={centerX}
          y2={centerY - 24}
          stroke={LAYER_COLORS["orchestrator"]}
          strokeWidth={2}
          opacity={0.6}
        />

        {/* Lines from center to siblings */}
        {siblingPositions.map((sp, i) => (
          <line
            key={i}
            x1={centerX}
            y1={centerY}
            x2={sp.x}
            y2={sp.y}
            stroke={LAYER_COLORS[getLayerForPrompt(sp.prompt)] ?? "#94a3b8"}
            strokeWidth={1.5}
            strokeDasharray="4 4"
            opacity={0.4}
          />
        ))}

        {/* Orchestrator node */}
        <g>
          <rect
            x={orchX - 80}
            y={orchY - 16}
            width={160}
            height={36}
            rx={8}
            fill="var(--card)"
            stroke={LAYER_COLORS["orchestrator"]}
            strokeWidth={1.5}
          />
          <text x={orchX} y={orchY + 4} textAnchor="middle" fill="currentColor" fontSize={12} fontWeight={600}>
            {agentId}
          </text>
          <text x={orchX} y={orchY + 16} textAnchor="middle" fill="#94a3b8" fontSize={9}>
            orchestrator
          </text>
        </g>

        {/* Sibling nodes */}
        {siblingPositions.map((sp, i) => {
          const color = LAYER_COLORS[getLayerForPrompt(sp.prompt)] ?? "#94a3b8"
          const label = sp.prompt.name.length > 18 ? sp.prompt.name.slice(0, 16) + "..." : sp.prompt.name
          return (
            <g
              key={i}
              className="cursor-pointer"
              onClick={() => onNavigate(sp.prompt.slug)}
            >
              <rect
                x={sp.x - 70}
                y={sp.y - 16}
                width={140}
                height={36}
                rx={8}
                fill="var(--card)"
                stroke={color}
                strokeWidth={1.5}
                opacity={0.8}
              />
              <text x={sp.x} y={sp.y + 2} textAnchor="middle" fill="currentColor" fontSize={11} fontWeight={500}>
                {label}
              </text>
              <text x={sp.x} y={sp.y + 14} textAnchor="middle" fill="#94a3b8" fontSize={9}>
                {sp.prompt.category}
              </text>
            </g>
          )
        })}

        {/* Current prompt (center, highlighted) */}
        <g>
          <circle cx={centerX} cy={centerY} r={52} fill="none" stroke={LAYER_COLORS[getLayerForPrompt(currentPrompt)]} strokeWidth={1} strokeDasharray="4 4" opacity={0.4} />
          <rect
            x={centerX - 80}
            y={centerY - 24}
            width={160}
            height={48}
            rx={10}
            fill={LAYER_COLORS[getLayerForPrompt(currentPrompt)]}
            stroke={LAYER_COLORS[getLayerForPrompt(currentPrompt)]}
            strokeWidth={2}
          />
          <text x={centerX} y={centerY - 4} textAnchor="middle" fill="white" fontSize={12} fontWeight={700}>
            {currentPrompt.name.length > 20 ? currentPrompt.name.slice(0, 18) + "..." : currentPrompt.name}
          </text>
          <text x={centerX} y={centerY + 12} textAnchor="middle" fill="rgba(255,255,255,0.7)" fontSize={10}>
            {currentPrompt.category} (current)
          </text>
        </g>
      </svg>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Orchestration Tab
// ---------------------------------------------------------------------------

export function OrchestrationTab({ prompt }: { prompt: PromptNode }) {
  const router = useRouter()
  const [viewMode, setViewMode] = useState<ViewMode>("tree")
  const [relatedPrompts, setRelatedPrompts] = useState<PromptNode[]>([])
  const [loading, setLoading] = useState(true)

  const agentId = prompt.agent_id ?? "global"

  const fetchRelated = useCallback(async () => {
    setLoading(true)
    try {
      if (prompt.agent_id) {
        // Fetch all prompts for this agent
        const res = await apiFetch(`${API_BASE}/prompts/agents/${prompt.agent_id}`)
        if (res.ok) {
          const data = await res.json()
          setRelatedPrompts(data.prompts ?? [])
        }
      } else {
        // No agent - fetch prompts with same subcategory or source_file
        const res = await apiFetch(`${API_BASE}/prompts/?limit=200`)
        if (res.ok) {
          const data = await res.json()
          const all: PromptNode[] = data.items ?? []
          // Find related by subcategory or source_file
          const related = all.filter(
            (p) =>
              p.slug !== prompt.slug &&
              ((prompt.subcategory && p.subcategory === prompt.subcategory) ||
                (prompt.source_file && p.source_file === prompt.source_file))
          )
          setRelatedPrompts(related)
        }
      }
    } catch {
      // silent
    } finally {
      setLoading(false)
    }
  }, [prompt.agent_id, prompt.slug, prompt.subcategory, prompt.source_file])

  useEffect(() => {
    fetchRelated()
  }, [fetchRelated])

  function handleNavigate(slug: string) {
    router.push(`/prompts/${slug}`)
  }

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* View mode toggle */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          Showing orchestration for{" "}
          <span className="font-mono font-medium text-foreground">{agentId}</span>
          {" "}&middot;{" "}
          {relatedPrompts.length + 1} prompt{relatedPrompts.length !== 0 ? "s" : ""}
        </div>
        <div className="flex rounded-lg border overflow-hidden">
          {(
            [
              { key: "tree", label: "Tree" },
              { key: "swimlane", label: "Swimlane" },
              { key: "radial", label: "Radial" },
            ] as const
          ).map((v) => (
            <button
              key={v.key}
              onClick={() => setViewMode(v.key)}
              className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                viewMode === v.key
                  ? "bg-primary text-primary-foreground"
                  : "bg-background text-muted-foreground hover:bg-muted"
              }`}
            >
              {v.label}
            </button>
          ))}
        </div>
      </div>

      {/* Graph */}
      {viewMode === "tree" && (
        <TreeView
          currentPrompt={prompt}
          relatedPrompts={relatedPrompts}
          agentId={agentId}
          onNavigate={handleNavigate}
        />
      )}
      {viewMode === "swimlane" && (
        <SwimlaneView
          currentPrompt={prompt}
          relatedPrompts={relatedPrompts}
          agentId={agentId}
          onNavigate={handleNavigate}
        />
      )}
      {viewMode === "radial" && (
        <RadialView
          currentPrompt={prompt}
          relatedPrompts={relatedPrompts}
          agentId={agentId}
          onNavigate={handleNavigate}
        />
      )}

      {/* Legend */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Orchestration Layers</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {LAYERS.map((layer) => (
              <div key={layer.key} className="flex items-center gap-2 text-xs">
                <span
                  className="inline-block w-3 h-3 rounded-sm shrink-0"
                  style={{ backgroundColor: LAYER_COLORS[layer.key] }}
                />
                <span className="font-medium">{layer.label}</span>
                <span className="text-muted-foreground hidden sm:inline">— {layer.desc}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
