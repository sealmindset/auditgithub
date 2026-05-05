"use client"

import { useState, useCallback } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet"
import { Loader2, Send, Search, Check, X, Copy, Palette, Wand2 } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import { API_BASE, apiFetch } from "@/lib/api"

interface DiagramEditorPanelProps {
    projectId: string
    currentCode: string
    onApply: (newCode: string, newImage: string | null) => void
    onClose: () => void
}

interface IconEntry {
    name: string
    label: string
    import_path: string
    provider: string
    category: string | null
    usage: string
    is_custom: boolean
}

export function DiagramEditorPanel({ projectId, currentCode, onApply, onClose }: DiagramEditorPanelProps) {
    const [instruction, setInstruction] = useState("")
    const [loading, setLoading] = useState(false)
    const [previewCode, setPreviewCode] = useState<string | null>(null)
    const [previewImage, setPreviewImage] = useState<string | null>(null)
    const [changesSummary, setChangesSummary] = useState("")
    const [fixLog, setFixLog] = useState<string[]>([])

    const [iconBrowserOpen, setIconBrowserOpen] = useState(false)
    const [iconSearch, setIconSearch] = useState("")
    const [iconResults, setIconResults] = useState<IconEntry[]>([])
    const [iconProviders, setIconProviders] = useState<Record<string, number>>({})
    const [iconLoading, setIconLoading] = useState(false)
    const [copiedIcon, setCopiedIcon] = useState<string | null>(null)

    const { toast } = useToast()

    const submitEdit = async () => {
        if (!instruction.trim()) return
        setLoading(true)
        setPreviewCode(null)
        setPreviewImage(null)

        try {
            const res = await apiFetch(`${API_BASE}/ai/architecture/edit`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    project_id: projectId,
                    instruction: instruction.trim(),
                    code: currentCode,
                }),
            })

            if (!res.ok) {
                const err = await res.json()
                throw new Error(err.detail || "Edit failed")
            }

            const data = await res.json()
            setPreviewCode(data.code)
            setPreviewImage(data.image || null)
            setChangesSummary(data.changes_summary || "")
            setFixLog(data.fix_log || [])
        } catch (err) {
            toast({
                title: "Edit Failed",
                description: err instanceof Error ? err.message : "Unknown error",
                variant: "destructive",
            })
        } finally {
            setLoading(false)
        }
    }

    const searchIcons = useCallback(async (query: string) => {
        setIconLoading(true)
        try {
            const params = new URLSearchParams()
            if (query.trim()) params.set("q", query.trim())
            params.set("limit", "50")

            const res = await apiFetch(`${API_BASE}/ai/architecture/icons?${params}`)
            if (res.ok) {
                const data = await res.json()
                setIconResults(data.icons || [])
                setIconProviders(data.providers || {})
            }
        } catch (err) {
            console.error("Icon search failed:", err)
        } finally {
            setIconLoading(false)
        }
    }, [])

    const copyUsage = (icon: IconEntry) => {
        navigator.clipboard.writeText(icon.usage)
        setCopiedIcon(icon.name)
        setTimeout(() => setCopiedIcon(null), 2000)
    }

    const insertIntoInstruction = (icon: IconEntry) => {
        const mention = icon.is_custom
            ? `Use custom icon "${icon.label}" (${icon.name})`
            : `Use ${icon.name} from ${icon.provider}`
        setInstruction(prev => prev ? `${prev}. ${mention}` : mention)
        setIconBrowserOpen(false)
    }

    const providerColors: Record<string, string> = {
        aws: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
        azure: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
        gcp: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
        saas: "bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300",
        onprem: "bg-gray-100 text-gray-800 dark:bg-gray-950 dark:text-gray-300",
        custom: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300",
    }

    return (
        <div className="space-y-4">
            <Card className="border-violet-200 dark:border-violet-800">
                <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                        <CardTitle className="text-base flex items-center gap-2">
                            <Wand2 className="h-4 w-4 text-violet-500" />
                            Diagram Editor Agent
                        </CardTitle>
                        <div className="flex items-center gap-2">
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => {
                                    setIconBrowserOpen(true)
                                    if (iconResults.length === 0) searchIcons("")
                                }}
                            >
                                <Palette className="h-3.5 w-3.5 mr-1.5" />
                                Browse Icons
                            </Button>
                            <Button variant="ghost" size="icon" onClick={onClose} className="h-7 w-7">
                                <X className="h-4 w-4" />
                            </Button>
                        </div>
                    </div>
                </CardHeader>
                <CardContent className="space-y-3">
                    <div className="flex gap-2">
                        <Input
                            value={instruction}
                            onChange={e => setInstruction(e.target.value)}
                            onKeyDown={e => e.key === "Enter" && !loading && submitEdit()}
                            placeholder='e.g., "Replace blank Sumo Logic icon with the custom brand icon"'
                            disabled={loading}
                            className="flex-1"
                        />
                        <Button onClick={submitEdit} disabled={loading || !instruction.trim()} size="sm">
                            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                        </Button>
                    </div>

                    {/* Suggested edits */}
                    <div className="flex flex-wrap gap-1.5">
                        {[
                            "Replace blank icons with custom brand icons",
                            "Add WAF node before the load balancer",
                            "Add Sumo Logic for log aggregation",
                        ].map(suggestion => (
                            <Badge
                                key={suggestion}
                                variant="outline"
                                className="cursor-pointer hover:bg-violet-50 dark:hover:bg-violet-950 text-xs"
                                onClick={() => setInstruction(suggestion)}
                            >
                                {suggestion}
                            </Badge>
                        ))}
                    </div>

                    {/* Preview result */}
                    {previewCode && (
                        <div className="space-y-3 border-t pt-3">
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-sm font-medium text-green-600 dark:text-green-400">
                                        Preview Ready
                                    </p>
                                    {changesSummary && (
                                        <p className="text-xs text-muted-foreground">{changesSummary}</p>
                                    )}
                                </div>
                                <div className="flex gap-2">
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => {
                                            setPreviewCode(null)
                                            setPreviewImage(null)
                                        }}
                                    >
                                        <X className="h-3.5 w-3.5 mr-1" />
                                        Discard
                                    </Button>
                                    <Button
                                        size="sm"
                                        onClick={() => onApply(previewCode, previewImage)}
                                        className="bg-green-600 hover:bg-green-700"
                                    >
                                        <Check className="h-3.5 w-3.5 mr-1" />
                                        Accept
                                    </Button>
                                </div>
                            </div>

                            {previewImage && (
                                <div className="bg-white rounded-md p-2 border">
                                    <img
                                        src={`data:image/png;base64,${previewImage}`}
                                        alt="Preview"
                                        className="max-w-full h-auto max-h-64 mx-auto"
                                    />
                                </div>
                            )}

                            {!previewImage && (
                                <p className="text-xs text-amber-600 dark:text-amber-400">
                                    Image generation failed — code changes are still valid. Accept and use &quot;Create Diagram&quot; to render.
                                </p>
                            )}

                            {fixLog.length > 0 && (
                                <details className="text-xs text-muted-foreground">
                                    <summary className="cursor-pointer">Self-annealing log ({fixLog.length} entries)</summary>
                                    <ul className="mt-1 space-y-0.5 font-mono">
                                        {fixLog.map((entry, i) => (
                                            <li key={i}>{entry}</li>
                                        ))}
                                    </ul>
                                </details>
                            )}
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Icon Browser Sheet */}
            <Sheet open={iconBrowserOpen} onOpenChange={setIconBrowserOpen}>
                <SheetContent className="w-[500px] sm:max-w-[500px]">
                    <SheetHeader>
                        <SheetTitle>Icon Catalog</SheetTitle>
                        <SheetDescription>
                            {Object.values(iconProviders).reduce((a, b) => a + b, 0)} icons across{" "}
                            {Object.keys(iconProviders).length} providers
                        </SheetDescription>
                    </SheetHeader>

                    <div className="mt-4 space-y-4">
                        <div className="flex gap-2">
                            <div className="relative flex-1">
                                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                                <Input
                                    value={iconSearch}
                                    onChange={e => setIconSearch(e.target.value)}
                                    onKeyDown={e => e.key === "Enter" && searchIcons(iconSearch)}
                                    placeholder="Search icons (e.g., monitor, waf, database)"
                                    className="pl-9"
                                />
                            </div>
                            <Button
                                size="sm"
                                onClick={() => searchIcons(iconSearch)}
                                disabled={iconLoading}
                            >
                                {iconLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Search"}
                            </Button>
                        </div>

                        {/* Provider chips */}
                        <div className="flex flex-wrap gap-1.5">
                            {Object.entries(iconProviders).sort().map(([prov, count]) => (
                                <Badge
                                    key={prov}
                                    variant="outline"
                                    className={`cursor-pointer text-xs ${providerColors[prov] || ""}`}
                                    onClick={() => {
                                        setIconSearch(prov)
                                        searchIcons(prov)
                                    }}
                                >
                                    {prov} ({count})
                                </Badge>
                            ))}
                        </div>

                        <ScrollArea className="h-[calc(100vh-280px)]">
                            <div className="space-y-1.5 pr-4">
                                {iconResults.map(icon => (
                                    <div
                                        key={icon.import_path}
                                        className="flex items-center justify-between p-2 rounded-md border hover:bg-accent/50 text-sm"
                                    >
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-2">
                                                <span className="font-medium truncate">{icon.name}</span>
                                                <Badge
                                                    variant="outline"
                                                    className={`text-[10px] px-1 py-0 ${providerColors[icon.provider] || ""}`}
                                                >
                                                    {icon.provider}
                                                </Badge>
                                                {icon.is_custom && (
                                                    <Badge variant="outline" className="text-[10px] px-1 py-0 bg-green-50 text-green-700 border-green-300">
                                                        brand
                                                    </Badge>
                                                )}
                                            </div>
                                            <p className="text-xs text-muted-foreground font-mono truncate mt-0.5">
                                                {icon.usage}
                                            </p>
                                        </div>
                                        <div className="flex gap-1 ml-2 shrink-0">
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                className="h-7 w-7"
                                                onClick={() => copyUsage(icon)}
                                                title="Copy import"
                                            >
                                                {copiedIcon === icon.name ? (
                                                    <Check className="h-3.5 w-3.5 text-green-500" />
                                                ) : (
                                                    <Copy className="h-3.5 w-3.5" />
                                                )}
                                            </Button>
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                className="h-7 w-7"
                                                onClick={() => insertIntoInstruction(icon)}
                                                title="Use in instruction"
                                            >
                                                <Send className="h-3.5 w-3.5" />
                                            </Button>
                                        </div>
                                    </div>
                                ))}
                                {iconResults.length === 0 && !iconLoading && (
                                    <p className="text-center text-sm text-muted-foreground py-8">
                                        Type a search term and press Enter
                                    </p>
                                )}
                            </div>
                        </ScrollArea>
                    </div>
                </SheetContent>
            </Sheet>
        </div>
    )
}
