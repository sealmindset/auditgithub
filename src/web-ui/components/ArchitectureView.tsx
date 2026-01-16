"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Loader2, RefreshCw, Save, Edit, X, ImagePlus, FileEdit, Wand2, History } from "lucide-react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import { Textarea } from "@/components/ui/textarea"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/components/ui/use-toast"
import { PromptEditorDialog } from "@/components/PromptEditorDialog"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"

interface ArchitectureViewProps {
    projectId: string
}

export function ArchitectureView({ projectId }: ArchitectureViewProps) {
    const [report, setReport] = useState<string>("")
    const [diagramCode, setDiagramCode] = useState<string | null>(null)
    const [diagramImage, setDiagramImage] = useState<string | null>(null)
    const [loading, setLoading] = useState(false)
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [editMode, setEditMode] = useState(false)
    const [promptEditorOpen, setPromptEditorOpen] = useState(false)
    const { toast } = useToast()

    const [providerName, setProviderName] = useState<string>("")

    // Fetch AI config on mount
    useEffect(() => {
        const fetchConfig = async () => {
            try {
                const res = await fetch("http://localhost:8000/ai/config")
                if (res.ok) {
                    const data = await res.json()
                    // Format provider name nicely (e.g. "anthropic_foundry" -> "Anthropic Foundry")
                    const name = data.provider.split('_').map((word: string) =>
                        word.charAt(0).toUpperCase() + word.slice(1)
                    ).join(' ')
                    setProviderName(name)
                }
            } catch (e) {
                console.error("Failed to fetch AI config", e)
            }
        }
        fetchConfig()
    }, [])

    // Fetch saved architecture on mount
    useEffect(() => {
        const fetchArchitecture = async () => {
            try {
                const res = await fetch(`http://localhost:8000/ai/architecture/${projectId}`)
                if (res.ok) {
                    const data = await res.json()
                    if (data.report) setReport(data.report)
                    if (data.diagram) setDiagramCode(data.diagram)
                    if (data.image) setDiagramImage(data.image)
                }
            } catch (e) {
                console.error("Failed to fetch architecture", e)
            }
        }
        fetchArchitecture()
    }, [projectId])

    const generateArchitecture = async () => {
        setLoading(true)
        setError(null)

        try {
            const res = await fetch(`http://localhost:8000/ai/architecture`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ project_id: projectId })
            })

            if (!res.ok) {
                const err = await res.json()
                throw new Error(err.detail || "Failed to generate architecture")
            }

            const data = await res.json()
            setReport(data.report)
            setDiagramCode(data.diagram)
            setDiagramImage(data.image)
            toast({ title: "Architecture Generated", description: "New report and diagram generated successfully." })

        } catch (err) {
            setError(err instanceof Error ? err.message : "An unknown error occurred")
        } finally {
            setLoading(false)
        }
    }

    const saveChanges = async () => {
        setSaving(true)
        try {
            const res = await fetch(`http://localhost:8000/ai/architecture/${projectId}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    report: report,
                    diagram: diagramCode
                })
            })

            if (!res.ok) throw new Error("Failed to save changes")

            const data = await res.json()
            setDiagramImage(data.image)

            toast({ title: "Saved", description: "Architecture changes saved successfully." })
            setEditMode(false)
        } catch (err) {
            toast({ title: "Error", description: "Failed to save changes", variant: "destructive" })
        } finally {
            setSaving(false)
        }
    }

    const [versions, setVersions] = useState<any[]>([])
    const [versionDialogOpen, setVersionDialogOpen] = useState(false)
    const [newVersionDesc, setNewVersionDesc] = useState("")

    // Fetch versions
    const fetchVersions = async () => {
        try {
            const res = await fetch(`http://localhost:8000/ai/architecture/${projectId}/versions`)
            if (res.ok) {
                setVersions(await res.json())
            }
        } catch (e) {
            console.error("Failed to fetch versions", e)
        }
    }

    useEffect(() => {
        fetchVersions()
    }, [projectId])

    const saveVersion = async () => {
        try {
            const res = await fetch(`http://localhost:8000/ai/architecture/${projectId}/versions`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ description: newVersionDesc })
            })

            if (!res.ok) throw new Error("Failed to save version")

            toast({ title: "Version Saved", description: "Architecture version saved successfully." })
            setVersionDialogOpen(false)
            setNewVersionDesc("")
            fetchVersions()
        } catch (e) {
            toast({ title: "Error", description: "Failed to save version", variant: "destructive" })
        }
    }

    const restoreVersion = async (versionId: string) => {
        if (!confirm("Are you sure? This will overwrite current changes.")) return

        try {
            const res = await fetch(`http://localhost:8000/ai/architecture/${projectId}/restore/${versionId}`, {
                method: "POST"
            })

            if (!res.ok) throw new Error("Failed to restore version")

            toast({ title: "Restored", description: "Architecture restored to previous version." })
            // Refresh current view
            const archRes = await fetch(`http://localhost:8000/ai/architecture/${projectId}`)
            if (archRes.ok) {
                const data = await archRes.json()
                setReport(data.report)
                setDiagramCode(data.diagram)
                setDiagramImage(data.image)
            }
        } catch (e) {
            toast({ title: "Error", description: "Failed to restore version", variant: "destructive" })
        }
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight">System Architecture</h2>
                    <p className="text-muted-foreground">
                        AI-generated architecture overview and Python Diagrams visualization.
                    </p>
                </div>
                <div className="flex gap-2">
                    <Dialog open={versionDialogOpen} onOpenChange={setVersionDialogOpen}>
                        <DialogTrigger asChild>
                            <Button variant="outline">
                                <History className="mr-2 h-4 w-4" /> History
                            </Button>
                        </DialogTrigger>
                        <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
                            <DialogHeader>
                                <DialogTitle>Version History</DialogTitle>
                                <DialogDescription>
                                    Save current state or restore previous versions.
                                </DialogDescription>
                            </DialogHeader>
                            <div className="flex-1 overflow-y-auto grid gap-4 py-4">
                                <div className="flex gap-2">
                                    <Input
                                        placeholder="Version description..."
                                        value={newVersionDesc}
                                        onChange={(e) => setNewVersionDesc(e.target.value)}
                                    />
                                    <Button onClick={saveVersion}>Save New</Button>
                                </div>
                                <div className="space-y-2">
                                    {versions.map((v) => (
                                        <div key={v.id} className="flex items-center justify-between p-2 border rounded hover:bg-slate-50 dark:hover:bg-slate-900">
                                            <div>
                                                <div className="font-medium">v{v.version_number}</div>
                                                <div className="text-xs text-muted-foreground">{new Date(v.created_at).toLocaleString()}</div>
                                                {v.description && <div className="text-sm">{v.description}</div>}
                                            </div>
                                            <Button variant="ghost" size="sm" onClick={() => restoreVersion(v.id)}>
                                                Restore
                                            </Button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </DialogContent>
                    </Dialog>

                    <Button
                        variant="outline"
                        size="icon"
                        onClick={() => setPromptEditorOpen(true)}
                        title="Prompt Edit"
                    >
                        <FileEdit className="h-4 w-4" />
                    </Button>
                    {editMode ? (
                        <>
                            <Button variant="outline" onClick={() => setEditMode(false)}>
                                <X className="mr-2 h-4 w-4" /> Cancel
                            </Button>
                            <Button onClick={saveChanges} disabled={saving}>
                                <Save className="mr-2 h-4 w-4" /> {saving ? "Saving..." : "Save Changes"}
                            </Button>
                        </>
                    ) : (
                        <>
                            <Button variant="outline" onClick={() => setEditMode(true)} disabled={!report && !diagramCode}>
                                <Edit className="mr-2 h-4 w-4" /> Edit
                            </Button>
                            <Button onClick={generateArchitecture} disabled={loading}>
                                {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                                {report ? "Regenerate" : "Generate Architecture"}
                            </Button>
                        </>
                    )}
                </div>
            </div>

            {error && (
                <div className="rounded-md bg-red-50 p-4 text-sm text-red-500">
                    {error}
                </div>
            )}

            <Tabs defaultValue="diagram" className="w-full">
                <div className="flex items-center justify-between mb-4">
                    <TabsList>
                        <TabsTrigger value="diagram">Diagram</TabsTrigger>
                        <TabsTrigger value="code">Python Code</TabsTrigger>
                        <TabsTrigger value="report">Report</TabsTrigger>
                    </TabsList>
                    <div className="flex gap-2">
                        {diagramCode && (
                            <>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={async () => {
                                        setLoading(true)
                                        try {
                                            const res = await fetch(`http://localhost:8000/ai/architecture/refine`, {
                                                method: "POST",
                                                headers: { "Content-Type": "application/json" },
                                                body: JSON.stringify({ project_id: projectId, code: diagramCode })
                                            })
                                            if (!res.ok) throw new Error("Failed to refine diagram")
                                            const data = await res.json()
                                            setDiagramCode(data.code)
                                            toast({ title: "Diagram Refined", description: "Icons updated based on detected cloud provider." })
                                        } catch (e) {
                                            toast({ title: "Error", description: "Failed to refine diagram", variant: "destructive" })
                                        } finally {
                                            setLoading(false)
                                        }
                                    }}
                                    disabled={loading || saving}
                                    title="Refine Icons"
                                >
                                    <Wand2 className="mr-2 h-4 w-4" />
                                    Refine Icons
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={saveChanges}
                                    disabled={saving}
                                    title="Create Diagram"
                                >
                                    <ImagePlus className="mr-2 h-4 w-4" />
                                    Create Diagram
                                </Button>
                            </>
                        )}
                    </div>
                </div>

                <TabsContent value="diagram" className="mt-0">
                    <Card>
                        <CardHeader>
                            <CardTitle>Architecture Diagram</CardTitle>
                            <CardDescription>Generated from Python code</CardDescription>
                        </CardHeader>
                        <CardContent className="flex justify-center bg-white p-4 rounded-md">
                            {diagramImage ? (
                                <img
                                    src={`data:image/png;base64,${diagramImage}`}
                                    alt="Architecture Diagram"
                                    className="max-w-full h-auto"
                                />
                            ) : (
                                <div className="text-muted-foreground italic p-8 text-center">
                                    {diagramCode ? (
                                        <div className="space-y-2">
                                            <p className="text-red-500 font-semibold">Diagram generation failed.</p>
                                            <p>Check the Python Code tab for errors (e.g., incorrect imports).</p>
                                            <p className="text-xs text-slate-500">Common fix: Change <code>from diagrams.generic.network import Internet</code> to <code>from diagrams.onprem.network import Internet</code></p>
                                        </div>
                                    ) : (
                                        "No diagram generated yet."
                                    )}
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="code" className="mt-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Diagram Source Code</CardTitle>
                            <CardDescription>Python code using the `diagrams` library</CardDescription>
                        </CardHeader>
                        <CardContent>
                            {editMode ? (
                                <Textarea
                                    value={diagramCode || ""}
                                    onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setDiagramCode(e.target.value)}
                                    className="min-h-[400px] font-mono text-sm"
                                    placeholder="from diagrams import Diagram..."
                                />
                            ) : (
                                <pre className="bg-slate-950 text-slate-50 p-4 rounded-md overflow-x-auto text-sm">
                                    <code>{diagramCode}</code>
                                </pre>
                            )}
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="report" className="mt-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Architecture Report</CardTitle>
                            <CardDescription>Technical overview generated by AI</CardDescription>
                        </CardHeader>
                        <CardContent>
                            {editMode ? (
                                <Textarea
                                    value={report}
                                    onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setReport(e.target.value)}
                                    className="min-h-[600px] font-mono"
                                />
                            ) : (
                                <div className="prose prose-slate dark:prose-invert max-w-none prose-headings:font-semibold prose-a:text-blue-600 hover:prose-a:underline prose-pre:bg-slate-900 prose-pre:text-slate-50">
                                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                        {report}
                                    </ReactMarkdown>
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </TabsContent>
            </Tabs>

            {!report && !diagramCode && !loading && !error && (
                <div className="flex h-64 items-center justify-center rounded-md border border-dashed">
                    <div className="text-center">
                        <p className="text-muted-foreground">No architecture report generated yet.</p>
                        <Button variant="link" onClick={generateArchitecture}>
                            Generate now
                        </Button>
                    </div>
                </div>
            )}

            {loading && (
                <div className="flex h-64 items-center justify-center">
                    <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                    <span className="ml-2 text-muted-foreground">{providerName || "AI"}: Analyzing repository structure...</span>
                </div>
            )}

            <PromptEditorDialog
                projectId={projectId}
                isOpen={promptEditorOpen}
                onOpenChange={setPromptEditorOpen}
            />
        </div>
    )
}

