"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Loader2, RefreshCw, Save, Edit, X, ImagePlus } from "lucide-react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import { Textarea } from "@/components/ui/textarea"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/components/ui/use-toast"

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
    const { toast } = useToast()

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
                    {diagramCode && (
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
                    )}
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
                                <div className="prose dark:prose-invert max-w-none">
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
                    <span className="ml-2 text-muted-foreground">Analyzing repository structure...</span>
                </div>
            )}
        </div>
    )
}
