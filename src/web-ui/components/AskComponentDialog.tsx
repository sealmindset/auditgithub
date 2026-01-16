"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Loader2, Sparkles, ShieldAlert, ShieldCheck, AlertTriangle } from "lucide-react"
import ReactMarkdown from "react-markdown"

interface ComponentAnalysis {
    analysis_text: string
    vulnerability_summary: string
    severity: string
    exploitability: string
    fixed_version: string
    source: string
}

interface AskComponentDialogProps {
    packageName: string
    version: string
    packageManager: string
    existingAnalysis?: ComponentAnalysis | null
    onAnalysisComplete?: (analysis: ComponentAnalysis) => void
}

const API_BASE = "http://localhost:8000"

export function AskComponentDialog({
    packageName,
    version,
    packageManager,
    existingAnalysis,
    onAnalysisComplete
}: AskComponentDialogProps) {
    const [open, setOpen] = useState(false)
    const [loading, setLoading] = useState(false)
    const [analysis, setAnalysis] = useState<ComponentAnalysis | null>(existingAnalysis || null)
    const [error, setError] = useState<string | null>(null)

    const handleAnalyze = async () => {
        setLoading(true)
        setError(null)
        try {
            const res = await fetch(`${API_BASE}/ai/analyze-component`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    package_name: packageName,
                    version: version,
                    package_manager: packageManager
                })
            })

            if (!res.ok) throw new Error("Analysis failed")

            const data = await res.json()
            setAnalysis(data)
            if (onAnalysisComplete) {
                onAnalysisComplete(data)
            }
        } catch (err) {
            setError("Failed to generate analysis. Please try again.")
            console.error(err)
        } finally {
            setLoading(false)
        }
    }

    const getSeverityColor = (sev: string) => {
        switch (sev?.toLowerCase()) {
            case "critical": return "bg-red-500 hover:bg-red-600"
            case "high": return "bg-orange-500 hover:bg-orange-600"
            case "medium": return "bg-yellow-500 hover:bg-yellow-600"
            case "low": return "bg-blue-500 hover:bg-blue-600"
            case "safe": return "bg-green-500 hover:bg-green-600"
            default: return "bg-gray-500"
        }
    }

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button
                    variant={analysis ? "outline" : "ghost"}
                    size="sm"
                    className="gap-2"
                    onClick={() => !analysis && handleAnalyze()}
                >
                    <Sparkles className="h-3 w-3 text-purple-500" />
                    {analysis ? "View Analysis" : "Ask AI"}
                </Button>
            </DialogTrigger>
            <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <Sparkles className="h-5 w-5 text-purple-500" />
                        Security Analysis: {packageName} @ {version}
                    </DialogTitle>
                    <DialogDescription>
                        AI-powered security assessment and risk analysis.
                    </DialogDescription>
                </DialogHeader>

                <div className="flex-1 overflow-y-auto space-y-6 py-4">
                    {loading ? (
                        <div className="flex flex-col items-center justify-center py-8 space-y-4">
                            <Loader2 className="h-8 w-8 animate-spin text-purple-500" />
                            <p className="text-sm text-muted-foreground">Analyzing component security posture...</p>
                        </div>
                    ) : error ? (
                        <div className="p-4 text-red-500 bg-red-50 rounded-md flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4" />
                            {error}
                        </div>
                    ) : analysis ? (
                        <>
                            {/* Summary Cards */}
                            <div className="grid grid-cols-3 gap-4">
                                <div className="p-3 border rounded-lg bg-card">
                                    <div className="text-xs text-muted-foreground mb-1">Severity</div>
                                    <Badge className={getSeverityColor(analysis.severity)}>
                                        {analysis.severity}
                                    </Badge>
                                </div>
                                <div className="p-3 border rounded-lg bg-card">
                                    <div className="text-xs text-muted-foreground mb-1">Exploitability</div>
                                    <div className="font-medium flex items-center gap-2">
                                        {analysis.exploitability === "High" ? (
                                            <ShieldAlert className="h-4 w-4 text-red-500" />
                                        ) : (
                                            <ShieldCheck className="h-4 w-4 text-green-500" />
                                        )}
                                        {analysis.exploitability}
                                    </div>
                                </div>
                                <div className="p-3 border rounded-lg bg-card">
                                    <div className="text-xs text-muted-foreground mb-1">Fixed Version</div>
                                    <div className="font-mono text-sm font-medium">
                                        {analysis.fixed_version}
                                    </div>
                                </div>
                            </div>

                            {/* Vulnerability Summary */}
                            <div className="p-3 bg-muted/50 rounded-lg border">
                                <h4 className="text-sm font-medium mb-1">Vulnerability Summary</h4>
                                <p className="text-sm text-muted-foreground">{analysis.vulnerability_summary}</p>
                            </div>

                            {/* Full Analysis */}
                            <ScrollArea className="h-[300px] w-full rounded-md border p-4">
                                <div className="prose prose-sm dark:prose-invert max-w-none">
                                    <ReactMarkdown>{analysis.analysis_text}</ReactMarkdown>
                                </div>
                            </ScrollArea>

                            <div className="text-xs text-muted-foreground text-right">
                                Source: {analysis.source === 'cache' ? 'Cached Analysis' : 'Generated by AI'}
                            </div>
                        </>
                    ) : (
                        <div className="flex justify-center py-8">
                            <Button onClick={handleAnalyze} className="gap-2">
                                <Sparkles className="h-4 w-4" />
                                Start Analysis
                            </Button>
                        </div>
                    )}
                </div>
            </DialogContent>
        </Dialog>
    )
}
