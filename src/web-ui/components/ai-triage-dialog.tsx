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
import { Loader2, Sparkles } from "lucide-react"

interface AiTriageDialogProps {
    finding: any
}

export function AiTriageDialog({ finding }: AiTriageDialogProps) {
    const [loading, setLoading] = useState(false)
    const [analysis, setAnalysis] = useState<any>(null)
    const [open, setOpen] = useState(false)

    const analyzeFinding = async () => {
        setLoading(true)
        try {
            const res = await fetch("http://localhost:8000/ai/triage", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title: finding.title,
                    description: finding.description,
                    severity: finding.severity,
                    scanner: finding.scanner_name || "unknown",
                    finding_id: finding.id
                })
            })
            if (res.ok) {
                setAnalysis(await res.json())
            }
        } catch (error) {
            console.error("AI analysis failed:", error)
        } finally {
            setLoading(false)
        }
    }

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button
                    variant="outline"
                    size="sm"
                    className="gap-2"
                    onClick={() => {
                        setOpen(true)
                        if (!analysis) analyzeFinding()
                    }}
                >
                    <Sparkles className="h-3 w-3" />
                    Ask AI
                </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[500px]">
                <DialogHeader>
                    <DialogTitle>AI Security Analysis</DialogTitle>
                    <DialogDescription>
                        Analyzing finding: {finding.title}
                    </DialogDescription>
                </DialogHeader>

                {loading ? (
                    <div className="flex flex-col items-center justify-center py-8">
                        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
                        <p className="mt-2 text-sm text-muted-foreground">Analyzing with AI...</p>
                    </div>
                ) : analysis ? (
                    <div className="space-y-4">
                        <div className="flex items-center justify-between">
                            <span className="text-sm font-medium">Priority Score</span>
                            <Badge variant={analysis.priority === "High" ? "destructive" : "default"}>
                                {analysis.priority}
                            </Badge>
                        </div>

                        <div className="space-y-2">
                            <h4 className="text-sm font-medium">Reasoning</h4>
                            <p className="text-sm text-muted-foreground bg-muted p-3 rounded-md">
                                {analysis.reasoning}
                            </p>
                        </div>

                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <span>Confidence: {(analysis.confidence * 100).toFixed(0)}%</span>
                            <span>•</span>
                            <span>False Positive Risk: {(analysis.false_positive_probability * 100).toFixed(0)}%</span>
                        </div>
                    </div>
                ) : (
                    <div className="py-4 text-center text-sm text-red-500">
                        Failed to generate analysis.
                    </div>
                )}
            </DialogContent>
        </Dialog>
    )
}
