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
import { Loader2, Sparkles, Save, Check } from "lucide-react"

interface AiTriageDialogProps {
    finding: any
    onDescriptionUpdated?: () => void
}

export function AiTriageDialog({ finding, onDescriptionUpdated }: AiTriageDialogProps) {
    const [loading, setLoading] = useState(false)
    const [analysis, setAnalysis] = useState<any>(null)
    const [open, setOpen] = useState(false)
    const [saving, setSaving] = useState(false)
    const [saved, setSaved] = useState(false)

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

    const updateDescriptionWithAI = async () => {
        if (!analysis?.reasoning) return
        
        setSaving(true)
        try {
            // Build the updated description with AI analysis
            const aiDescription = `**AI Analysis (${new Date().toLocaleDateString()})**

**Priority:** ${analysis.priority}
**Confidence:** ${(analysis.confidence * 100).toFixed(0)}%
**False Positive Risk:** ${(analysis.false_positive_probability * 100).toFixed(0)}%

**Reasoning:**
${analysis.reasoning}

---
*Original Description:*
${finding.description || 'No original description provided.'}`

            const res = await fetch(`http://localhost:8000/findings/${finding.id}`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    description: aiDescription
                })
            })
            
            if (res.ok) {
                setSaved(true)
                // Notify parent component to refresh data if callback provided
                if (onDescriptionUpdated) {
                    onDescriptionUpdated()
                }
            } else {
                console.error("Failed to update description:", await res.text())
            }
        } catch (error) {
            console.error("Failed to save description:", error)
        } finally {
            setSaving(false)
        }
    }

    return (
        <Dialog open={open} onOpenChange={(isOpen) => {
            setOpen(isOpen)
            // Reset saved state when dialog closes
            if (!isOpen) {
                setSaved(false)
            }
        }}>
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
            <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
                <DialogHeader>
                    <DialogTitle>AI Security Analysis</DialogTitle>
                    <DialogDescription>
                        Analyzing finding: {finding.title}
                    </DialogDescription>
                </DialogHeader>

                <div className="flex-1 overflow-y-auto">
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

                            {/* Update Description Section */}
                            <div className="border-t pt-4 mt-4">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <h4 className="text-sm font-medium">Update Finding Description</h4>
                                        <p className="text-xs text-muted-foreground mt-1">
                                            Save this AI analysis as the finding&apos;s description for review.
                                        </p>
                                    </div>
                                    {saved ? (
                                        <Button variant="outline" size="sm" disabled className="gap-2">
                                            <Check className="h-4 w-4 text-green-500" />
                                            Description Updated
                                        </Button>
                                    ) : (
                                        <Button
                                            variant="default"
                                            size="sm"
                                            className="gap-2"
                                            onClick={updateDescriptionWithAI}
                                            disabled={saving}
                                        >
                                            {saving ? (
                                                <>
                                                    <Loader2 className="h-4 w-4 animate-spin" />
                                                    Saving...
                                                </>
                                            ) : (
                                                <>
                                                    <Save className="h-4 w-4" />
                                                    Update Description with AI Results
                                                </>
                                            )}
                                        </Button>
                                    )}
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="py-4 text-center text-sm text-red-500">
                            Failed to generate analysis.
                        </div>
                    )}
                </div>
            </DialogContent>
        </Dialog>
    )
}
