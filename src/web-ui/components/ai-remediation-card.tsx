"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Loader2, Sparkles, CheckCircle2, AlertTriangle } from "lucide-react"
import { API_BASE, apiFetch } from "@/lib/api"

interface Remediation {
    id?: string
    remediation: string
    diff: string
}

interface AiRemediationCardProps {
    findingId: string
    vulnType: string
    description: string
    context: string
    language: string
    existingRemediations?: any[]
}

export function AiRemediationCard({
    findingId,
    vulnType,
    description,
    context,
    language,
    existingRemediations = []
}: AiRemediationCardProps) {
    const [loading, setLoading] = useState(false)
    const [remediation, setRemediation] = useState<Remediation | null>(() => {
        if (existingRemediations && existingRemediations.length > 0) {
            // Use the most recent remediation
            const latest = existingRemediations[0]
            return {
                id: latest.id,
                remediation: latest.remediation_text,
                diff: latest.diff
            }
        }
        return null
    })
    const [error, setError] = useState<string | null>(null)

    const handleGenerate = async () => {
        setLoading(true)
        setError(null)
        try {
            const response = await apiFetch(`${API_BASE}/ai/remediate`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    vuln_type: vulnType,
                    description: description,
                    context: context,
                    language: language,
                    finding_id: findingId
                })
            })

            if (!response.ok) throw new Error("Failed to generate remediation")

            const data = await response.json()
            setRemediation({
                id: data.remediation_id,
                remediation: data.remediation,
                diff: data.diff
            })
        } catch (err) {
            setError("Failed to generate AI remediation. Please try again.")
        } finally {
            setLoading(false)
        }
    }

    const handleDiscard = async () => {
        if (!remediation?.id) {
            setRemediation(null)
            return
        }

        try {
            setLoading(true)
            const response = await apiFetch(`${API_BASE}/ai/remediate/${remediation.id}`, {
                method: "DELETE"
            })

            if (!response.ok) throw new Error("Failed to discard remediation")

            setRemediation(null)
        } catch (err) {
            setError("Failed to discard remediation")
        } finally {
            setLoading(false)
        }
    }

    return (
        <Card className="border-info-line bg-info-soft/50 dark:bg-info-soft/20">
            <CardHeader>
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Sparkles className="h-5 w-5 text-info-text" />
                        <CardTitle className="text-lg text-info-text">
                            AI Remediation
                        </CardTitle>
                    </div>
                    <Badge variant="outline" className="border-info-line bg-info-soft text-info-text">
                        Beta
                    </Badge>
                </div>
                <CardDescription>
                    Generate an AI-powered fix for this vulnerability.
                </CardDescription>
            </CardHeader>
            <CardContent>
                {!remediation && !loading && (
                    <Button
                        onClick={handleGenerate}
                        className="w-full bg-info hover:bg-info"
                    >
                        <Sparkles className="mr-2 h-4 w-4" />
                        Generate Fix
                    </Button>
                )}

                {loading && (
                    <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                        <Loader2 className="h-8 w-8 animate-spin text-info-text" />
                        <p className="mt-2 text-sm">Processing...</p>
                    </div>
                )}

                {error && (
                    <div className="flex items-center gap-2 rounded-md bg-danger-soft p-3 text-sm text-danger-text dark:bg-danger-soft/50">
                        <AlertTriangle className="h-4 w-4" />
                        {error}
                    </div>
                )}

                {remediation && !loading && (
                    <div className="space-y-4">
                        <div className="rounded-md bg-card p-4 text-sm shadow-sm">
                            <h4 className="mb-2 font-semibold">Suggested Fix:</h4>
                            <div className="prose prose-sm dark:prose-invert max-w-none whitespace-pre-wrap">
                                {remediation.remediation}
                            </div>
                        </div>

                        {remediation.diff && (
                            <div className="rounded-md border bg-muted p-4">
                                <h4 className="mb-2 text-xs font-semibold uppercase text-muted-foreground">Code Changes</h4>
                                <pre className="overflow-x-auto text-xs">
                                    <code>{remediation.diff}</code>
                                </pre>
                            </div>
                        )}

                        <div className="flex gap-2">
                            <Button className="flex-1" variant="outline" onClick={handleDiscard}>
                                Discard
                            </Button>
                            <Button className="flex-1 bg-success hover:bg-success">
                                <CheckCircle2 className="mr-2 h-4 w-4" />
                                Apply Fix
                            </Button>
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    )
}
