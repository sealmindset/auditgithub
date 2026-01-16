"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Loader2, Sparkles, CheckCircle2, AlertTriangle } from "lucide-react"

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
            const response = await fetch("http://localhost:8000/ai/remediate", {
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
            const response = await fetch(`http://localhost:8000/ai/remediate/${remediation.id}`, {
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
        <Card className="border-blue-200 bg-blue-50/50 dark:border-blue-900 dark:bg-blue-950/20">
            <CardHeader>
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Sparkles className="h-5 w-5 text-blue-500" />
                        <CardTitle className="text-lg text-blue-700 dark:text-blue-300">
                            AI Remediation
                        </CardTitle>
                    </div>
                    <Badge variant="outline" className="border-blue-200 bg-blue-100 text-blue-700 dark:border-blue-800 dark:bg-blue-900 dark:text-blue-300">
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
                        className="w-full bg-blue-600 hover:bg-blue-700"
                    >
                        <Sparkles className="mr-2 h-4 w-4" />
                        Generate Fix
                    </Button>
                )}

                {loading && (
                    <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
                        <p className="mt-2 text-sm">Processing...</p>
                    </div>
                )}

                {error && (
                    <div className="flex items-center gap-2 rounded-md bg-red-50 p-3 text-sm text-red-600 dark:bg-red-950/50 dark:text-red-400">
                        <AlertTriangle className="h-4 w-4" />
                        {error}
                    </div>
                )}

                {remediation && !loading && (
                    <div className="space-y-4">
                        <div className="rounded-md bg-white p-4 text-sm shadow-sm dark:bg-gray-900">
                            <h4 className="mb-2 font-semibold">Suggested Fix:</h4>
                            <div className="prose prose-sm dark:prose-invert max-w-none whitespace-pre-wrap">
                                {remediation.remediation}
                            </div>
                        </div>

                        {remediation.diff && (
                            <div className="rounded-md border bg-gray-50 p-4 dark:bg-gray-900">
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
                            <Button className="flex-1 bg-green-600 hover:bg-green-700">
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
