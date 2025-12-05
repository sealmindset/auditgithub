"use client"

import { useEffect, useState } from "react"
import { useParams, useRouter } from "next/navigation"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { AiRemediationCard } from "@/components/ai-remediation-card"
import { Loader2, ArrowLeft } from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"

const API_BASE = "http://localhost:8000"

export default function FindingDetailsPage() {
    const params = useParams()
    const router = useRouter()
    const id = params.id as string
    const [finding, setFinding] = useState<any>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        const fetchFinding = async () => {
            try {
                const res = await fetch(`${API_BASE}/findings/${id}`)
                if (!res.ok) throw new Error("Finding not found")
                const data = await res.json()
                setFinding(data)
            } catch (err) {
                setError("Failed to load finding details")
            } finally {
                setLoading(false)
            }
        }

        if (id) fetchFinding()
    }, [id])

    if (loading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    if (error || !finding) {
        return (
            <div className="flex h-screen flex-col items-center justify-center gap-4">
                <p className="text-red-500">{error || "Finding not found"}</p>
                <Button variant="outline" onClick={() => router.back()}>Go Back</Button>
            </div>
        )
    }

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => router.back()}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-2xl font-bold tracking-tight">{finding.title}</h1>
                    <div className="flex items-center gap-2 text-muted-foreground">
                        <span>{finding.repo_name}</span>
                        <span>•</span>
                        <span>{finding.id.substring(0, 8)}</span>
                    </div>
                </div>
                <Badge
                    className={`ml-auto ${finding.severity === "Critical" ? "bg-red-500" :
                        finding.severity === "High" ? "bg-orange-500" : "bg-blue-500"
                        }`}
                >
                    {finding.severity}
                </Badge>
            </div>

            <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-6">
                    <Card>
                        <CardHeader>
                            <CardTitle>Details</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div>
                                <h3 className="font-semibold">Description</h3>
                                <p className="text-sm text-muted-foreground">{finding.description}</p>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <h3 className="font-semibold">Scanner</h3>
                                    <p className="text-sm">{finding.scanner_name}</p>
                                </div>
                                <div>
                                    <h3 className="font-semibold">Status</h3>
                                    <p className="text-sm capitalize">{finding.status}</p>
                                </div>
                            </div>
                            {finding.file_path && (
                                <div>
                                    <h3 className="font-semibold">Location</h3>
                                    <p className="text-sm font-mono bg-muted p-2 rounded">
                                        {finding.file_path}:{finding.line_start}
                                    </p>
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {finding.code_snippet && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Code Context</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <pre className="overflow-x-auto rounded-md bg-slate-950 p-4 text-xs text-slate-50">
                                    <code>{finding.code_snippet}</code>
                                </pre>
                            </CardContent>
                        </Card>
                    )}
                </div>

                <div className="space-y-6">
                    <AiRemediationCard
                        findingId={finding.id}
                        vulnType={finding.title}
                        description={finding.description || ""}
                        context={finding.code_snippet || ""}
                        language="python" // TODO: Detect language dynamically
                        existingRemediations={finding.remediations}
                    />
                </div>
            </div>
        </div>
    )
}
