"use client"

import { useEffect, useState } from "react"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Loader2, Download, Copy, Check, FileCode2 } from "lucide-react"

interface OpenAPISpec {
    spec_content: string
    spec_format: string
    version: string
    endpoint_count: number
    generated_at: string
}

interface OpenAPIModalProps {
    projectId: string
    open: boolean
    onOpenChange: (open: boolean) => void
}

const API_BASE = "http://localhost:8000"

export function OpenAPIModal({ projectId, open, onOpenChange }: OpenAPIModalProps) {
    const [spec, setSpec] = useState<OpenAPISpec | null>(null)
    const [loading, setLoading] = useState(false)
    const [copied, setCopied] = useState(false)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        if (open && !spec) {
            loadSpec()
        }
    }, [open, projectId])

    const loadSpec = async () => {
        setLoading(true)
        setError(null)

        try {
            const res = await fetch(`${API_BASE}/projects/${projectId}/api-audit/openapi/view`)
            if (res.ok) {
                setSpec(await res.json())
            } else if (res.status === 404) {
                setError("OpenAPI specification not found. Run an API audit scan first.")
            } else {
                setError("Failed to load OpenAPI specification.")
            }
        } catch (err) {
            console.error("Failed to load OpenAPI spec:", err)
            setError("Failed to connect to API server.")
        } finally {
            setLoading(false)
        }
    }

    const handleCopy = async () => {
        if (spec?.spec_content) {
            await navigator.clipboard.writeText(spec.spec_content)
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
        }
    }

    const handleDownload = () => {
        window.open(`${API_BASE}/projects/${projectId}/api-audit/openapi?format=yaml`, '_blank')
    }

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="max-w-4xl max-h-[90vh]">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <FileCode2 className="h-5 w-5" />
                        OpenAPI Specification
                    </DialogTitle>
                    <DialogDescription>
                        Auto-generated OpenAPI v3 specification from source code analysis.
                    </DialogDescription>
                </DialogHeader>

                {loading && (
                    <div className="flex items-center justify-center py-12">
                        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                    </div>
                )}

                {error && (
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                        <p className="text-muted-foreground">{error}</p>
                    </div>
                )}

                {spec && !loading && (
                    <>
                        {/* Metadata bar */}
                        <div className="flex items-center justify-between py-2 border-b">
                            <div className="flex items-center gap-3">
                                <Badge variant="outline">
                                    OpenAPI {spec.version}
                                </Badge>
                                <Badge variant="secondary">
                                    {spec.endpoint_count} endpoints
                                </Badge>
                                <span className="text-xs text-muted-foreground">
                                    Generated: {new Date(spec.generated_at).toLocaleString()}
                                </span>
                            </div>
                            <div className="flex items-center gap-2">
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={handleCopy}
                                >
                                    {copied ? (
                                        <Check className="h-4 w-4 mr-1 text-green-500" />
                                    ) : (
                                        <Copy className="h-4 w-4 mr-1" />
                                    )}
                                    {copied ? "Copied!" : "Copy"}
                                </Button>
                                <Button
                                    variant="default"
                                    size="sm"
                                    onClick={handleDownload}
                                >
                                    <Download className="h-4 w-4 mr-1" />
                                    Download YAML
                                </Button>
                            </div>
                        </div>

                        {/* Spec content */}
                        <ScrollArea className="h-[500px] w-full rounded-md border">
                            <pre className="p-4 text-sm font-mono bg-muted/30">
                                <code className="language-yaml">
                                    {spec.spec_content}
                                </code>
                            </pre>
                        </ScrollArea>
                    </>
                )}
            </DialogContent>
        </Dialog>
    )
}
