"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Textarea } from "@/components/ui/textarea"
import { PlayCircle, Loader2 } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"

interface PromptEditorDialogProps {
    projectId: string
    isOpen: boolean
    onOpenChange: (open: boolean) => void
    promptEndpoint?: string  // Optional custom endpoint for fetching prompt
    validateEndpoint?: string  // Optional custom endpoint for validation
}

export function PromptEditorDialog({
    projectId,
    isOpen,
    onOpenChange,
    promptEndpoint = "/ai/architecture/prompt",
    validateEndpoint = "/ai/architecture/validate"
}: PromptEditorDialogProps) {
    const [prompt, setPrompt] = useState<string>("")
    const [response, setResponse] = useState<string>("")
    const [loadingPrompt, setLoadingPrompt] = useState(false)
    const [validating, setValidating] = useState(false)
    const { toast } = useToast()

    // Fetch prompt when dialog opens
    useEffect(() => {
        if (isOpen && !prompt) {
            fetchPrompt()
        }
    }, [isOpen, projectId])

    const fetchPrompt = async () => {
        setLoadingPrompt(true)
        try {
            const url = promptEndpoint.includes("{projectId}")
                ? `http://localhost:8000${promptEndpoint.replace("{projectId}", projectId)}`
                : `http://localhost:8000${promptEndpoint}`

            const res = await fetch(url, {
                method: promptEndpoint.includes("architecture/prompt") ? "POST" : "GET",
                headers: { "Content-Type": "application/json" },
                ...(promptEndpoint.includes("architecture/prompt") && {
                    body: JSON.stringify({ project_id: projectId })
                })
            })
            if (res.ok) {
                const data = await res.json()
                setPrompt(data.prompt)
            } else {
                toast({ title: "Error", description: "Failed to load prompt", variant: "destructive" })
            }
        } catch (e) {
            console.error(e)
            toast({ title: "Error", description: "Failed to load prompt", variant: "destructive" })
        } finally {
            setLoadingPrompt(false)
        }
    }

    const validatePrompt = async () => {
        setValidating(true)
        setResponse("")
        try {
            const url = `http://localhost:8000${validateEndpoint}`
            const res = await fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    project_id: projectId,
                    prompt: prompt,
                    test_query: "Find all repositories using React" // Default test query
                })
            })

            if (res.ok) {
                const data = await res.json()
                if (data.success !== undefined) {
                    // For zero-day endpoint which returns {success, response}
                    setResponse(data.response)
                    if (data.success) {
                        toast({ title: "Success", description: "Prompt executed successfully" })
                    } else {
                        toast({ title: "Warning", description: "Prompt validation had issues", variant: "destructive" })
                    }
                } else {
                    // For architecture endpoint which returns {response}
                    setResponse(data.response)
                    toast({ title: "Success", description: "Prompt executed successfully" })
                }
            } else {
                const err = await res.json()
                setResponse(`Error: ${err.detail || "Validation failed"}`)
                toast({ title: "Error", description: "Validation failed", variant: "destructive" })
            }
        } catch (e) {
            setResponse(`Error: ${e instanceof Error ? e.message : "Unknown error"}`)
            toast({ title: "Error", description: "Validation failed", variant: "destructive" })
        } finally {
            setValidating(false)
        }
    }

    return (
        <Dialog open={isOpen} onOpenChange={onOpenChange}>
            <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
                <DialogHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <DialogTitle>Prompt Editor</DialogTitle>
                    <div className="flex gap-2">
                        <Button
                            size="icon"
                            variant="outline"
                            onClick={validatePrompt}
                            disabled={validating || loadingPrompt}
                            title="Validate Prompt"
                        >
                            {validating ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
                        </Button>
                    </div>
                </DialogHeader>

                <div className="flex-1 grid grid-cols-2 gap-4 min-h-0">
                    <div className="flex flex-col gap-2 h-full">
                        <h3 className="text-sm font-medium text-muted-foreground">Prompt</h3>
                        {loadingPrompt ? (
                            <div className="flex items-center justify-center h-full border rounded-md">
                                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                            </div>
                        ) : (
                            <Textarea
                                value={prompt}
                                onChange={(e) => setPrompt(e.target.value)}
                                className="flex-1 font-mono text-sm resize-none overflow-y-auto"
                                placeholder="Enter your prompt here..."
                            />
                        )}
                    </div>

                    <div className="flex flex-col gap-2 h-full">
                        <h3 className="text-sm font-medium text-muted-foreground">Response</h3>
                        <div className="flex-1 border rounded-md p-4 overflow-y-auto bg-slate-50 dark:bg-slate-900">
                            {response ? (
                                <div className="prose dark:prose-invert max-w-none text-sm">
                                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                        {response}
                                    </ReactMarkdown>
                                </div>
                            ) : (
                                <div className="text-muted-foreground italic text-center mt-20">
                                    {validating ? "Executing prompt..." : "Response will appear here"}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    )
}
