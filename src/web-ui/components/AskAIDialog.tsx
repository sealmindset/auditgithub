"use client"

import { useState } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Sparkles, Send, Loader2 } from "lucide-react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"

interface AskAIDialogProps {
    findingId: string
    trigger?: React.ReactNode
}

export function AskAIDialog({ findingId, trigger }: AskAIDialogProps) {
    const [isOpen, setIsOpen] = useState(false)
    const [prompt, setPrompt] = useState("")
    const [isLoading, setIsLoading] = useState(false)
    const [analysis, setAnalysis] = useState<string | null>(null)

    const handleAnalyze = async () => {
        setIsLoading(true)
        try {
            const response = await fetch("http://localhost:8000/ai/analyze-finding", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ finding_id: findingId, prompt: prompt || undefined }),
            })

            if (!response.ok) {
                const errorData = await response.json().catch(() => null)
                throw new Error(errorData?.detail || "Analysis failed")
            }

            const data = await response.json()
            setAnalysis(data.analysis)
            setPrompt("") // Clear prompt after sending
        } catch (error) {
            console.error("Analysis failed", error)
            setAnalysis("Failed to generate analysis. Please try again.")
        } finally {
            setIsLoading(false)
        }
    }

    return (
        <Dialog open={isOpen} onOpenChange={setIsOpen}>
            <DialogTrigger asChild>
                {trigger || (
                    <Button variant="outline" size="sm" className="gap-2">
                        <Sparkles className="h-4 w-4 text-purple-500" />
                        Ask AI
                    </Button>
                )}
            </DialogTrigger>
            <DialogContent className="max-w-3xl max-h-[80vh] flex flex-col">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <Sparkles className="h-5 w-5 text-purple-500" />
                        AI Security Analysis
                    </DialogTitle>
                </DialogHeader>

                <div className="flex-1 overflow-y-auto min-h-[300px] p-4 border rounded-md bg-muted/50">
                    {isLoading && !analysis ? (
                        <div className="flex flex-col items-center justify-center h-full gap-4 text-muted-foreground">
                            <Loader2 className="h-8 w-8 animate-spin" />
                            <p>Analyzing finding...</p>
                        </div>
                    ) : analysis ? (
                        <div className="prose dark:prose-invert max-w-none">
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>{analysis}</ReactMarkdown>
                        </div>
                    ) : (
                        <div className="flex flex-col items-center justify-center h-full gap-4 text-muted-foreground">
                            <Sparkles className="h-12 w-12 opacity-20" />
                            <p>Ask AI to analyze this finding or suggest remediation.</p>
                            <Button onClick={handleAnalyze} disabled={isLoading}>
                                {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                                Start Analysis
                            </Button>
                        </div>
                    )}
                </div>

                <div className="flex gap-2 mt-4">
                    <Textarea
                        placeholder="Ask a follow-up question..."
                        value={prompt}
                        onChange={(e) => setPrompt(e.target.value)}
                        className="resize-none"
                        rows={2}
                        onKeyDown={(e) => {
                            if (e.key === "Enter" && !e.shiftKey) {
                                e.preventDefault()
                                handleAnalyze()
                            }
                        }}
                    />
                    <Button
                        onClick={handleAnalyze}
                        disabled={isLoading || (!prompt && !!analysis)}
                        className="h-auto"
                    >
                        {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                    </Button>
                </div>
            </DialogContent>
        </Dialog>
    )
}
