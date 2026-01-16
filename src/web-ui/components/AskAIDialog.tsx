"use client"

import { useState, useRef, useEffect } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Sparkles, Send, Loader2, Save, Check, MessageSquare, User, Bot, History, RotateCcw, Lightbulb } from "lucide-react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"

interface ConversationMessage {
    role: 'user' | 'assistant'
    content: string
    timestamp: Date
}

interface DescriptionVersion {
    id: string
    description: string
    created_at: string
    is_current: boolean
}

interface AskAIDialogProps {
    findingId: string
    trigger?: React.ReactNode
    onDescriptionUpdated?: () => void
}

export function AskAIDialog({ findingId, trigger, onDescriptionUpdated }: AskAIDialogProps) {
    const [isOpen, setIsOpen] = useState(false)
    const [prompt, setPrompt] = useState("")
    const [isLoading, setIsLoading] = useState(false)
    const [analysis, setAnalysis] = useState<string | null>(null)
    const [conversation, setConversation] = useState<ConversationMessage[]>([])
    const [saving, setSaving] = useState(false)
    const [saved, setSaved] = useState(false)
    const [versions, setVersions] = useState<DescriptionVersion[]>([])
    const [loadingVersions, setLoadingVersions] = useState(false)
    const [restoringVersion, setRestoringVersion] = useState<string | null>(null)
    const [historyOpen, setHistoryOpen] = useState(false)
    const scrollRef = useRef<HTMLDivElement>(null)
    const hasStartedAnalysis = useRef(false)

    // Auto-scroll to bottom when new messages are added
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight
        }
    }, [conversation, isLoading])

    // Fetch version history
    const fetchVersionHistory = async () => {
        setLoadingVersions(true)
        try {
            const res = await fetch(`http://localhost:8000/findings/${findingId}/description-versions`)
            if (res.ok) {
                const data = await res.json()
                setVersions(data.versions || [])
            }
        } catch (error) {
            console.error("Failed to fetch version history:", error)
        } finally {
            setLoadingVersions(false)
        }
    }

    // Restore a previous version
    const restoreVersion = async (versionId: string) => {
        setRestoringVersion(versionId)
        try {
            const res = await fetch(`http://localhost:8000/findings/${findingId}/restore-description`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ version_id: versionId })
            })
            
            if (res.ok) {
                // Refresh the finding data
                if (onDescriptionUpdated) {
                    onDescriptionUpdated()
                }
                // Refresh version history
                await fetchVersionHistory()
                setHistoryOpen(false)
                
                // Add notification to conversation
                setConversation(prev => [...prev, {
                    role: 'assistant',
                    content: `✅ **Description Restored**\n\nThe description has been restored to a previous version from the history.`,
                    timestamp: new Date()
                }])
            } else {
                console.error("Failed to restore version:", await res.text())
            }
        } catch (error) {
            console.error("Failed to restore version:", error)
        } finally {
            setRestoringVersion(null)
        }
    }

    // Detect if user prompt is requesting a description revision
    const isDescriptionRevisionRequest = (text: string): boolean => {
        const lowerText = text.toLowerCase()
        const revisionKeywords = [
            'revise the description',
            'update the description',
            'change the description',
            'modify the description',
            'edit the description',
            'rewrite the description',
            'improve the description',
            'enhance the description',
            'add to the description',
            'include in the description',
            'make the description',
            'description should',
            'description to include',
            'description to provide',
            'description to explain',
            'description to mention',
            'update description',
            'revise description',
            'save this as the description',
            'use this as the description',
            'set the description to',
            'replace the description'
        ]
        return revisionKeywords.some(keyword => lowerText.includes(keyword))
    }

    // Save revised description to database
    const saveRevisedDescription = async (newAnalysis: string) => {
        try {
            const timestamp = new Date().toLocaleString('en-US', { 
                dateStyle: 'medium', 
                timeStyle: 'short' 
            })
            
            const aiDescription = `**AI Security Analysis**

> *Generated on ${timestamp}*

---

${newAnalysis}

---

*This description was enhanced by AI analysis. Review and validate findings before taking action.*`

            const res = await fetch(`http://localhost:8000/findings/${findingId}`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    description: aiDescription
                })
            })
            
            if (res.ok) {
                setSaved(true)
                if (onDescriptionUpdated) {
                    onDescriptionUpdated()
                }
                return true
            }
            return false
        } catch (error) {
            console.error("Failed to save revised description:", error)
            return false
        }
    }

    const handleAnalyze = async () => {
        const isInitialAnalysis = !analysis
        const currentPrompt = prompt.trim()
        const isRevisionRequest = !isInitialAnalysis && isDescriptionRevisionRequest(currentPrompt)
        
        // Add user message to conversation if it's a follow-up
        if (!isInitialAnalysis && currentPrompt) {
            setConversation(prev => [...prev, {
                role: 'user',
                content: currentPrompt,
                timestamp: new Date()
            }])
        }
        
        setIsLoading(true)
        setPrompt("") // Clear prompt immediately
        
        try {
            // If it's a revision request, modify the prompt to generate a complete revised description
            const apiPrompt = isRevisionRequest 
                ? `${currentPrompt}\n\nIMPORTANT: Generate a complete, standalone revised description that incorporates this request. The response should be a full security analysis description, not just the additions.`
                : currentPrompt
            
            const response = await fetch("http://localhost:8000/ai/analyze-finding", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ finding_id: findingId, prompt: apiPrompt || undefined }),
            })

            if (!response.ok) {
                const errorData = await response.json().catch(() => null)
                throw new Error(errorData?.detail || "Analysis failed")
            }

            const data = await response.json()
            
            if (isInitialAnalysis) {
                // First analysis becomes the main description
                setAnalysis(data.analysis)
                setSaved(false)
            } else {
                // Check if this was a revision request
                if (isRevisionRequest) {
                    // Update the main analysis with the revised version
                    setAnalysis(data.analysis)
                    setSaved(false)
                    
                    // Auto-save the revised description
                    const saved = await saveRevisedDescription(data.analysis)
                    
                    // Add confirmation to conversation
                    setConversation(prev => [...prev, {
                        role: 'assistant',
                        content: saved 
                            ? `✅ **Description Updated**\n\nI've revised the description based on your request and automatically saved it. The new description is now displayed above.\n\n---\n\n${data.analysis}`
                            : `I've revised the description based on your request (shown above), but there was an issue saving it automatically. Please use the "Update Description with AI Results" button to save manually.\n\n---\n\n${data.analysis}`,
                        timestamp: new Date()
                    }])
                } else {
                    // Regular follow-up responses go to conversation only
                    setConversation(prev => [...prev, {
                        role: 'assistant',
                        content: data.analysis,
                        timestamp: new Date()
                    }])
                }
            }
        } catch (error) {
            console.error("Analysis failed", error)
            if (isInitialAnalysis) {
                setAnalysis("Failed to generate analysis. Please try again.")
            } else {
                setConversation(prev => [...prev, {
                    role: 'assistant',
                    content: "Failed to generate response. Please try again.",
                    timestamp: new Date()
                }])
            }
        } finally {
            setIsLoading(false)
        }
    }

    // Auto-start analysis when dialog opens
    useEffect(() => {
        if (isOpen && !analysis && !isLoading && !hasStartedAnalysis.current) {
            hasStartedAnalysis.current = true
            handleAnalyze()
        }
    }, [isOpen, analysis, isLoading])

    const updateDescriptionWithAI = async () => {
        if (!analysis) return
        
        setSaving(true)
        try {
            const timestamp = new Date().toLocaleString('en-US', { 
                dateStyle: 'medium', 
                timeStyle: 'short' 
            })
            
            const aiDescription = `**AI Security Analysis**

> *Generated on ${timestamp}*

---

${analysis}

---

*This description was enhanced by AI analysis. Review and validate findings before taking action.*`

            const res = await fetch(`http://localhost:8000/findings/${findingId}`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    description: aiDescription
                })
            })
            
            if (res.ok) {
                setSaved(true)
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

    const handleClose = (open: boolean) => {
        setIsOpen(open)
        if (!open) {
            setSaved(false)
            // Optionally reset conversation when closing
            // setConversation([])
        }
    }

    return (
        <Dialog open={isOpen} onOpenChange={handleClose}>
            <DialogTrigger asChild>
                {trigger || (
                    <Button variant="outline" size="sm" className="gap-2">
                        <Sparkles className="h-4 w-4 text-purple-500" />
                        Ask AI
                    </Button>
                )}
            </DialogTrigger>
            <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
                <DialogHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <DialogTitle className="flex items-center gap-2">
                        <Sparkles className="h-5 w-5 text-purple-500" />
                        AI Security Analysis
                    </DialogTitle>
                    <Popover open={historyOpen} onOpenChange={(open) => {
                        setHistoryOpen(open)
                        if (open) fetchVersionHistory()
                    }}>
                        <PopoverTrigger asChild>
                            <Button variant="outline" size="sm" className="gap-2">
                                <History className="h-4 w-4" />
                                Version History
                            </Button>
                        </PopoverTrigger>
                        <PopoverContent className="w-96" align="end">
                            <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                    <h4 className="font-medium text-sm">Description Versions</h4>
                                    {loadingVersions && <Loader2 className="h-4 w-4 animate-spin" />}
                                </div>
                                {versions.length === 0 && !loadingVersions ? (
                                    <p className="text-sm text-muted-foreground py-4 text-center">
                                        No previous versions found.
                                    </p>
                                ) : (
                                    <ScrollArea className="h-[300px]">
                                        <div className="space-y-2 pr-3">
                                            {versions.map((version, index) => (
                                                <div
                                                    key={version.id}
                                                    className="p-3 rounded-lg border bg-muted/30 space-y-2"
                                                >
                                                    <div className="flex items-center justify-between">
                                                        <span className="text-xs font-medium text-muted-foreground">
                                                            Version {versions.length - index}
                                                        </span>
                                                        <span className="text-xs text-muted-foreground">
                                                            {new Date(version.created_at).toLocaleString([], {
                                                                dateStyle: 'short',
                                                                timeStyle: 'short'
                                                            })}
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-muted-foreground line-clamp-3">
                                                        {version.description?.substring(0, 150)}...
                                                    </p>
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        className="w-full gap-2"
                                                        onClick={() => restoreVersion(version.id)}
                                                        disabled={restoringVersion === version.id}
                                                    >
                                                        {restoringVersion === version.id ? (
                                                            <>
                                                                <Loader2 className="h-3 w-3 animate-spin" />
                                                                Restoring...
                                                            </>
                                                        ) : (
                                                            <>
                                                                <RotateCcw className="h-3 w-3" />
                                                                Restore This Version
                                                            </>
                                                        )}
                                                    </Button>
                                                </div>
                                            ))}
                                        </div>
                                    </ScrollArea>
                                )}
                            </div>
                        </PopoverContent>
                    </Popover>
                </DialogHeader>

                {/* Scrollable content area */}
                <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-4 pr-2">
                    {/* Initial Analysis Card */}
                    <Card className="border-purple-200 dark:border-purple-800">
                        <CardHeader className="pb-3">
                            <CardTitle className="text-base flex items-center gap-2">
                                <Sparkles className="h-4 w-4 text-purple-500" />
                                Initial Analysis
                            </CardTitle>
                        </CardHeader>
                        <CardContent>
                            {isLoading && !analysis ? (
                                <div className="flex flex-col items-center justify-center py-8 gap-4 text-muted-foreground">
                                    <Loader2 className="h-8 w-8 animate-spin" />
                                    <p>Analyzing finding...</p>
                                </div>
                            ) : analysis ? (
                                <div className="prose prose-sm dark:prose-invert max-w-none">
                                    <ReactMarkdown remarkPlugins={[remarkGfm]}>{analysis}</ReactMarkdown>
                                </div>
                            ) : null}
                        </CardContent>
                    </Card>

                    {/* Update Description Section - shows after analysis is complete */}
                    {analysis && analysis !== "Failed to generate analysis. Please try again." && (
                        <div className="flex items-center justify-between p-4 rounded-lg border bg-muted/30">
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
                    )}

                    {/* Conversation History - shows after initial analysis */}
                    {analysis && conversation.length > 0 && (
                        <Card>
                            <CardHeader className="pb-3">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <MessageSquare className="h-4 w-4 text-blue-500" />
                                    Follow-up Conversation
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-4">
                                {conversation.map((message, index) => (
                                    <div
                                        key={index}
                                        className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                                    >
                                        {message.role === 'assistant' && (
                                            <div className="flex-shrink-0 w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900 flex items-center justify-center">
                                                <Bot className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                                            </div>
                                        )}
                                        <div
                                            className={`max-w-[80%] rounded-lg p-3 ${
                                                message.role === 'user'
                                                    ? 'bg-blue-500 text-white'
                                                    : 'bg-muted'
                                            }`}
                                        >
                                            {message.role === 'user' ? (
                                                <p className="text-sm">{message.content}</p>
                                            ) : (
                                                <div className="prose prose-sm dark:prose-invert max-w-none">
                                                    <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                                                </div>
                                            )}
                                            <p className={`text-xs mt-2 ${message.role === 'user' ? 'text-blue-100' : 'text-muted-foreground'}`}>
                                                {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                            </p>
                                        </div>
                                        {message.role === 'user' && (
                                            <div className="flex-shrink-0 w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                                                <User className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                                            </div>
                                        )}
                                    </div>
                                ))}
                                
                                {/* Loading indicator for follow-up */}
                                {isLoading && analysis && (
                                    <div className="flex gap-3 justify-start">
                                        <div className="flex-shrink-0 w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900 flex items-center justify-center">
                                            <Bot className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                                        </div>
                                        <div className="bg-muted rounded-lg p-3">
                                            <Loader2 className="h-4 w-4 animate-spin" />
                                        </div>
                                    </div>
                                )}
                            </CardContent>
                        </Card>
                    )}
                    
                    {/* Loading indicator for first follow-up when no conversation yet */}
                    {isLoading && analysis && conversation.length === 0 && (
                        <Card>
                            <CardHeader className="pb-3">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <MessageSquare className="h-4 w-4 text-blue-500" />
                                    Follow-up Conversation
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <div className="flex gap-3 justify-start">
                                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900 flex items-center justify-center">
                                        <Bot className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                                    </div>
                                    <div className="bg-muted rounded-lg p-3">
                                        <Loader2 className="h-4 w-4 animate-spin" />
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </div>

                {/* Input area - fixed at bottom */}
                {analysis && (
                    <div className="pt-4 border-t mt-4 space-y-2">
                        <div className="flex gap-2">
                            <Textarea
                                placeholder="Ask a follow-up question..."
                                value={prompt}
                                onChange={(e) => setPrompt(e.target.value)}
                                className="resize-none"
                                rows={2}
                                onKeyDown={(e) => {
                                    if (e.key === "Enter" && !e.shiftKey && prompt.trim()) {
                                        e.preventDefault()
                                        handleAnalyze()
                                    }
                                }}
                            />
                            <div className="flex flex-col gap-2">
                                <Button
                                    onClick={handleAnalyze}
                                    disabled={isLoading || !prompt.trim()}
                                    className="h-auto flex-1"
                                >
                                    {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                                </Button>
                                <Popover>
                                    <PopoverTrigger asChild>
                                        <Button
                                            variant="ghost"
                                            size="icon"
                                            className="h-8 w-8 text-amber-500 hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-950"
                                        >
                                            <Lightbulb className="h-4 w-4" />
                                        </Button>
                                    </PopoverTrigger>
                                    <PopoverContent className="w-[420px]" align="end" side="top">
                                        <div className="space-y-4">
                                            <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400">
                                                <Lightbulb className="h-5 w-5" />
                                                <h4 className="font-semibold">Pro Tips: Smart Description Updates</h4>
                                            </div>
                                            
                                            <p className="text-sm text-muted-foreground">
                                                You can do more than just ask questions! Use natural language to automatically revise and save the description.
                                            </p>

                                            <div className="space-y-2">
                                                <h5 className="text-sm font-medium">How it works:</h5>
                                                <p className="text-xs text-muted-foreground">
                                                    When you type a follow-up containing phrases like:
                                                </p>
                                                <div className="grid grid-cols-2 gap-1 text-xs">
                                                    <code className="bg-muted px-2 py-1 rounded">&quot;Revise the description to...&quot;</code>
                                                    <code className="bg-muted px-2 py-1 rounded">&quot;Update the description to...&quot;</code>
                                                    <code className="bg-muted px-2 py-1 rounded">&quot;Change the description to...&quot;</code>
                                                    <code className="bg-muted px-2 py-1 rounded">&quot;Make the description...&quot;</code>
                                                    <code className="bg-muted px-2 py-1 rounded">&quot;Add to the description...&quot;</code>
                                                    <code className="bg-muted px-2 py-1 rounded">&quot;Improve the description...&quot;</code>
                                                </div>
                                            </div>

                                            <div className="space-y-2">
                                                <h5 className="text-sm font-medium">The system will automatically:</h5>
                                                <ul className="text-xs text-muted-foreground space-y-1">
                                                    <li className="flex items-center gap-2">
                                                        <Check className="h-3 w-3 text-green-500" />
                                                        Detect your revision intent using smart matching
                                                    </li>
                                                    <li className="flex items-center gap-2">
                                                        <Check className="h-3 w-3 text-green-500" />
                                                        Generate a complete revised description
                                                    </li>
                                                    <li className="flex items-center gap-2">
                                                        <Check className="h-3 w-3 text-green-500" />
                                                        Update the Initial Analysis card above
                                                    </li>
                                                    <li className="flex items-center gap-2">
                                                        <Check className="h-3 w-3 text-green-500" />
                                                        Auto-save to the database (no button click needed!)
                                                    </li>
                                                    <li className="flex items-center gap-2">
                                                        <Check className="h-3 w-3 text-green-500" />
                                                        Show ✅ confirmation in the conversation
                                                    </li>
                                                </ul>
                                            </div>

                                            <div className="space-y-2 bg-muted/50 rounded-lg p-3">
                                                <h5 className="text-sm font-medium">Example prompts:</h5>
                                                <ul className="text-xs text-muted-foreground space-y-1.5">
                                                    <li className="italic">&quot;Revise the description to provide a high-level explanation of what Cisco Meraki is and what it&apos;s used for.&quot;</li>
                                                    <li className="italic">&quot;Update the description to include remediation steps&quot;</li>
                                                    <li className="italic">&quot;Change the description to explain the business impact&quot;</li>
                                                    <li className="italic">&quot;Make the description more technical for the security team&quot;</li>
                                                    <li className="italic">&quot;Add to the description information about compliance implications&quot;</li>
                                                </ul>
                                            </div>
                                        </div>
                                    </PopoverContent>
                                </Popover>
                            </div>
                        </div>
                    </div>
                )}
            </DialogContent>
        </Dialog>
    )
}
