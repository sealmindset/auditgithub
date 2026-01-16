"use client"

import { useState } from "react"
import { ThumbsUp, ThumbsDown } from "lucide-react"
import { cn } from "@/lib/utils"
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip"

const API_BASE = "http://localhost:8000"

interface FeedbackButtonProps {
    componentId: string
    componentName: string
    className?: string
    size?: "sm" | "md"
}

export function FeedbackButton({
    componentId,
    componentName,
    className,
    size = "sm"
}: FeedbackButtonProps) {
    const [feedback, setFeedback] = useState<"up" | "down" | null>(null)
    const [isSubmitting, setIsSubmitting] = useState(false)
    const [showThanks, setShowThanks] = useState(false)

    const submitFeedback = async (vote: "up" | "down") => {
        if (isSubmitting) return

        setIsSubmitting(true)
        try {
            await fetch(`${API_BASE}/feedback/component`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    component_id: componentId,
                    component_name: componentName,
                    vote: vote,
                    timestamp: new Date().toISOString()
                })
            })

            setFeedback(vote)
            setShowThanks(true)
            setTimeout(() => setShowThanks(false), 2000)
        } catch (error) {
            console.error("Failed to submit feedback:", error)
        } finally {
            setIsSubmitting(false)
        }
    }

    const iconSize = size === "sm" ? "h-3.5 w-3.5" : "h-4 w-4"
    const buttonPadding = size === "sm" ? "p-1" : "p-1.5"

    return (
        <TooltipProvider>
            <div className={cn(
                "flex items-center gap-1 rounded-md bg-muted/50 backdrop-blur-sm",
                className
            )}>
                {showThanks ? (
                    <span className="text-[10px] text-green-500 px-2 py-1 animate-in fade-in-0">
                        Thanks!
                    </span>
                ) : (
                    <>
                        <Tooltip>
                            <TooltipTrigger asChild>
                                <button
                                    onClick={() => submitFeedback("up")}
                                    disabled={isSubmitting || feedback !== null}
                                    className={cn(
                                        buttonPadding,
                                        "rounded-l-md transition-all hover:bg-green-500/20",
                                        feedback === "up" && "bg-green-500/30 text-green-500",
                                        feedback !== null && feedback !== "up" && "opacity-30",
                                        isSubmitting && "cursor-wait"
                                    )}
                                >
                                    <ThumbsUp className={cn(
                                        iconSize,
                                        feedback === "up" ? "text-green-500" : "text-muted-foreground"
                                    )} />
                                </button>
                            </TooltipTrigger>
                            <TooltipContent side="bottom" className="text-xs">
                                This works well
                            </TooltipContent>
                        </Tooltip>

                        <div className="w-px h-4 bg-border" />

                        <Tooltip>
                            <TooltipTrigger asChild>
                                <button
                                    onClick={() => submitFeedback("down")}
                                    disabled={isSubmitting || feedback !== null}
                                    className={cn(
                                        buttonPadding,
                                        "rounded-r-md transition-all hover:bg-red-500/20",
                                        feedback === "down" && "bg-red-500/30 text-red-500",
                                        feedback !== null && feedback !== "down" && "opacity-30",
                                        isSubmitting && "cursor-wait"
                                    )}
                                >
                                    <ThumbsDown className={cn(
                                        iconSize,
                                        feedback === "down" ? "text-red-500" : "text-muted-foreground"
                                    )} />
                                </button>
                            </TooltipTrigger>
                            <TooltipContent side="bottom" className="text-xs">
                                Needs improvement
                            </TooltipContent>
                        </Tooltip>
                    </>
                )}
            </div>
        </TooltipProvider>
    )
}
