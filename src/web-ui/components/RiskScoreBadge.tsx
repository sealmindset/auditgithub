"use client"

import { Badge } from "@/components/ui/badge"
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip"
import { TrendingUp, AlertTriangle, Shield, Info } from "lucide-react"

interface RiskScoreBadgeProps {
    score: number | null
    level?: string | null
    factors?: Record<string, any> | null
    showScore?: boolean
    size?: "sm" | "md" | "lg"
}

export function RiskScoreBadge({
    score,
    level,
    factors,
    showScore = true,
    size = "md"
}: RiskScoreBadgeProps) {
    if (score === null || score === undefined) {
        return (
            <Badge variant="outline" className="text-muted-foreground">
                --
            </Badge>
        )
    }

    const getColorClass = (riskLevel: string) => {
        switch (riskLevel?.toLowerCase()) {
            case 'critical':
                return 'bg-red-600 hover:bg-red-700 text-white'
            case 'high':
                return 'bg-orange-500 hover:bg-orange-600 text-white'
            case 'medium':
                return 'bg-yellow-500 hover:bg-yellow-600 text-black'
            case 'low':
                return 'bg-green-500 hover:bg-green-600 text-white'
            default:
                return 'bg-gray-400 hover:bg-gray-500 text-white'
        }
    }

    const getIcon = (riskLevel: string) => {
        const iconSize = size === "sm" ? "h-3 w-3" : "h-4 w-4"
        switch (riskLevel?.toLowerCase()) {
            case 'critical':
                return <AlertTriangle className={iconSize} />
            case 'high':
                return <TrendingUp className={iconSize} />
            case 'medium':
                return <Shield className={iconSize} />
            default:
                return <Info className={iconSize} />
        }
    }

    const sizeClass = size === "sm" ? "text-xs px-1.5 py-0.5" : size === "lg" ? "text-base px-3 py-1.5" : "text-sm px-2 py-1"

    const riskLevel = level || (score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low')

    const formatFactors = () => {
        if (!factors) return null

        const lines = []
        if (factors.severity) {
            lines.push(`🎯 Severity: ${factors.severity.value} (+${factors.severity.points})`)
        }
        if (factors.exposure?.reasons?.length > 0) {
            lines.push(`🌐 Exposure: ${factors.exposure.reasons.join(', ')} (+${factors.exposure.points})`)
        }
        if (factors.age?.days) {
            lines.push(`📅 Age: ${factors.age.days} days (+${factors.age.points})`)
        }
        if (factors.context?.reasons?.length > 0) {
            lines.push(`📂 Context: ${factors.context.reasons.join(', ')} (+${factors.context.points})`)
        }
        return lines.join('\n')
    }

    const badge = (
        <Badge
            className={`${getColorClass(riskLevel)} ${sizeClass} flex items-center gap-1 cursor-help transition-all`}
        >
            {getIcon(riskLevel)}
            {showScore && <span>{score}</span>}
        </Badge>
    )

    if (factors) {
        return (
            <TooltipProvider>
                <Tooltip>
                    <TooltipTrigger asChild>
                        {badge}
                    </TooltipTrigger>
                    <TooltipContent className="max-w-xs">
                        <div className="text-sm space-y-1">
                            <div className="font-semibold border-b pb-1 mb-1">
                                Risk Score: {score}/100 ({riskLevel.toUpperCase()})
                            </div>
                            <pre className="text-xs whitespace-pre-wrap">
                                {formatFactors()}
                            </pre>
                        </div>
                    </TooltipContent>
                </Tooltip>
            </TooltipProvider>
        )
    }

    return badge
}
