"use client"

import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip"
import { Badge } from "@/components/ui/badge"
import { SeverityBadge } from "@/components/ui/severity-badge"
import {
    SEVERITY_TONE,
    normalizeSeverity,
    severityFromRisk,
    severityLabel,
} from "@/lib/severity"
import { cn } from "@/lib/utils"

interface RiskFactor {
    value?: string | number
    points?: number
    days?: number
    reasons?: string[]
}

interface RiskScoreBadgeProps {
    score: number | null
    level?: string | null
    factors?: Record<string, RiskFactor> | null
    showScore?: boolean
    size?: "sm" | "md" | "lg"
}

/** The four factors the scorer reports, in the order it weights them. */
const FACTOR_LABELS: Array<{ key: string; label: string }> = [
    { key: "severity", label: "Severity" },
    { key: "exposure", label: "Exposure" },
    { key: "age", label: "Age" },
    { key: "context", label: "Context" },
]

function describeFactor(key: string, factor: RiskFactor): string | null {
    const points = factor.points !== undefined ? ` (+${factor.points})` : ""

    if (key === "age" && factor.days !== undefined) {
        return `${factor.days} day${factor.days === 1 ? "" : "s"}${points}`
    }
    if (factor.reasons?.length) {
        return `${factor.reasons.join(", ")}${points}`
    }
    if (factor.value !== undefined) {
        return `${factor.value}${points}`
    }
    return points ? points.trim() : null
}

/**
 * Risk score badge.
 *
 * The score band uses the same five-step ramp and the same glyphs as every
 * other severity in the product, so a "High" here reads as the same thing as a
 * "High" in the findings table.
 */
export function RiskScoreBadge({
    score,
    level,
    factors,
    showScore = true,
    size = "md",
}: RiskScoreBadgeProps) {
    if (score === null || score === undefined) {
        return (
            <Badge variant="outline" className="text-muted-foreground" title="No risk score recorded">
                &mdash;
            </Badge>
        )
    }

    const band = level ? normalizeSeverity(level) : severityFromRisk(score)

    const badge = (
        <SeverityBadge
            severity={band}
            size={size === "sm" ? "sm" : "default"}
            label={showScore ? score : severityLabel(band)}
            className={cn(
                "tabular-nums",
                size === "lg" && "h-7 px-2.5 text-sm",
                factors && "cursor-help",
            )}
            aria-label={`Risk score ${score} of 100, ${severityLabel(band)}`}
        />
    )

    if (!factors) return badge

    const rows = FACTOR_LABELS.map(({ key, label }) => {
        const factor = factors[key]
        if (!factor) return null
        const detail = describeFactor(key, factor)
        return detail ? { label, detail } : null
    }).filter((r): r is { label: string; detail: string } => r !== null)

    return (
        <TooltipProvider delayDuration={150}>
            <Tooltip>
                <TooltipTrigger asChild>
                    <span>{badge}</span>
                </TooltipTrigger>
                <TooltipContent className="max-w-xs p-0">
                    <div className="border-b px-3 py-2">
                        <p className="text-sm font-semibold">
                            Risk score {score}
                            <span className="text-muted-foreground">/100</span>
                        </p>
                        <p className={cn("text-xs", SEVERITY_TONE[band].text)}>
                            {severityLabel(band)} band
                        </p>
                    </div>
                    {rows.length > 0 && (
                        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 px-3 py-2 text-xs">
                            {rows.map((row) => (
                                <div key={row.label} className="contents">
                                    <dt className="text-muted-foreground">{row.label}</dt>
                                    <dd className="text-foreground">{row.detail}</dd>
                                </div>
                            ))}
                        </dl>
                    )}
                </TooltipContent>
            </Tooltip>
        </TooltipProvider>
    )
}
