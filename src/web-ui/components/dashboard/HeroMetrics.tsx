"use client"

import { AlertTriangle, Bot, GitBranch, ShieldAlert } from "lucide-react"

import { StatCard, StatGrid, type StatTrend } from "@/components/ui/stat-card"
import { AnimatedCounter } from "./AnimatedCounter"

interface TrendPayload {
    value: number
    label: string
}

interface HeroMetricsProps {
    data: {
        repositories: number
        criticalFindings: number
        underInvestigation: number
        aiAnalysesToday: number
        trends?: {
            repositories?: TrendPayload
            findings?: TrendPayload
            investigations?: TrendPayload
            aiAnalyses?: TrendPayload
        }
    }
    loading?: boolean
}

/** Adapt the API's trend payload to the stat tile's shape. */
function toTrend(
    payload: TrendPayload | undefined,
    higherIsBetter: boolean,
): StatTrend | undefined {
    if (!payload) return undefined
    return { delta: payload.value, label: payload.label, higherIsBetter }
}

/**
 * The four numbers that answer "how bad is it right now".
 *
 * All four use the same tile as every other metric in the product; only the
 * tone differs, and the tone carries meaning: red is the count you must act
 * on, amber is work in flight, violet is machine-generated.
 */
export function HeroMetrics({ data, loading = false }: HeroMetricsProps) {
    return (
        <StatGrid>
            <StatCard
                label="Repositories"
                value={<AnimatedCounter value={data.repositories} duration={1200} />}
                hint="Monitored"
                icon={GitBranch}
                tone="info"
                loading={loading}
                href="/repositories"
                trend={toTrend(data.trends?.repositories, true)}
            />
            <StatCard
                label="Critical findings"
                value={<AnimatedCounter value={data.criticalFindings} duration={1200} />}
                hint="Awaiting remediation"
                icon={ShieldAlert}
                tone="danger"
                loading={loading}
                href="/findings?severity=critical"
                trend={toTrend(data.trends?.findings, false)}
            />
            <StatCard
                label="Under investigation"
                value={<AnimatedCounter value={data.underInvestigation} duration={1200} />}
                hint="Triage in progress"
                icon={AlertTriangle}
                tone="warning"
                loading={loading}
                href="/findings?status=investigating"
                trend={toTrend(data.trends?.investigations, true)}
            />
            <StatCard
                label="AI analyses"
                value={<AnimatedCounter value={data.aiAnalysesToday} duration={1200} />}
                hint="Completed today"
                icon={Bot}
                tone="ai"
                loading={loading}
                href="/prompts/analytics"
                trend={toTrend(data.trends?.aiAnalyses, true)}
            />
        </StatGrid>
    )
}
