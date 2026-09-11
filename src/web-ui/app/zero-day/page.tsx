"use client"

import { Crosshair } from "lucide-react"

import { PageHeader, PageShell } from "@/components/ui/page-header"
import { ZeroDayView } from "@/components/ZeroDayView"

export default function ZeroDayPage() {
    return (
        <PageShell>
            <PageHeader
                icon={Crosshair}
                eyebrow="Research"
                title="Zero day analysis"
                description="Targeted analysis of code paths that no published advisory covers yet."
            />
            <ZeroDayView />
        </PageShell>
    )
}
