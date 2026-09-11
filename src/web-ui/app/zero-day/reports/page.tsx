"use client"

import { FileText } from "lucide-react"

import { PageHeader, PageShell } from "@/components/ui/page-header"
import { ZDAReportsView } from "@/components/ZDAReportsView"

export default function ZDAReportsPage() {
    return (
        <PageShell>
            <PageHeader
                icon={FileText}
                eyebrow="Research"
                title="ZDA reports"
                description="Saved zero day analysis reports, newest first."
            />
            <ZDAReportsView />
        </PageShell>
    )
}
