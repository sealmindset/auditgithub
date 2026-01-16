import { ZDAReportsView } from "@/components/ZDAReportsView"

export default function ZDAReportsPage() {
    return (
        <div className="container mx-auto py-6">
            <h1 className="text-3xl font-bold mb-6">ZDA Reports</h1>
            <p className="text-muted-foreground mb-6">
                View and manage your saved Zero Day Analysis reports.
            </p>
            <ZDAReportsView />
        </div>
    )
}
