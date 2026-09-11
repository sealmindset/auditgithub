"use client"

import { useState } from "react"
import { SeverityBadge, SeverityDot } from "@/components/ui/severity-badge"
import { Button } from "@/components/ui/button"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Loader2, Pencil } from "lucide-react"
import { API_BASE, apiFetch } from "@/lib/api"

interface SeverityEditorProps {
    findingId: string
    currentSeverity: string
    onUpdate: () => void
}

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

export function SeverityEditor({ findingId, currentSeverity, onUpdate }: SeverityEditorProps) {
    const [isOpen, setIsOpen] = useState(false)
    const [severity, setSeverity] = useState(currentSeverity)
    const [scope, setScope] = useState("specific")
    const [loading, setLoading] = useState(false)

    const handleUpdate = async () => {
        setLoading(true)
        try {
            const res = await apiFetch(`${API_BASE}/findings/${findingId}`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    severity: severity,
                    scope: scope
                })
            })

            if (!res.ok) throw new Error("Failed to update severity")

            setIsOpen(false)
            onUpdate()
        } catch (error) {
            console.error(error)
            // Error handling could be improved (toast notification)
        } finally {
            setLoading(false)
        }
    }

    return (
        <Dialog open={isOpen} onOpenChange={setIsOpen}>
            <DialogTrigger asChild>
                <button
                    type="button"
                    className="group flex cursor-pointer items-center gap-2 rounded-md focus-visible:ring-[3px] focus-visible:ring-ring/45 focus-visible:outline-none"
                    aria-label={`Severity ${currentSeverity}. Click to change.`}
                >
                    <SeverityBadge
                        severity={currentSeverity}
                        className="transition-colors group-hover:brightness-95"
                    />
                    <Pencil
                        className="size-3 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100"
                        aria-hidden="true"
                    />
                </button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <DialogTitle>Edit Severity</DialogTitle>
                    <DialogDescription>
                        Manually override the severity rating for this finding.
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-6 py-4">
                    <div className="space-y-2">
                        <Label>Severity Level</Label>
                        <Select value={severity} onValueChange={setSeverity}>
                            <SelectTrigger>
                                <SelectValue placeholder="Select severity" />
                            </SelectTrigger>
                            <SelectContent>
                                {SEVERITIES.map((sev) => (
                                    <SelectItem key={sev} value={sev}>
                                        <div className="flex items-center gap-2">
                                            <SeverityDot severity={sev} />
                                            {sev}
                                        </div>
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </div>

                    <div className="space-y-3">
                        <Label>Scope</Label>
                        <RadioGroup value={scope} onValueChange={setScope} className="grid gap-4">
                            <div className="flex items-center space-x-2 rounded-md border p-3 hover:bg-accent/50 cursor-pointer">
                                <RadioGroupItem value="specific" id="specific" />
                                <Label htmlFor="specific" className="flex-1 cursor-pointer">
                                    <div className="font-medium">This finding only</div>
                                    <div className="text-xs text-muted-foreground">
                                        Update only this specific instance.
                                    </div>
                                </Label>
                            </div>
                            <div className="flex items-center space-x-2 rounded-md border p-3 hover:bg-accent/50 cursor-pointer">
                                <RadioGroupItem value="global" id="global" />
                                <Label htmlFor="global" className="flex-1 cursor-pointer">
                                    <div className="font-medium">Global (Repository)</div>
                                    <div className="text-xs text-muted-foreground">
                                        Update all identical findings in this repo.
                                    </div>
                                </Label>
                            </div>
                        </RadioGroup>
                    </div>
                </div>
                <DialogFooter>
                    <Button variant="outline" onClick={() => setIsOpen(false)}>Cancel</Button>
                    <Button onClick={handleUpdate} disabled={loading}>
                        {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Save Changes
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    )
}
