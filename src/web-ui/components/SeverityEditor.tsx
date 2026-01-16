"use client"

import { useState } from "react"
import { Badge } from "@/components/ui/badge"
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

interface SeverityEditorProps {
    findingId: string
    currentSeverity: string
    onUpdate: () => void
}

const API_BASE = "http://localhost:8000"

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

export function SeverityEditor({ findingId, currentSeverity, onUpdate }: SeverityEditorProps) {
    const [isOpen, setIsOpen] = useState(false)
    const [severity, setSeverity] = useState(currentSeverity)
    const [scope, setScope] = useState("specific")
    const [loading, setLoading] = useState(false)

    const handleUpdate = async () => {
        setLoading(true)
        try {
            const res = await fetch(`${API_BASE}/findings/${findingId}`, {
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

    const getSeverityColor = (sev: string) => {
        const s = sev.toLowerCase()
        if (s === "critical") return "bg-red-600 hover:bg-red-700"
        if (s === "high") return "bg-orange-500 hover:bg-orange-600"
        if (s === "medium") return "bg-yellow-500 hover:bg-yellow-600 text-black"
        if (s === "low") return "bg-green-500 hover:bg-green-600"
        return "bg-gray-400 hover:bg-gray-500"
    }

    return (
        <Dialog open={isOpen} onOpenChange={setIsOpen}>
            <DialogTrigger asChild>
                <div className="group cursor-pointer flex items-center gap-2">
                    <Badge className={`${getSeverityColor(currentSeverity)} cursor-pointer transition-all hover:scale-105`}>
                        {currentSeverity}
                        <Pencil className="ml-1 h-3 w-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </Badge>
                </div>
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
                                            <div className={`h-2 w-2 rounded-full ${getSeverityColor(sev).split(" ")[0]}`} />
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
