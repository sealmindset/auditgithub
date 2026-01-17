"use client"

import { useState } from "react"
import { format } from "date-fns"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Loader2 } from "lucide-react"

export type TimeWindow = "morning" | "afternoon" | "evening" | "night"

interface TimeWindowDialogProps {
    open: boolean
    onOpenChange: (open: boolean) => void
    onConfirm: (timeWindow: TimeWindow, reason?: string) => Promise<void>
    eventTitle: string
    newDate: Date
    isLoading?: boolean
}

const TIME_WINDOW_OPTIONS: { value: TimeWindow; label: string; time: string }[] = [
    { value: "morning", label: "Morning", time: "8:00 AM" },
    { value: "afternoon", label: "Afternoon", time: "2:00 PM" },
    { value: "evening", label: "Evening", time: "8:00 PM" },
    { value: "night", label: "Night", time: "2:00 AM" },
]

export function TimeWindowDialog({
    open,
    onOpenChange,
    onConfirm,
    eventTitle,
    newDate,
    isLoading = false,
}: TimeWindowDialogProps) {
    const [selectedTimeWindow, setSelectedTimeWindow] = useState<TimeWindow>("morning")
    const [reason, setReason] = useState("")

    const handleConfirm = async () => {
        await onConfirm(selectedTimeWindow, reason || undefined)
        // Reset form state
        setSelectedTimeWindow("morning")
        setReason("")
    }

    const handleCancel = () => {
        if (isLoading) return // Prevent cancel while loading
        onOpenChange(false)
        // Reset form state
        setSelectedTimeWindow("morning")
        setReason("")
    }

    const formattedDate = format(newDate, "EEEE, MMMM d, yyyy")

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <DialogTitle>Reschedule: {eventTitle}</DialogTitle>
                    <DialogDescription>
                        New date: {formattedDate}
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                    <div className="grid gap-2">
                        <Label htmlFor="time-window">Time window</Label>
                        <Select
                            value={selectedTimeWindow}
                            onValueChange={(value) => setSelectedTimeWindow(value as TimeWindow)}
                        >
                            <SelectTrigger id="time-window">
                                <SelectValue placeholder="Select time window" />
                            </SelectTrigger>
                            <SelectContent>
                                {TIME_WINDOW_OPTIONS.map((option) => (
                                    <SelectItem key={option.value} value={option.value}>
                                        {option.label} ({option.time})
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="reason">Reason (optional)</Label>
                        <Textarea
                            id="reason"
                            placeholder="Enter reason for rescheduling..."
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                            rows={3}
                        />
                    </div>
                </div>
                <DialogFooter>
                    <Button variant="outline" onClick={handleCancel} disabled={isLoading}>
                        Cancel
                    </Button>
                    <Button onClick={handleConfirm} disabled={isLoading}>
                        {isLoading ? (
                            <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                Saving...
                            </>
                        ) : (
                            "Reschedule"
                        )}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    )
}
