"use client"

import { useState, useEffect, useCallback, useMemo } from "react"
import { format } from "date-fns"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"
import { Loader2, Lock, Unlock, Bot, User, Clock, Calendar, History, Info, Settings2, ChevronDown, ChevronRight } from "lucide-react"
import type { Schedule } from "@/components/SchedulerCalendar"

// Scanner info type from API
interface ScannerInfo {
    id: string
    name: string
    category: string
    description: string
}

const API_BASE = "http://localhost:8000"

// Override history item type
interface OverrideHistoryItem {
    id: string
    previous_frequency: string | null
    previous_day_of_week: number | null
    previous_time_window: string | null
    new_frequency: string | null
    new_day_of_week: number | null
    new_time_window: string | null
    override_reason: string | null
    overridden_by_email: string
    created_at: string
}

interface OverrideHistoryResponse {
    schedule_id: string
    repository_name: string
    overrides: OverrideHistoryItem[]
}

interface ScheduleOverrideDialogProps {
    open: boolean
    onOpenChange: (open: boolean) => void
    schedule: Schedule | null
    onLock: (reason: string) => Promise<void>
    onUnlock: () => Promise<void>
    onUpdateScanners?: (scanners: string[] | null) => Promise<void>
    isLoading?: boolean
}

// Category display names
const CATEGORY_NAMES: Record<string, string> = {
    secrets: "Secrets Detection",
    sast: "Static Analysis (SAST)",
    deps: "Dependency Scanning",
    iac: "Infrastructure as Code",
    api: "API Security",
    mobile: "Mobile Security",
    go: "Go Tools",
    other: "Other Tools",
}

// Category order for display
const CATEGORY_ORDER = ["secrets", "sast", "deps", "iac", "api", "mobile", "go", "other"]

// Day of week names
const DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

// Format frequency for display
const formatFrequency = (frequency: string): string => {
    const map: Record<string, string> = {
        daily: "Daily",
        weekly: "Weekly",
        "bi-weekly": "Bi-weekly",
        monthly: "Monthly",
    }
    return map[frequency] || frequency
}

// Format time window for display
const formatTimeWindow = (timeWindow: string): string => {
    const map: Record<string, string> = {
        morning: "Morning (8 AM)",
        afternoon: "Afternoon (2 PM)",
        evening: "Evening (8 PM)",
        night: "Night (2 AM)",
    }
    return map[timeWindow] || timeWindow
}

// Format changes as diff string
const formatChanges = (item: OverrideHistoryItem): string => {
    const changes: string[] = []

    if (item.previous_frequency !== item.new_frequency) {
        changes.push(`${item.previous_frequency || "none"} -> ${item.new_frequency || "none"}`)
    }
    if (item.previous_time_window !== item.new_time_window) {
        changes.push(`${item.previous_time_window || "none"} -> ${item.new_time_window || "none"}`)
    }
    if (item.previous_day_of_week !== item.new_day_of_week) {
        const prevDay = item.previous_day_of_week !== null ? DAY_NAMES[item.previous_day_of_week] : "none"
        const newDay = item.new_day_of_week !== null ? DAY_NAMES[item.new_day_of_week] : "none"
        changes.push(`${prevDay} -> ${newDay}`)
    }

    return changes.length > 0 ? changes.join(", ") : "No changes (lock/unlock only)"
}

export function ScheduleOverrideDialog({
    open,
    onOpenChange,
    schedule,
    onLock,
    onUnlock,
    onUpdateScanners,
    isLoading = false,
}: ScheduleOverrideDialogProps) {
    const [activeTab, setActiveTab] = useState("details")
    const [lockReason, setLockReason] = useState("")
    const [history, setHistory] = useState<OverrideHistoryItem[]>([])
    const [historyLoading, setHistoryLoading] = useState(false)
    const [historyError, setHistoryError] = useState<string | null>(null)

    // Scanner state
    const [availableScanners, setAvailableScanners] = useState<ScannerInfo[]>([])
    const [scannersLoading, setScannersLoading] = useState(false)
    const [scannersError, setScannersError] = useState<string | null>(null)
    const [selectedScanners, setSelectedScanners] = useState<string[]>([])
    const [useAllScanners, setUseAllScanners] = useState(true)
    const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set())
    const [scannersSaving, setScannersSaving] = useState(false)

    // Reset state when dialog opens/closes
    useEffect(() => {
        if (!open) {
            setActiveTab("details")
            setLockReason("")
            setHistory([])
            setHistoryError(null)
            setAvailableScanners([])
            setScannersError(null)
            setExpandedCategories(new Set())
        }
    }, [open])

    // Initialize scanner selection from schedule
    useEffect(() => {
        if (schedule) {
            const scanArgs = schedule.scan_arguments as { scanners?: string } | null
            if (scanArgs?.scanners) {
                const scannerList = scanArgs.scanners.split(",").map(s => s.trim()).filter(Boolean)
                setSelectedScanners(scannerList)
                setUseAllScanners(false)
            } else {
                setSelectedScanners([])
                setUseAllScanners(true)
            }
        }
    }, [schedule])

    // Fetch history when history tab is selected
    const fetchHistory = useCallback(async () => {
        if (!schedule) return

        setHistoryLoading(true)
        setHistoryError(null)

        try {
            const res = await fetch(`${API_BASE}/schedules/${schedule.repository_id}/history`)
            if (!res.ok) {
                throw new Error("Failed to fetch history")
            }
            const data: OverrideHistoryResponse = await res.json()
            setHistory(data.overrides)
        } catch (err) {
            setHistoryError(err instanceof Error ? err.message : "Failed to load history")
        } finally {
            setHistoryLoading(false)
        }
    }, [schedule])

    // Fetch available scanners
    const fetchScanners = useCallback(async () => {
        setScannersLoading(true)
        setScannersError(null)

        try {
            const res = await fetch(`${API_BASE}/schedules/scanners`)
            if (!res.ok) {
                throw new Error("Failed to fetch scanners")
            }
            const data = await res.json()
            setAvailableScanners(data.scanners || [])
        } catch (err) {
            setScannersError(err instanceof Error ? err.message : "Failed to load scanners")
        } finally {
            setScannersLoading(false)
        }
    }, [])

    // Lazy load history when tab changes
    useEffect(() => {
        if (activeTab === "history" && schedule && history.length === 0 && !historyLoading) {
            fetchHistory()
        }
    }, [activeTab, schedule, history.length, historyLoading, fetchHistory])

    // Lazy load scanners when tab changes
    useEffect(() => {
        if (activeTab === "scanners" && availableScanners.length === 0 && !scannersLoading) {
            fetchScanners()
        }
    }, [activeTab, availableScanners.length, scannersLoading, fetchScanners])

    // Group scanners by category
    const scannersByCategory = useMemo(() => {
        const grouped: Record<string, ScannerInfo[]> = {}
        for (const scanner of availableScanners) {
            if (!grouped[scanner.category]) {
                grouped[scanner.category] = []
            }
            grouped[scanner.category].push(scanner)
        }
        return grouped
    }, [availableScanners])

    // Toggle category expansion
    const toggleCategory = (category: string) => {
        setExpandedCategories((prev) => {
            const next = new Set(prev)
            if (next.has(category)) {
                next.delete(category)
            } else {
                next.add(category)
            }
            return next
        })
    }

    // Toggle scanner selection
    const toggleScanner = (scannerId: string) => {
        setSelectedScanners((prev) => {
            if (prev.includes(scannerId)) {
                return prev.filter((id) => id !== scannerId)
            } else {
                return [...prev, scannerId]
            }
        })
    }

    // Select all scanners in a category
    const selectAllInCategory = (category: string) => {
        const categoryIds = scannersByCategory[category]?.map((s) => s.id) || []
        setSelectedScanners((prev) => {
            const withoutCategory = prev.filter((id) => !categoryIds.includes(id))
            return [...withoutCategory, ...categoryIds]
        })
    }

    // Clear all scanners in a category
    const clearAllInCategory = (category: string) => {
        const categoryIds = scannersByCategory[category]?.map((s) => s.id) || []
        setSelectedScanners((prev) => prev.filter((id) => !categoryIds.includes(id)))
    }

    // Save scanner configuration
    const handleSaveScanners = async () => {
        if (!onUpdateScanners) return

        setScannersSaving(true)
        try {
            // Pass null to use all scanners, otherwise pass the selection
            await onUpdateScanners(useAllScanners ? null : selectedScanners)
        } finally {
            setScannersSaving(false)
        }
    }

    const handleLock = async () => {
        if (!lockReason.trim()) return
        await onLock(lockReason)
        setLockReason("")
    }

    const handleUnlock = async () => {
        await onUnlock()
    }

    if (!schedule) return null

    const isLocked = schedule.is_locked
    const isAI = schedule.schedule_type === "ai"

    // Check if custom scanners are configured
    const scanArgs = schedule.scan_arguments as { scanners?: string } | null
    const hasCustomScanners = Boolean(scanArgs?.scanners)
    const customScannerCount = hasCustomScanners
        ? scanArgs!.scanners!.split(",").filter(Boolean).length
        : 0

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-[550px]">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        {schedule.repository_name}
                        {isLocked && <Lock className="h-4 w-4 text-amber-500" />}
                    </DialogTitle>
                    <DialogDescription>
                        View and manage schedule settings
                    </DialogDescription>
                </DialogHeader>

                <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                    <TabsList className="grid w-full grid-cols-4">
                        <TabsTrigger value="details" className="flex items-center gap-1">
                            <Info className="h-4 w-4" />
                            Details
                        </TabsTrigger>
                        <TabsTrigger value="lock" className="flex items-center gap-1">
                            {isLocked ? <Unlock className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
                            {isLocked ? "Unlock" : "Lock"}
                        </TabsTrigger>
                        <TabsTrigger value="scanners" className="flex items-center gap-1">
                            <Settings2 className="h-4 w-4" />
                            Scanners
                        </TabsTrigger>
                        <TabsTrigger value="history" className="flex items-center gap-1">
                            <History className="h-4 w-4" />
                            History
                        </TabsTrigger>
                    </TabsList>

                    {/* Details Tab */}
                    <TabsContent value="details" className="space-y-4 pt-4">
                        <div className="grid gap-4">
                            {/* Schedule Type Badge */}
                            <div className="flex items-center gap-2">
                                <Label className="text-muted-foreground">Type:</Label>
                                <Badge variant={isAI ? "default" : "secondary"} className="flex items-center gap-1">
                                    {isAI ? <Bot className="h-3 w-3" /> : <User className="h-3 w-3" />}
                                    {isAI ? "AI Scheduled" : "Manual"}
                                </Badge>
                            </div>

                            {/* Frequency */}
                            <div className="flex items-center gap-2">
                                <Label className="text-muted-foreground">Frequency:</Label>
                                <span>{formatFrequency(schedule.frequency)}</span>
                                {schedule.day_of_week !== null && (
                                    <span className="text-muted-foreground">
                                        ({DAY_NAMES[schedule.day_of_week]})
                                    </span>
                                )}
                            </div>

                            {/* Time Window */}
                            <div className="flex items-center gap-2">
                                <Clock className="h-4 w-4 text-muted-foreground" />
                                <Label className="text-muted-foreground">Time Window:</Label>
                                <span>{formatTimeWindow(schedule.time_window)}</span>
                            </div>

                            {/* Next Scheduled */}
                            {schedule.next_scheduled_at && (
                                <div className="flex items-center gap-2">
                                    <Calendar className="h-4 w-4 text-muted-foreground" />
                                    <Label className="text-muted-foreground">Next Run:</Label>
                                    <span>
                                        {format(new Date(schedule.next_scheduled_at), "PPpp")}
                                    </span>
                                </div>
                            )}

                            {/* AI Confidence */}
                            {isAI && schedule.ai_confidence !== null && (
                                <div className="flex items-center gap-2">
                                    <Bot className="h-4 w-4 text-blue-500" />
                                    <Label className="text-muted-foreground">AI Confidence:</Label>
                                    <span className="text-blue-500 font-medium">
                                        {Math.round(schedule.ai_confidence * 100)}%
                                    </span>
                                </div>
                            )}

                            {/* Scanner Configuration */}
                            <div className="flex items-center gap-2">
                                <Settings2 className="h-4 w-4 text-muted-foreground" />
                                <Label className="text-muted-foreground">Scanners:</Label>
                                {hasCustomScanners ? (
                                    <Badge variant="secondary" className="text-xs">
                                        Custom ({customScannerCount} selected)
                                    </Badge>
                                ) : (
                                    <span className="text-muted-foreground text-sm">All scanners (default)</span>
                                )}
                            </div>

                            {/* Locked Info */}
                            {isLocked && schedule.locked_by_email && (
                                <div className="flex items-center gap-2 p-3 bg-amber-500/10 rounded-md border border-amber-500/20">
                                    <Lock className="h-4 w-4 text-amber-500" />
                                    <div className="text-sm">
                                        <span className="text-muted-foreground">Locked by </span>
                                        <span className="font-medium">{schedule.locked_by_email}</span>
                                        {schedule.locked_at && (
                                            <span className="text-muted-foreground">
                                                {" "}on {format(new Date(schedule.locked_at), "PP")}
                                            </span>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    </TabsContent>

                    {/* Lock/Unlock Tab */}
                    <TabsContent value="lock" className="space-y-4 pt-4">
                        {!isLocked ? (
                            /* Lock Form */
                            <div className="space-y-4">
                                <p className="text-sm text-muted-foreground">
                                    Locking this schedule will prevent AI from modifying it.
                                    The current settings will be preserved until manually unlocked.
                                </p>
                                <div className="grid gap-2">
                                    <Label htmlFor="lock-reason">Reason for locking</Label>
                                    <Textarea
                                        id="lock-reason"
                                        placeholder="Enter reason for locking this schedule..."
                                        value={lockReason}
                                        onChange={(e) => setLockReason(e.target.value)}
                                        rows={3}
                                    />
                                </div>
                                <Button
                                    onClick={handleLock}
                                    disabled={isLoading || !lockReason.trim()}
                                    className="w-full"
                                >
                                    {isLoading ? (
                                        <>
                                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                            Locking...
                                        </>
                                    ) : (
                                        <>
                                            <Lock className="mr-2 h-4 w-4" />
                                            Lock Schedule
                                        </>
                                    )}
                                </Button>
                            </div>
                        ) : (
                            /* Unlock Form */
                            <div className="space-y-4">
                                <div className="p-4 bg-amber-500/10 rounded-md border border-amber-500/20">
                                    <p className="text-sm font-medium text-amber-600 dark:text-amber-400 mb-2">
                                        This schedule is currently locked
                                    </p>
                                    {schedule.locked_by_email && (
                                        <p className="text-sm text-muted-foreground">
                                            Locked by: {schedule.locked_by_email}
                                        </p>
                                    )}
                                </div>
                                <p className="text-sm text-muted-foreground">
                                    Unlocking will return this schedule to AI management.
                                    The AI may adjust the schedule based on repository activity patterns.
                                </p>
                                <Button
                                    onClick={handleUnlock}
                                    disabled={isLoading}
                                    variant="outline"
                                    className="w-full"
                                >
                                    {isLoading ? (
                                        <>
                                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                            Unlocking...
                                        </>
                                    ) : (
                                        <>
                                            <Unlock className="mr-2 h-4 w-4" />
                                            Unlock Schedule
                                        </>
                                    )}
                                </Button>
                            </div>
                        )}
                    </TabsContent>

                    {/* Scanners Tab */}
                    <TabsContent value="scanners" className="pt-4">
                        {scannersLoading ? (
                            <div className="flex items-center justify-center py-8">
                                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                            </div>
                        ) : scannersError ? (
                            <div className="text-center py-8 text-destructive">
                                {scannersError}
                            </div>
                        ) : (
                            <div className="space-y-4">
                                {/* Use all scanners toggle */}
                                <div className="flex items-center space-x-2 p-3 bg-muted/30 rounded-md">
                                    <Checkbox
                                        id="use-all-scanners"
                                        checked={useAllScanners}
                                        onCheckedChange={(checked) => {
                                            setUseAllScanners(checked === true)
                                            if (checked) {
                                                setSelectedScanners([])
                                            }
                                        }}
                                    />
                                    <label
                                        htmlFor="use-all-scanners"
                                        className="text-sm font-medium leading-none cursor-pointer"
                                    >
                                        Use all scanners (default)
                                    </label>
                                </div>

                                {/* Scanner categories - only show when not using all */}
                                {!useAllScanners && (
                                    <div className="space-y-2 max-h-[250px] overflow-y-auto">
                                        {CATEGORY_ORDER.map((category) => {
                                            const scanners = scannersByCategory[category]
                                            if (!scanners || scanners.length === 0) return null

                                            const isExpanded = expandedCategories.has(category)
                                            const selectedInCategory = scanners.filter((s) =>
                                                selectedScanners.includes(s.id)
                                            ).length
                                            const allSelected = selectedInCategory === scanners.length

                                            return (
                                                <div key={category} className="border rounded-md">
                                                    {/* Category header */}
                                                    <div
                                                        className="flex items-center justify-between p-2 cursor-pointer hover:bg-muted/50"
                                                        onClick={() => toggleCategory(category)}
                                                    >
                                                        <div className="flex items-center gap-2">
                                                            {isExpanded ? (
                                                                <ChevronDown className="h-4 w-4" />
                                                            ) : (
                                                                <ChevronRight className="h-4 w-4" />
                                                            )}
                                                            <span className="text-sm font-medium">
                                                                {CATEGORY_NAMES[category] || category}
                                                            </span>
                                                            <Badge variant="outline" className="text-xs">
                                                                {selectedInCategory}/{scanners.length}
                                                            </Badge>
                                                        </div>
                                                        <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                                                            <Button
                                                                variant="ghost"
                                                                size="sm"
                                                                className="h-6 px-2 text-xs"
                                                                onClick={() => selectAllInCategory(category)}
                                                                disabled={allSelected}
                                                            >
                                                                All
                                                            </Button>
                                                            <Button
                                                                variant="ghost"
                                                                size="sm"
                                                                className="h-6 px-2 text-xs"
                                                                onClick={() => clearAllInCategory(category)}
                                                                disabled={selectedInCategory === 0}
                                                            >
                                                                Clear
                                                            </Button>
                                                        </div>
                                                    </div>

                                                    {/* Scanners in category */}
                                                    {isExpanded && (
                                                        <div className="p-2 pt-0 space-y-1">
                                                            {scanners.map((scanner) => (
                                                                <div
                                                                    key={scanner.id}
                                                                    className="flex items-start space-x-2 py-1"
                                                                >
                                                                    <Checkbox
                                                                        id={`scanner-${scanner.id}`}
                                                                        checked={selectedScanners.includes(scanner.id)}
                                                                        onCheckedChange={() => toggleScanner(scanner.id)}
                                                                    />
                                                                    <div className="grid gap-0.5">
                                                                        <label
                                                                            htmlFor={`scanner-${scanner.id}`}
                                                                            className="text-sm font-medium leading-none cursor-pointer"
                                                                        >
                                                                            {scanner.name}
                                                                        </label>
                                                                        <p className="text-xs text-muted-foreground">
                                                                            {scanner.description}
                                                                        </p>
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            )
                                        })}
                                    </div>
                                )}

                                {/* Save button */}
                                {onUpdateScanners && (
                                    <Button
                                        onClick={handleSaveScanners}
                                        disabled={scannersSaving || (!useAllScanners && selectedScanners.length === 0)}
                                        className="w-full"
                                    >
                                        {scannersSaving ? (
                                            <>
                                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                                Saving...
                                            </>
                                        ) : (
                                            <>
                                                <Settings2 className="mr-2 h-4 w-4" />
                                                Save Scanner Config
                                            </>
                                        )}
                                    </Button>
                                )}

                                {/* Selection summary */}
                                {!useAllScanners && selectedScanners.length > 0 && (
                                    <p className="text-xs text-muted-foreground text-center">
                                        {selectedScanners.length} scanner{selectedScanners.length !== 1 ? "s" : ""} selected
                                    </p>
                                )}
                            </div>
                        )}
                    </TabsContent>

                    {/* History Tab */}
                    <TabsContent value="history" className="pt-4">
                        {historyLoading ? (
                            <div className="flex items-center justify-center py-8">
                                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                            </div>
                        ) : historyError ? (
                            <div className="text-center py-8 text-destructive">
                                {historyError}
                            </div>
                        ) : history.length === 0 ? (
                            <div className="text-center py-8 text-muted-foreground">
                                No override history found
                            </div>
                        ) : (
                            <div className="space-y-3 max-h-[300px] overflow-y-auto">
                                {history.map((item) => (
                                    <div
                                        key={item.id}
                                        className="p-3 border rounded-md bg-muted/30 space-y-1"
                                    >
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm font-medium">
                                                {item.overridden_by_email}
                                            </span>
                                            <span className="text-xs text-muted-foreground">
                                                {format(new Date(item.created_at), "PP p")}
                                            </span>
                                        </div>
                                        <p className="text-sm text-muted-foreground">
                                            {formatChanges(item)}
                                        </p>
                                        {item.override_reason && (
                                            <p className="text-xs text-muted-foreground italic">
                                                &quot;{item.override_reason}&quot;
                                            </p>
                                        )}
                                    </div>
                                ))}
                            </div>
                        )}
                    </TabsContent>
                </Tabs>

                <DialogFooter>
                    <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isLoading}>
                        Close
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    )
}
