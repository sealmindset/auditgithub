"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Loader2, ShieldOff, Trash2, AlertTriangle, Copy, Check } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"

const API_BASE = "http://localhost:8000"

interface ExceptionDialogProps {
    finding: any
    onDeleted?: () => void
}

interface ExceptionRule {
    scanner_name: string
    rule_type: string
    rule_content: string
    instruction: string
    affected_count: number
}

interface DryRunResult {
    count: number
    scanner_name: string
    file_path: string | null
    sample_findings: Array<{
        id: string
        title: string
        file_path: string
        scanner_name: string
    }>
}

export function ExceptionDialog({ finding, onDeleted }: ExceptionDialogProps) {
    const [open, setOpen] = useState(false)
    const [scope, setScope] = useState<"specific" | "global">("specific")
    const [reason, setReason] = useState("")

    // Rule generation state
    const [generatingRule, setGeneratingRule] = useState(false)
    const [exceptionRule, setExceptionRule] = useState<ExceptionRule | null>(null)

    // Deletion state
    const [dryRunning, setDryRunning] = useState(false)
    const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null)
    const [deleting, setDeleting] = useState(false)
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

    const [copied, setCopied] = useState(false)
    const { toast } = useToast()

    const resetState = () => {
        setScope("specific")
        setReason("")
        setExceptionRule(null)
        setDryRunResult(null)
        setShowDeleteConfirm(false)
    }

    const generateRule = async () => {
        setGeneratingRule(true)
        setExceptionRule(null)

        try {
            const res = await fetch(`${API_BASE}/findings/exception/generate`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    finding_id: finding.id,
                    scope: scope,
                    reason: reason || undefined
                })
            })

            if (!res.ok) {
                const err = await res.json()
                throw new Error(err.detail || "Failed to generate exception rule")
            }

            const data = await res.json()
            setExceptionRule(data)
            toast({ title: "Rule Generated", description: "Exception rule generated successfully." })
        } catch (err) {
            toast({
                title: "Error",
                description: err instanceof Error ? err.message : "Failed to generate rule",
                variant: "destructive"
            })
        } finally {
            setGeneratingRule(false)
        }
    }

    const runDryDelete = async () => {
        setDryRunning(true)
        setDryRunResult(null)

        try {
            const res = await fetch(`${API_BASE}/findings/exception/delete/dry-run`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    finding_id: finding.id,
                    scope: scope
                })
            })

            if (!res.ok) {
                const err = await res.json()
                throw new Error(err.detail || "Failed to run dry delete")
            }

            const data = await res.json()
            setDryRunResult(data)
            setShowDeleteConfirm(true)
        } catch (err) {
            toast({
                title: "Error",
                description: err instanceof Error ? err.message : "Failed to verify deletion",
                variant: "destructive"
            })
        } finally {
            setDryRunning(false)
        }
    }

    const confirmDelete = async () => {
        setDeleting(true)

        try {
            const res = await fetch(`${API_BASE}/findings/exception/delete`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    finding_id: finding.id,
                    scope: scope,
                    confirmed: true
                })
            })

            if (!res.ok) {
                const err = await res.json()
                throw new Error(err.detail || "Failed to delete findings")
            }

            const data = await res.json()
            toast({
                title: "Deleted",
                description: data.message
            })
            setOpen(false)
            resetState()
            onDeleted?.()
        } catch (err) {
            toast({
                title: "Error",
                description: err instanceof Error ? err.message : "Failed to delete findings",
                variant: "destructive"
            })
        } finally {
            setDeleting(false)
        }
    }

    const copyToClipboard = async (text: string) => {
        await navigator.clipboard.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        toast({ title: "Copied", description: "Rule copied to clipboard." })
    }

    return (
        <Dialog open={open} onOpenChange={(isOpen) => {
            setOpen(isOpen)
            if (!isOpen) resetState()
        }}>
            <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2">
                    <ShieldOff className="h-4 w-4" />
                    Create Exception
                </Button>
            </DialogTrigger>
            <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
                <DialogHeader>
                    <DialogTitle>Exception Management</DialogTitle>
                    <DialogDescription>
                        Generate an exception rule or delete this finding from the database.
                    </DialogDescription>
                </DialogHeader>

                <div className="flex-1 overflow-y-auto space-y-6 py-4">
                    {/* Finding Summary */}
                    <div className="rounded-md border p-4 bg-muted/50">
                        <div className="flex items-center justify-between">
                            <div>
                                <h4 className="font-medium">{finding.title}</h4>
                                <p className="text-sm text-muted-foreground">{finding.file_path}</p>
                            </div>
                            <div className="flex items-center gap-2">
                                <Badge variant="outline">{finding.scanner_name}</Badge>
                                <Badge className={
                                    finding.severity === "Critical" ? "bg-red-500" :
                                    finding.severity === "High" ? "bg-orange-500" : "bg-blue-500"
                                }>
                                    {finding.severity}
                                </Badge>
                            </div>
                        </div>
                    </div>

                    {/* Scope Selection */}
                    <div className="space-y-3">
                        <Label className="text-base font-semibold">Exception Scope</Label>
                        <RadioGroup value={scope} onValueChange={(v) => setScope(v as "specific" | "global")}>
                            <div className="flex items-start space-x-3 p-3 rounded-md border hover:bg-muted/50 cursor-pointer">
                                <RadioGroupItem value="specific" id="specific" className="mt-1" />
                                <div className="flex-1">
                                    <Label htmlFor="specific" className="font-medium cursor-pointer">Specific</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Apply exception only to this specific finding instance.
                                    </p>
                                </div>
                            </div>
                            <div className="flex items-start space-x-3 p-3 rounded-md border hover:bg-muted/50 cursor-pointer">
                                <RadioGroupItem value="global" id="global" className="mt-1" />
                                <div className="flex-1">
                                    <Label htmlFor="global" className="font-medium cursor-pointer">Global</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Apply to all findings from <strong>{finding.scanner_name}</strong> in <strong>{finding.file_path}</strong>
                                    </p>
                                </div>
                            </div>
                        </RadioGroup>
                    </div>

                    {/* Reason (Optional) */}
                    <div className="space-y-2">
                        <Label htmlFor="reason">Reason (Optional)</Label>
                        <Textarea
                            id="reason"
                            placeholder="Why is this a false positive or accepted risk?"
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                            className="resize-none"
                            rows={2}
                        />
                    </div>

                    {/* Actions */}
                    <div className="flex gap-3">
                        <Button onClick={generateRule} disabled={generatingRule}>
                            {generatingRule ? (
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            ) : (
                                <ShieldOff className="mr-2 h-4 w-4" />
                            )}
                            Generate Rule
                        </Button>
                        <Button variant="destructive" onClick={runDryDelete} disabled={dryRunning}>
                            {dryRunning ? (
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            ) : (
                                <Trash2 className="mr-2 h-4 w-4" />
                            )}
                            Delete Finding(s)
                        </Button>
                    </div>

                    {/* Generated Rule Display */}
                    {exceptionRule && (
                        <div className="space-y-3 rounded-md border p-4">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h4 className="font-semibold">Generated Exception Rule</h4>
                                    <p className="text-sm text-muted-foreground">
                                        {exceptionRule.rule_type} for {exceptionRule.scanner_name}
                                        {exceptionRule.affected_count > 1 && (
                                            <span className="ml-2 text-orange-500">
                                                ({exceptionRule.affected_count} findings affected)
                                            </span>
                                        )}
                                    </p>
                                </div>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => copyToClipboard(exceptionRule.rule_content)}
                                >
                                    {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                                </Button>
                            </div>
                            <pre className="overflow-x-auto rounded-md bg-slate-950 p-4 text-sm text-slate-50">
                                <code>{exceptionRule.rule_content}</code>
                            </pre>
                            <Alert>
                                <AlertTitle>Instructions</AlertTitle>
                                <AlertDescription>{exceptionRule.instruction}</AlertDescription>
                            </Alert>
                        </div>
                    )}

                    {/* Delete Confirmation */}
                    {showDeleteConfirm && dryRunResult && (
                        <Alert variant="destructive">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertTitle>Confirm Deletion</AlertTitle>
                            <AlertDescription className="space-y-3">
                                <p>
                                    This action will delete <strong>{dryRunResult.count}</strong> finding(s)
                                    from <strong>{dryRunResult.scanner_name}</strong>
                                    {dryRunResult.file_path && <> in <code>{dryRunResult.file_path}</code></>}.
                                </p>
                                {dryRunResult.sample_findings.length > 0 && (
                                    <div className="text-sm">
                                        <p className="font-medium mb-1">Sample findings to be deleted:</p>
                                        <ul className="list-disc list-inside space-y-1">
                                            {dryRunResult.sample_findings.map((f) => (
                                                <li key={f.id} className="truncate">
                                                    {f.title} - {f.file_path}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}
                                <div className="flex gap-2 mt-4">
                                    <Button
                                        variant="destructive"
                                        size="sm"
                                        onClick={confirmDelete}
                                        disabled={deleting}
                                    >
                                        {deleting ? (
                                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        ) : null}
                                        Confirm & Delete
                                    </Button>
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => setShowDeleteConfirm(false)}
                                    >
                                        Cancel
                                    </Button>
                                </div>
                            </AlertDescription>
                        </Alert>
                    )}
                </div>
            </DialogContent>
        </Dialog>
    )
}
