"use client"

import { useState } from "react"
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
import { Checkbox } from "@/components/ui/checkbox"
import { Loader2, ShieldCheck, AlertTriangle } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"

interface ExceptionDialogProps {
    findingId: string
    scannerName: string
    onSuccess?: () => void
}

export function ExceptionDialog({ findingId, scannerName, onSuccess }: ExceptionDialogProps) {
    const [open, setOpen] = useState(false)
    const [scope, setScope] = useState("specific")
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)

    // State Machine
    const [step, setStep] = useState<"input" | "review" | "verify" | "deleted">("input")

    const [generatedRule, setGeneratedRule] = useState<any>(null)
    const [dryRunResult, setDryRunResult] = useState<any>(null)
    const [deletionResult, setDeletionResult] = useState<any>(null)

    const resetState = () => {
        setStep("input")
        setGeneratedRule(null)
        setDryRunResult(null)
        setDeletionResult(null)
        setError(null)
        setScope("specific")
    }

    // Step 1: Generate Rule
    const handleGenerateRule = async () => {
        setLoading(true)
        setError(null)
        try {
            const res = await fetch(`/api/findings/${findingId}/exception`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scope, delete_finding: false }),
            })
            if (!res.ok) throw new Error("Failed to generate rule")
            const data = await res.json()
            setGeneratedRule(data)
            setStep("review")
        } catch (err: any) {
            setError(err.message)
        } finally {
            setLoading(false)
        }
    }

    // Step 2: Verify Deletion (Dry Run)
    const handleVerifyDeletion = async () => {
        setLoading(true)
        setError(null)
        try {
            const res = await fetch(`/api/findings/${findingId}/exception`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scope, delete_finding: true, dry_run: true }),
            })
            if (!res.ok) throw new Error("Failed to verify deletion")
            const data = await res.json()
            setDryRunResult(data)
            setStep("verify")
        } catch (err: any) {
            setError(err.message)
        } finally {
            setLoading(false)
        }
    }

    // Step 3: Confirm Deletion
    const handleConfirmDeletion = async () => {
        setLoading(true)
        setError(null)
        try {
            const res = await fetch(`/api/findings/${findingId}/exception`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scope, delete_finding: true, dry_run: false }),
            })
            if (!res.ok) throw new Error("Failed to delete findings")
            const data = await res.json()
            setDeletionResult(data)
            setStep("deleted")
            if (onSuccess) onSuccess()
        } catch (err: any) {
            setError(err.message)
        } finally {
            setLoading(false)
        }
    }

    return (
        <Dialog open={open} onOpenChange={(val) => {
            setOpen(val)
            if (!val) setTimeout(resetState, 300) // Reset after animation
        }}>
            <DialogTrigger asChild>
                <Button variant="outline">Create Exception</Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[500px]">
                <DialogHeader>
                    <DialogTitle>Create Exception Rule</DialogTitle>
                    <DialogDescription>
                        Use AI to generate an exception rule for this {scannerName} finding.
                    </DialogDescription>
                </DialogHeader>

                {step === "input" && (
                    <div className="grid gap-6 py-4">
                        <div className="space-y-4">
                            <Label>Exception Scope</Label>
                            <RadioGroup defaultValue="specific" value={scope} onValueChange={setScope}>
                                <div className="flex items-center space-x-2">
                                    <RadioGroupItem value="specific" id="specific" />
                                    <Label htmlFor="specific">Specific (This finding only)</Label>
                                </div>
                                <div className="flex items-center space-x-2">
                                    <RadioGroupItem value="global" id="global" />
                                    <Label htmlFor="global">Global (All matching findings in this location)</Label>
                                </div>
                            </RadioGroup>
                        </div>
                        {error && <div className="text-sm text-red-500 bg-red-50 p-2 rounded">Error: {error}</div>}
                    </div>
                )}

                {step === "review" && generatedRule && (
                    <div className="space-y-4 py-4">
                        <Alert className="bg-blue-50 border-blue-200">
                            <ShieldCheck className="h-4 w-4 text-blue-600" />
                            <AlertTitle className="text-blue-800">Rule Generated</AlertTitle>
                            <AlertDescription className="text-blue-700">
                                Review the generated rule below.
                            </AlertDescription>
                        </Alert>
                        <div className="space-y-2">
                            <Label>Generated Rule ({generatedRule.rule.format})</Label>
                            <pre className="bg-slate-950 text-slate-50 p-4 rounded-md overflow-x-auto text-xs">
                                {JSON.stringify(generatedRule.rule.rule, null, 2)}
                            </pre>
                            <p className="text-sm text-muted-foreground mt-2">
                                {generatedRule.rule.instruction}
                            </p>
                        </div>
                    </div>
                )}

                {step === "verify" && dryRunResult && (
                    <div className="space-y-4 py-4">
                        <Alert className="bg-yellow-50 border-yellow-200">
                            <AlertTriangle className="h-4 w-4 text-yellow-600" />
                            <AlertTitle className="text-yellow-800">Verify Deletion</AlertTitle>
                            <AlertDescription className="text-yellow-700">
                                This action will delete <strong>{dryRunResult.deleted_count}</strong> finding(s) from the database.
                                <br />
                                {dryRunResult.message}
                            </AlertDescription>
                        </Alert>
                    </div>
                )}

                {step === "deleted" && deletionResult && (
                    <div className="space-y-4 py-4">
                        <Alert className="bg-green-50 border-green-200">
                            <ShieldCheck className="h-4 w-4 text-green-600" />
                            <AlertTitle className="text-green-800">Success</AlertTitle>
                            <AlertDescription className="text-green-700">
                                {deletionResult.message}
                            </AlertDescription>
                        </Alert>
                        <p className="text-sm font-medium">
                            Deleted {deletionResult.deleted_count} finding(s).
                        </p>
                    </div>
                )}

                <DialogFooter>
                    {step === "input" && (
                        <Button onClick={handleGenerateRule} disabled={loading}>
                            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            Generate Rule
                        </Button>
                    )}

                    {step === "review" && (
                        <>
                            <Button variant="outline" onClick={() => setOpen(false)}>Close</Button>
                            <Button variant="destructive" onClick={handleVerifyDeletion} disabled={loading}>
                                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                Delete Finding(s)
                            </Button>
                        </>
                    )}

                    {step === "verify" && (
                        <>
                            <Button variant="outline" onClick={() => setStep("review")}>Cancel</Button>
                            <Button variant="destructive" onClick={handleConfirmDeletion} disabled={loading}>
                                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                Confirm Delete
                            </Button>
                        </>
                    )}

                    {step === "deleted" && (
                        <Button onClick={() => setOpen(false)}>Close</Button>
                    )}
                </DialogFooter>
            </DialogContent>
        </Dialog>
    )
}
