"use client"

/**
 * Review queue for cross-scanner rule merges.
 *
 * Filing groups findings by scanner plus rule id, which files two issues when
 * two scanners report one defect under their own rule names — grype calls it
 * `GHSA-M7JM-9GC2-MPF2`, trivy-fs calls the same advisory `CVE-2024-21538`.
 * An AI pass proposes which rule pairs are really one defect; this page is
 * where a person approves or rejects each proposal.
 *
 * A pending proposal changes nothing. The API reads only approved-and-
 * equivalent rows when it groups findings, so nothing on this page takes
 * effect until it is approved here. That is deliberate: AuditBoard issues
 * cannot be deleted and their descriptions cannot be edited after create, so a
 * wrong merge permanently claims an issue covers a finding it does not
 * describe, while a missed merge only files a duplicate somebody can close.
 *
 * Approving does not change issues already filed. It changes how the next
 * filing groups.
 */

import { useCallback, useEffect, useState } from "react"
import { API_BASE, apiFetch } from "@/lib/api"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageHeader } from "@/components/ui/page-header"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { StatCard } from "@/components/ui/stat-card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useToast } from "@/components/ui/use-toast"
import {
  AlertCircle,
  Check,
  GitMerge,
  Loader2,
  Sparkles,
  Split,
  X,
} from "lucide-react"

interface RuleSide {
  scanner_name: string
  rule_id: string
  key: string
}

interface Equivalence {
  id: string
  rule_a: RuleSide
  rule_b: RuleSide
  pair_key: string
  verdict: "equivalent" | "distinct"
  confidence: number | null
  model: string | null
  rationale: string | null
  evidence: Record<string, unknown> | null
  review_decision: "approved" | "rejected" | null
  reviewed_by: string | null
  review_note: string | null
  affects_grouping: boolean
}

interface Candidate {
  pair_key: string
  rule_a: RuleSide
  rule_b: RuleSide
  shared_repos: number
  shared_locations: number
  sample_paths: string[]
}

interface Stats {
  total: number
  pending: number
  pending_equivalent: number
  approved_equivalent: number
  approved_distinct: number
  rejected: number
  candidates_total: number
  candidates_all_severities: number
  candidates_undecided: number
  min_confidence: number
}

interface ProposeResult {
  asked: number
  equivalent: number
  distinct: number
  downgraded: number
  no_answer: number
  model: string | null
  candidates_remaining: number
}

type StatusFilter = "pending" | "approved" | "rejected" | "all"

const STATUS_LABELS: Record<StatusFilter, string> = {
  pending: "Pending review",
  approved: "Approved",
  rejected: "Rejected",
  all: "All",
}

/** How many pairs one press asks about. Each pair is one AI call. */
const BATCH_SIZES = [5, 10, 25, 50]

function confidenceLabel(value: number | null): string {
  return value === null || value === undefined ? "—" : `${Math.round(value * 100)}%`
}

function evidenceNumber(evidence: Record<string, unknown> | null, key: string): number | null {
  const raw = evidence?.[key]
  return typeof raw === "number" ? raw : null
}

export default function RuleMergesPage() {
  const { toast } = useToast()
  const [stats, setStats] = useState<Stats | null>(null)
  const [rows, setRows] = useState<Equivalence[]>([])
  const [candidates, setCandidates] = useState<Candidate[]>([])
  const [status, setStatus] = useState<StatusFilter>("pending")
  const [loading, setLoading] = useState(true)
  const [proposing, setProposing] = useState(false)
  const [batchSize, setBatchSize] = useState(10)
  const [reviewing, setReviewing] = useState<string | null>(null)
  const [notes, setNotes] = useState<Record<string, string>>({})
  const [error, setError] = useState<string | null>(null)
  const [lastRun, setLastRun] = useState<ProposeResult | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [statsRes, rowsRes, candidateRes] = await Promise.all([
        apiFetch(`${API_BASE}/rule-equivalences/stats`),
        apiFetch(`${API_BASE}/rule-equivalences?status=${status}&limit=200`),
        apiFetch(`${API_BASE}/rule-equivalences/candidates?limit=10`),
      ])
      if (!statsRes.ok) throw new Error(`Stats failed (${statsRes.status})`)
      if (!rowsRes.ok) throw new Error(`Queue failed (${rowsRes.status})`)
      setStats(await statsRes.json())
      setRows(await rowsRes.json())
      // Candidates are a preview, not the point of the page. A failure here
      // must not blank the queue a reviewer came to work through.
      setCandidates(candidateRes.ok ? await candidateRes.json() : [])
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load the review queue")
    } finally {
      setLoading(false)
    }
  }, [status])

  useEffect(() => {
    load()
  }, [load])

  const propose = async () => {
    setProposing(true)
    setError(null)
    try {
      const res = await apiFetch(`${API_BASE}/rule-equivalences/propose`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit: batchSize }),
      })
      if (!res.ok) {
        const detail = await res.json().catch(() => null)
        throw new Error(detail?.detail || `Proposal run failed (${res.status})`)
      }
      const result: ProposeResult = await res.json()
      setLastRun(result)
      toast({
        title: `Asked about ${result.asked} rule pair${result.asked === 1 ? "" : "s"}`,
        description:
          `${result.equivalent} proposed as one defect, ${result.distinct} as separate` +
          (result.no_answer ? `, ${result.no_answer} with no usable answer` : "") +
          ". Nothing is merged until it is approved here.",
      })
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Proposal run failed")
    } finally {
      setProposing(false)
    }
  }

  const review = async (row: Equivalence, decision: "approved" | "rejected") => {
    setReviewing(row.id)
    try {
      const res = await apiFetch(`${API_BASE}/rule-equivalences/${row.id}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision, note: notes[row.id] || null }),
      })
      if (!res.ok) {
        const detail = await res.json().catch(() => null)
        throw new Error(detail?.detail || `Review failed (${res.status})`)
      }
      const merged = decision === "approved" && row.verdict === "equivalent"
      toast({
        title: merged ? "Rules merged for filing" : `Proposal ${decision}`,
        description: merged
          ? `${row.rule_a.key} and ${row.rule_b.key} will file as one defect from now on. Issues already filed are unchanged.`
          : "Grouping is unchanged; the pair will not be asked about again.",
      })
      await load()
    } catch (err) {
      toast({
        title: "Review failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      })
    } finally {
      setReviewing(null)
    }
  }

  const askedShare =
    stats && stats.candidates_total > 0
      ? Math.round(((stats.candidates_total - stats.candidates_undecided) / stats.candidates_total) * 100)
      : 0

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="AI Management"
        title="Rule Merges"
        icon={GitMerge}
        description={
          <>
            Two scanners can report one defect under two rule names, which files two
            issues. An AI pass proposes which rule pairs are the same defect; approving
            one here makes future filings group them together. Nothing takes effect
            until it is approved, and issues already filed are never changed.
          </>
        }
        actions={
          <div className="flex items-center gap-2">
            <Select value={String(batchSize)} onValueChange={(v) => setBatchSize(Number(v))}>
              <SelectTrigger className="w-[130px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {BATCH_SIZES.map((size) => (
                  <SelectItem key={size} value={String(size)}>
                    {size} pairs
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button onClick={propose} disabled={proposing || loading}>
              {proposing ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Sparkles className="mr-2 h-4 w-4" />
              )}
              Ask the AI
            </Button>
          </div>
        }
      />

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Could not complete that</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard
          label="Waiting on review"
          value={stats?.pending ?? "—"}
          hint={`${stats?.pending_equivalent ?? 0} propose a merge`}
          icon={GitMerge}
          tone={stats && stats.pending_equivalent > 0 ? "warning" : "neutral"}
          loading={loading}
        />
        <StatCard
          label="Merging today"
          value={stats?.approved_equivalent ?? "—"}
          hint="Approved pairs that group findings"
          icon={Check}
          tone="success"
          loading={loading}
        />
        <StatCard
          label="Kept separate"
          value={(stats?.approved_distinct ?? 0) + (stats?.rejected ?? 0)}
          hint="Decided not to be one defect"
          icon={Split}
          loading={loading}
        />
        <StatCard
          label="Pairs not yet asked"
          value={stats?.candidates_undecided ?? "—"}
          hint={`${askedShare}% of ${stats?.candidates_total ?? 0} candidates covered`}
          icon={Sparkles}
          loading={loading}
        />
      </div>

      {stats && (
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>What is counted here</AlertTitle>
          <AlertDescription>
            {stats.candidates_total} rule pairs are candidates: pairs from different
            scanners that both report findings at the same file in the same project, at
            a severity that can be filed as a group. Ignoring the severity floor there
            are {stats.candidates_all_severities}. Co-location is only why a pair is
            worth asking about — two unrelated defects in one{" "}
            <code>package-lock.json</code> co-locate perfectly. A verdict of{" "}
            <em>equivalent</em> below {Math.round(stats.min_confidence * 100)}% confidence
            is recorded as <em>distinct</em>, so an unsure model never merges anything.
          </AlertDescription>
        </Alert>
      )}

      {lastRun && lastRun.no_answer > 0 && (
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>
            {lastRun.no_answer} pair{lastRun.no_answer === 1 ? "" : "s"} gave no usable answer
          </AlertTitle>
          <AlertDescription>
            Nothing was recorded for those, so they stay separate and stay candidates.
            Pressing Ask the AI again retries them.
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-4">
          <CardTitle>Proposals</CardTitle>
          <Select value={status} onValueChange={(v) => setStatus(v as StatusFilter)}>
            <SelectTrigger className="w-[180px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {(Object.keys(STATUS_LABELS) as StatusFilter[]).map((key) => (
                <SelectItem key={key} value={key}>
                  {STATUS_LABELS[key]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="mr-2 h-5 w-5 animate-spin" /> Loading proposals
            </div>
          ) : rows.length === 0 ? (
            <EmptyState
              icon={GitMerge}
              title={
                status === "pending" ? "Nothing waiting on review" : "No proposals here"
              }
              description={
                status === "pending"
                  ? `${stats?.candidates_undecided ?? 0} candidate pairs have not been asked about yet. Ask the AI to fill the queue.`
                  : "Change the filter to see proposals in another state."
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule pair</TableHead>
                  <TableHead>Proposed</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Overlap</TableHead>
                  <TableHead>Why</TableHead>
                  <TableHead className="text-right">Decision</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((row) => {
                  const repos = evidenceNumber(row.evidence, "shared_repos")
                  const locations = evidenceNumber(row.evidence, "shared_locations")
                  const downgraded = row.evidence?.["downgraded_from"]
                  return (
                    <TableRow key={row.id}>
                      <TableCell className="align-top">
                        <div className="font-mono text-xs leading-relaxed">
                          <div>{row.rule_a.key}</div>
                          <div className="text-muted-foreground">{row.rule_b.key}</div>
                        </div>
                      </TableCell>
                      <TableCell className="align-top">
                        <Badge
                          variant="outline"
                          className={
                            row.verdict === "equivalent"
                              ? "bg-warning/15 text-warning-text border-warning/20"
                              : "bg-muted text-muted-foreground"
                          }
                        >
                          {row.verdict === "equivalent" ? "One defect" : "Separate"}
                        </Badge>
                        {row.affects_grouping && (
                          <div className="mt-1 text-xs text-success-text">
                            Grouping findings now
                          </div>
                        )}
                        {row.review_decision && !row.affects_grouping && (
                          <div className="mt-1 text-xs text-muted-foreground">
                            {row.review_decision}
                            {row.reviewed_by ? ` by ${row.reviewed_by}` : ""}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="align-top">
                        {confidenceLabel(row.confidence)}
                        {downgraded ? (
                          <div className="mt-1 text-xs text-muted-foreground">
                            answered &quot;{String(downgraded)}&quot;, below the floor
                          </div>
                        ) : null}
                        {row.model ? (
                          <div className="mt-1 max-w-[12rem] truncate text-xs text-muted-foreground">
                            {row.model}
                          </div>
                        ) : (
                          <div className="mt-1 text-xs text-muted-foreground">by hand</div>
                        )}
                      </TableCell>
                      <TableCell className="align-top text-sm">
                        {locations === null ? (
                          "—"
                        ) : (
                          <>
                            {locations} place{locations === 1 ? "" : "s"}
                            <div className="text-xs text-muted-foreground">
                              in {repos ?? 0} project{repos === 1 ? "" : "s"}
                            </div>
                          </>
                        )}
                      </TableCell>
                      <TableCell className="max-w-md align-top text-sm text-muted-foreground">
                        {row.rationale || "No rationale recorded"}
                        {row.review_note ? (
                          <div className="mt-1 text-xs">Note: {row.review_note}</div>
                        ) : null}
                      </TableCell>
                      <TableCell className="align-top text-right">
                        {row.review_decision ? (
                          <span className="text-xs text-muted-foreground">
                            Decided{row.reviewed_by ? ` by ${row.reviewed_by}` : ""}
                          </span>
                        ) : (
                          <div className="flex flex-col items-end gap-2">
                            <Input
                              placeholder="Note (optional)"
                              value={notes[row.id] ?? ""}
                              onChange={(e) =>
                                setNotes((prev) => ({ ...prev, [row.id]: e.target.value }))
                              }
                              className="h-8 w-40 text-xs"
                            />
                            <div className="flex gap-2">
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={reviewing === row.id}
                                onClick={() => review(row, "rejected")}
                              >
                                <X className="mr-1 h-3 w-3" /> Reject
                              </Button>
                              <Button
                                size="sm"
                                disabled={reviewing === row.id}
                                onClick={() => review(row, "approved")}
                              >
                                {reviewing === row.id ? (
                                  <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                                ) : (
                                  <Check className="mr-1 h-3 w-3" />
                                )}
                                Approve
                              </Button>
                            </div>
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {candidates.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Next pairs in line ({stats?.candidates_undecided ?? candidates.length} undecided)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule pair</TableHead>
                  <TableHead>Overlap</TableHead>
                  <TableHead>Example paths</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {candidates.map((candidate) => (
                  <TableRow key={candidate.pair_key}>
                    <TableCell className="font-mono text-xs">
                      <div>{candidate.rule_a.key}</div>
                      <div className="text-muted-foreground">{candidate.rule_b.key}</div>
                    </TableCell>
                    <TableCell className="text-sm">
                      {candidate.shared_locations} place
                      {candidate.shared_locations === 1 ? "" : "s"} in{" "}
                      {candidate.shared_repos} project
                      {candidate.shared_repos === 1 ? "" : "s"}
                    </TableCell>
                    <TableCell className="max-w-md truncate font-mono text-xs text-muted-foreground">
                      {candidate.sample_paths.join(", ") || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
