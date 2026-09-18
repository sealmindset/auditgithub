"use client";

/**
 * Report a hand-picked selection of findings to AuditBoard as one GRC issue.
 *
 * The tier dialog (`AuditBoardIssueDialog`) files at `specific`, `project` or
 * `org` — three scopes that are *rules*, so the server re-derives what each
 * issue covers from the issue row. This one files at `selection`: the ticked
 * rows and nothing else, with the membership written down server-side because
 * there is no rule that could reproduce it.
 *
 * One press still files exactly one issue. Ten ticked findings become one
 * record listing ten locations, not ten records.
 *
 * Two guards this dialog carries that the tier dialog does not need:
 *
 *   * **The expected count travels with the request.** The findings table
 *     holds a capped slice of the database and filters over it in the browser,
 *     so "everything matching my filters" on screen is not everything matching
 *     in the database. The server refuses the request if a different number of
 *     findings resolves than the filer was shown.
 *   * **Filing is blocked behind an acknowledgement while the table is
 *     truncated.** If the table has not loaded every finding, a selection made
 *     with a filter cannot be the complete answer to that filter, and an
 *     AuditBoard issue cannot be deleted or its description edited afterwards.
 *
 * Every figure shown is measured by the server, by the same service the filing
 * endpoint counts with. Nothing here is counted in the browser.
 *
 * The AuditBoard credential never reaches the browser. This component talks
 * only to our API.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCopy,
  ExternalLink,
  Loader2,
  ShieldAlert,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useToast } from "@/components/ui/use-toast";
import { API_BASE, apiFetch } from "@/lib/api";
import { normalizeSeverity, severityLabel, SEVERITY_TONE } from "@/lib/severity";
import {
  EMPTY_AUDITBOARD_CONFIG,
  ESCALATED_DEFICIENCY_LEVEL_IDS,
  type AuditBoardConfig,
  type AuditBoardIssueResult,
} from "@/lib/auditboard";
import type { FindingLike } from "@/lib/finding-issue";
import {
  buildSelectionDescription,
  buildSelectionExecutiveSummary,
  buildSelectionSummary,
  type SelectionPreview,
} from "@/lib/selection-issue";

interface SelectionAuditBoardDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The ticked rows, already narrowed to those passing the current filters. */
  findings: FindingLike[];
  /** True when the table holds fewer findings than the database does. */
  tableTruncated?: boolean;
  /** Rows loaded into the table, for the truncation wording. */
  loadedCount?: number;
  /** Findings in the database, for the truncation wording. */
  totalCount?: number;
  /** Called after AuditBoard confirms a create. */
  onFiled?: () => void;
}

export function SelectionAuditBoardDialog({
  open,
  onOpenChange,
  findings,
  tableTruncated = false,
  loadedCount,
  totalCount,
  onFiled,
}: SelectionAuditBoardDialogProps) {
  const { toast } = useToast();

  const [config, setConfig] = useState<AuditBoardConfig | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);

  const [preview, setPreview] = useState<SelectionPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const [levelOverride, setLevelOverride] = useState<number | null>(null);
  // Null means "use the generated line", so a scope change still refreshes the
  // suggestion while an edit a person actually typed survives it.
  const [summaryEdit, setSummaryEdit] = useState<string | null>(null);
  const [summaryLineEdit, setSummaryLineEdit] = useState<string | null>(null);

  const [acknowledgedTruncation, setAcknowledgedTruncation] = useState(false);
  const [includeIneligible, setIncludeIneligible] = useState(false);

  // Armed-then-confirmed, because the next click writes to a system of record
  // that cannot delete what it is given.
  const [armed, setArmed] = useState(false);
  const [filing, setFiling] = useState(false);
  const [filingError, setFilingError] = useState<string | null>(null);
  const [result, setResult] = useState<AuditBoardIssueResult | null>(null);

  const findingIds = useMemo(
    () => findings.map((f) => String(f.id ?? "")).filter(Boolean),
    [findings],
  );

  /**
   * Availability and vocabulary. Carries no credential — only whether filing
   * works and which deficiency levels this instance defines.
   */
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    apiFetch(`${API_BASE}/findings/auditboard/config`)
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then((data: AuditBoardConfig) => {
        if (!cancelled) {
          setConfig(data);
          setConfigError(data.problem ?? null);
        }
      })
      .catch((err: Error) => {
        if (!cancelled) setConfigError(`Could not read the AuditBoard configuration: ${err.message}`);
      });
    return () => {
      cancelled = true;
    };
  }, [open]);

  /** Measure the selection server-side. Read-only; calls nothing external. */
  useEffect(() => {
    if (!open || findingIds.length === 0) return;
    let cancelled = false;
    setPreviewLoading(true);
    setPreviewError(null);
    apiFetch(`${API_BASE}/findings/selection/preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_ids: findingIds }),
    })
      .then(async (res) => {
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body?.detail || `HTTP ${res.status}`);
        }
        return res.json();
      })
      .then((data: SelectionPreview) => {
        if (!cancelled) setPreview(data);
      })
      .catch((err: Error) => {
        if (!cancelled) setPreviewError(err.message);
      })
      .finally(() => {
        if (!cancelled) setPreviewLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, findingIds]);

  // Reset per opening. Leaving an acknowledgement or an arm ticked from a
  // previous selection would let a second, different set be filed on a
  // decision made about the first.
  useEffect(() => {
    if (open) return;
    setArmed(false);
    setResult(null);
    setFilingError(null);
    setAcknowledgedTruncation(false);
    setIncludeIneligible(false);
    setSummaryEdit(null);
    setSummaryLineEdit(null);
    setLevelOverride(null);
    setPreview(null);
  }, [open]);

  const generatedTitle = useMemo(
    () => buildSelectionSummary(findings, preview),
    [findings, preview],
  );
  const generatedDescription = useMemo(
    () =>
      buildSelectionDescription(findings, preview, {
        appOrigin: typeof window === "undefined" ? null : window.location.origin,
      }),
    [findings, preview],
  );
  const generatedExecutiveSummary = useMemo(
    () => buildSelectionExecutiveSummary(findings, preview),
    [findings, preview],
  );

  const title = summaryEdit ?? generatedTitle;
  const executiveSummary = summaryLineEdit ?? generatedExecutiveSummary;

  const severity = preview?.severity ? normalizeSeverity(preview.severity) : null;
  const defaultLevelId = severity
    ? (config?.default_deficiency_levels?.[severity] ?? null)
    : null;
  const effectiveLevelId = levelOverride ?? defaultLevelId;
  const effectiveLevelName =
    (config?.deficiency_levels ?? []).find((l) => l.id === effectiveLevelId)?.name ?? null;
  const escalated =
    effectiveLevelId !== null && ESCALATED_DEFICIENCY_LEVEL_IDS.has(effectiveLevelId);

  const count = preview?.finding_count ?? findings.length;
  const alreadyFiled = preview?.already_filed?.length ?? 0;
  const ineligible = preview?.ineligible?.length ?? 0;
  const missing = preview?.missing_ids?.length ?? 0;

  const truncationBlocks = tableTruncated && !acknowledgedTruncation;
  const canFile =
    !filing &&
    !previewLoading &&
    !previewError &&
    !configError &&
    config?.enabled === true &&
    count > 0 &&
    missing === 0 &&
    (ineligible === 0 || includeIneligible) &&
    !truncationBlocks;

  const file = useCallback(async () => {
    setFiling(true);
    setFilingError(null);
    try {
      const res = await apiFetch(`${API_BASE}/findings/selection/auditboard-issue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_ids: findingIds,
          // The number the filer was shown, not the length of the array. If
          // the two disagree the server refuses rather than filing short.
          expected_count: count,
          title,
          description: generatedDescription,
          deficiency_level_id: levelOverride,
          executive_summary: executiveSummary,
          include_ineligible: includeIneligible,
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body?.detail || `AuditBoard filing failed (HTTP ${res.status})`);
      }
      const created = body as AuditBoardIssueResult;
      setResult(created);
      setArmed(false);
      toast({
        title: "Filed to AuditBoard",
        description: created.issue_id
          ? `Issue ${created.issue_id} at ${created.deficiency_level_name}, covering ${created.occurrence_count} finding(s).`
          : `Filed at ${created.deficiency_level_name}.`,
      });
      onFiled?.();
    } catch (err) {
      setFilingError(err instanceof Error ? err.message : String(err));
      setArmed(false);
    } finally {
      setFiling(false);
    }
  }, [
    findingIds,
    count,
    title,
    generatedDescription,
    levelOverride,
    executiveSummary,
    includeIneligible,
    toast,
    onFiled,
  ]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5" />
            Report {count} selected finding{count === 1 ? "" : "s"} to AuditBoard
          </DialogTitle>
          <DialogDescription>
            One issue covering exactly these findings. It will not cover other
            occurrences of the same defects, and it cannot be deleted once created.
          </DialogDescription>
        </DialogHeader>

        {result ? (
          <div className="space-y-4">
            <Alert>
              <CheckCircle2 className="h-4 w-4" />
              <AlertTitle>Issue created</AlertTitle>
              <AlertDescription>
                Filed at <strong>{result.deficiency_level_name}</strong>, covering{" "}
                <strong>{result.occurrence_count}</strong> finding(s) across{" "}
                <strong>{result.project_count}</strong> project(s),{" "}
                <strong>{result.location_count}</strong> location(s) listed
                {result.locations_omitted > 0 && (
                  <> ({result.locations_omitted} omitted for length)</>
                )}
                .
              </AlertDescription>
            </Alert>
            {result.issue_url && (
              <Button asChild variant="outline">
                <a href={result.issue_url} target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Open {result.issue_id ? `issue ${result.issue_id}` : "the issue"} in AuditBoard
                </a>
              </Button>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            {configError && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>AuditBoard filing is unavailable</AlertTitle>
                <AlertDescription>{configError}</AlertDescription>
              </Alert>
            )}

            {previewError && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>The selection could not be measured</AlertTitle>
                <AlertDescription>
                  {previewError}. Nothing has been filed.
                </AlertDescription>
              </Alert>
            )}

            {/* Measured coverage. Every number here came from the server. */}
            <div className="rounded-md border p-3 text-sm space-y-1">
              <div className="flex items-center gap-2 font-medium">
                {previewLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Measuring the selection…
                  </>
                ) : (
                  <>
                    Coverage
                    {severity && (
                      <Badge variant="outline" className={SEVERITY_TONE[severity].soft}>
                        {severityLabel(severity)}
                      </Badge>
                    )}
                  </>
                )}
              </div>
              {preview && (
                <ul className="text-muted-foreground space-y-0.5">
                  <li>
                    <strong>{preview.finding_count}</strong> finding(s) in{" "}
                    <strong>{preview.project_count}</strong> project(s),{" "}
                    <strong>{preview.location_count}</strong> distinct location(s)
                    {preview.locations_omitted > 0 && (
                      <> — {preview.locations_omitted} will be omitted from the body for length</>
                    )}
                  </li>
                  <li>
                    <strong>{preview.identity_keys.length}</strong> distinct defect(s),
                    rated at the highest severity present
                  </li>
                  {alreadyFiled > 0 && (
                    <li className="text-warning-text">
                      {alreadyFiled} of these are already covered by an existing
                      AuditBoard issue. Filing again creates a second record, and
                      neither can be deleted.
                    </li>
                  )}
                </ul>
              )}
            </div>

            {/* The table cap. This is the gate, not a note. */}
            {tableTruncated && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>The findings table is not showing everything</AlertTitle>
                <AlertDescription className="space-y-2">
                  <p>
                    {loadedCount != null && totalCount != null ? (
                      <>
                        This table has loaded <strong>{loadedCount.toLocaleString()}</strong> of{" "}
                        <strong>{totalCount.toLocaleString()}</strong> findings, and filters are
                        applied to the loaded rows only.
                      </>
                    ) : (
                      <>
                        This table holds only part of the database, and filters are applied to
                        the loaded rows only.
                      </>
                    )}{" "}
                    So a selection made with a filter is not the complete answer to that
                    filter — there may be matching findings that were never loaded and
                    therefore could not be ticked.
                  </p>
                  <p>
                    The issue will cover the {count} finding(s) you selected and say so. It
                    cannot be edited or deleted afterwards.
                  </p>
                  <label className="flex items-start gap-2 font-medium">
                    <Checkbox
                      checked={acknowledgedTruncation}
                      onCheckedChange={(value) => setAcknowledgedTruncation(!!value)}
                    />
                    <span>
                      I understand this issue covers only these {count} finding(s), not
                      every finding matching my filters.
                    </span>
                  </label>
                </AlertDescription>
              </Alert>
            )}

            {missing > 0 && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>{missing} selected finding(s) no longer exist</AlertTitle>
                <AlertDescription>
                  They were deleted or moved out of scope since the table loaded. Reload
                  the findings page and select again — nothing will be filed for a
                  partial selection.
                </AlertDescription>
              </Alert>
            )}

            {ineligible > 0 && (
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>
                  {ineligible} selected finding(s) are below the filing floor
                </AlertTitle>
                <AlertDescription className="space-y-2">
                  <p>
                    The filing policy covers Critical, High and Medium findings that are
                    still actionable. These are outside it. They can still be filed, and
                    the issue body will name them as a deliberate inclusion.
                  </p>
                  <label className="flex items-start gap-2 font-medium">
                    <Checkbox
                      checked={includeIneligible}
                      onCheckedChange={(value) => setIncludeIneligible(!!value)}
                    />
                    <span>Include them anyway</span>
                  </label>
                </AlertDescription>
              </Alert>
            )}

            <div className="space-y-2">
              <Label htmlFor="selection-issue-title">Issue title</Label>
              <Input
                id="selection-issue-title"
                value={title}
                onChange={(event) => setSummaryEdit(event.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="selection-exec-summary">
                Executive summary
                {config?.executive_summary_required && " (required by this category)"}
              </Label>
              <Input
                id="selection-exec-summary"
                value={executiveSummary}
                onChange={(event) => setSummaryLineEdit(event.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                One line for a non-technical reader. This category asks for under{" "}
                {config?.executive_summary_target_chars ?? 30} characters; longer is
                accepted and shown in full on the record.
              </p>
            </div>

            <div className="space-y-2">
              <Label>Deficiency level</Label>
              <Select
                value={effectiveLevelId != null ? String(effectiveLevelId) : undefined}
                onValueChange={(value) => setLevelOverride(Number(value))}
                disabled={!config?.deficiency_levels?.length}
              >
                <SelectTrigger>
                  <SelectValue
                    placeholder={
                      effectiveLevelName
                        ? `Default for ${severity ? severityLabel(severity) : "this severity"} — ${effectiveLevelName}`
                        : "Server default"
                    }
                  />
                </SelectTrigger>
                <SelectContent>
                  {(config?.deficiency_levels ?? []).map((level) => (
                    <SelectItem key={level.id} value={String(level.id)}>
                      {level.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {escalated && (
                <p className="text-xs text-warning-text">
                  {effectiveLevelName} is an audit determination, not a scanner
                  severity. Filing at this level puts the issue in front of an audience
                  that will treat it as one.
                </p>
              )}
            </div>

            {/* The exact body, because nobody can review a normalization they
                cannot see, and there is no Create button on AuditBoard's side
                to reconsider at. */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Issue body, exactly as it will be sent</Label>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    void navigator.clipboard?.writeText(generatedDescription);
                    toast({ title: "Copied the issue body" });
                  }}
                >
                  <ClipboardCopy className="mr-2 h-3.5 w-3.5" />
                  Copy
                </Button>
              </div>
              <pre className="max-h-64 overflow-auto rounded-md border bg-muted/40 p-3 text-xs whitespace-pre-wrap">
                {generatedDescription}
              </pre>
              <p className="text-xs text-muted-foreground">
                The server appends the location list and a provenance footer, so the
                counts in them are ones it measured rather than ones this page guessed.
              </p>
            </div>

            {filingError && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>AuditBoard refused the issue</AlertTitle>
                <AlertDescription>{filingError}. Nothing was filed.</AlertDescription>
              </Alert>
            )}
          </div>
        )}

        <DialogFooter>
          {result ? (
            <Button onClick={() => onOpenChange(false)}>Done</Button>
          ) : (
            <>
              <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={filing}>
                Cancel
              </Button>
              {armed ? (
                <Button variant="destructive" onClick={file} disabled={!canFile}>
                  {filing ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Filing…
                    </>
                  ) : (
                    <>Confirm — create one issue covering {count} finding(s)</>
                  )}
                </Button>
              ) : (
                <Button onClick={() => setArmed(true)} disabled={!canFile}>
                  File to AuditBoard
                </Button>
              )}
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
