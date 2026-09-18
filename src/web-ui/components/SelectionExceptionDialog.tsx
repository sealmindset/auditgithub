"use client";

/**
 * Create exceptions for a hand-picked selection of findings.
 *
 * Two different things live behind the one word "exception", and this dialog
 * keeps them apart because they have opposite risk profiles:
 *
 *   * **Suppress in the scanner** — generated rules to paste into the
 *     repository, so the finding stops being reported at the source. A scanner
 *     rule keys on a *path*: gitleaks allowlists, `.semgrepignore` entries and
 *     the rest cannot suppress the third of five findings on one line. So a
 *     rule always covers at least the selection and usually more, and the
 *     overreach is measured and shown before anything is copied.
 *
 *   * **Delete as false positives** — remove the findings from AuditGitHub.
 *     This is exact to the selection, and it takes each finding's history with
 *     it. It also leaves any AuditBoard issue that covered them open in the
 *     GRC register with nothing behind it, which only someone with AuditBoard
 *     rights can close. Both facts are shown, per issue, before the delete.
 *
 * Unlike the AuditBoard filing dialog this one has no truncation gate. A wrong
 * exception is correctable — an unwanted scanner rule can be removed from the
 * repository, and a delete is measured against the exact ids submitted rather
 * than against a filter. A wrong AuditBoard issue is permanent.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCopy,
  ExternalLink,
  FileCode,
  Loader2,
  Trash2,
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useToast } from "@/components/ui/use-toast";
import { API_BASE, apiFetch } from "@/lib/api";
import type { FindingLike } from "@/lib/finding-issue";

interface SelectionExceptionRule {
  scanner_name: string;
  file_path: string | null;
  rule_type: string;
  rule_content: string;
  instruction: string;
  selected_count: number;
  affected_count: number;
}

interface SelectionExceptionResponse {
  rules: SelectionExceptionRule[];
  selected_count: number;
  affected_count: number;
  collateral_count: number;
  missing_ids: string[];
}

interface DryRunAuditBoardIssue {
  issue_id: string;
  issue_uid: string | null;
  issue_url: string | null;
  issue_status: string | null;
  scope: string;
  filed_by: string | null;
  filed_at: string | null;
  direct: boolean;
  remaining_findings: number;
}

interface DryRunResponse {
  count: number;
  scanner_name: string;
  file_path: string | null;
  sample_findings: Array<{
    id: string;
    title: string | null;
    file_path: string | null;
    scanner_name: string | null;
  }>;
  auditboard_issues: DryRunAuditBoardIssue[];
}

interface SelectionExceptionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  findings: FindingLike[];
  /** Called after a delete succeeds, so the page can re-read the findings. */
  onDeleted?: () => void;
}

export function SelectionExceptionDialog({
  open,
  onOpenChange,
  findings,
  onDeleted,
}: SelectionExceptionDialogProps) {
  const { toast } = useToast();

  const [rules, setRules] = useState<SelectionExceptionResponse | null>(null);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [rulesError, setRulesError] = useState<string | null>(null);

  const [dryRun, setDryRun] = useState<DryRunResponse | null>(null);
  const [dryRunLoading, setDryRunLoading] = useState(false);
  const [dryRunError, setDryRunError] = useState<string | null>(null);

  const [armed, setArmed] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deletedCount, setDeletedCount] = useState<number | null>(null);

  const findingIds = useMemo(
    () => findings.map((f) => String(f.id ?? "")).filter(Boolean),
    [findings],
  );

  useEffect(() => {
    if (!open || findingIds.length === 0) return;
    let cancelled = false;

    const post = async <T,>(path: string): Promise<T> => {
      const res = await apiFetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_ids: findingIds }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body?.detail || `HTTP ${res.status}`);
      return body as T;
    };

    setRulesLoading(true);
    setRulesError(null);
    post<SelectionExceptionResponse>("/findings/exception/selection/generate")
      .then((data) => {
        if (!cancelled) setRules(data);
      })
      .catch((err: Error) => {
        if (!cancelled) setRulesError(err.message);
      })
      .finally(() => {
        if (!cancelled) setRulesLoading(false);
      });

    // The dry run is fetched up front, not on switching to the delete tab: it
    // is the only thing that can say an AuditBoard issue is about to be
    // orphaned, and that has to be visible before anyone goes looking for the
    // delete button.
    setDryRunLoading(true);
    setDryRunError(null);
    post<DryRunResponse>("/findings/exception/selection/delete/dry-run")
      .then((data) => {
        if (!cancelled) setDryRun(data);
      })
      .catch((err: Error) => {
        if (!cancelled) setDryRunError(err.message);
      })
      .finally(() => {
        if (!cancelled) setDryRunLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open, findingIds]);

  useEffect(() => {
    if (open) return;
    setArmed(false);
    setDeletedCount(null);
    setDeleteError(null);
    setRules(null);
    setDryRun(null);
  }, [open]);

  const remove = useCallback(async () => {
    setDeleting(true);
    setDeleteError(null);
    try {
      const res = await apiFetch(`${API_BASE}/findings/exception/selection/delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_ids: findingIds,
          // The number the dry run reported, so a selection that changed
          // underneath this dialog is refused rather than partly deleted.
          expected_count: dryRun?.count ?? findingIds.length,
          confirmed: true,
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body?.detail || `HTTP ${res.status}`);
      setDeletedCount(body?.deleted_count ?? null);
      setArmed(false);
      toast({
        title: "Findings deleted",
        description: `${body?.deleted_count ?? 0} finding(s) removed from AuditGitHub.`,
      });
      onDeleted?.();
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : String(err));
      setArmed(false);
    } finally {
      setDeleting(false);
    }
  }, [findingIds, dryRun, toast, onDeleted]);

  const orphaned = (dryRun?.auditboard_issues ?? []).filter(
    (issue) => issue.remaining_findings === 0,
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            Create an exception for {findingIds.length} selected finding
            {findingIds.length === 1 ? "" : "s"}
          </DialogTitle>
          <DialogDescription>
            Suppress them in the scanner, or delete them from AuditGitHub as false
            positives.
          </DialogDescription>
        </DialogHeader>

        {deletedCount !== null ? (
          <Alert>
            <CheckCircle2 className="h-4 w-4" />
            <AlertTitle>{deletedCount} finding(s) deleted</AlertTitle>
            <AlertDescription>
              {orphaned.length > 0 ? (
                <>
                  {orphaned.length} AuditBoard issue(s) now have no findings behind them
                  and are still open. They have to be closed in AuditBoard by hand — this
                  app cannot close them.
                </>
              ) : (
                <>Their history was removed with them.</>
              )}
            </AlertDescription>
          </Alert>
        ) : (
          <Tabs defaultValue="suppress">
            <TabsList>
              <TabsTrigger value="suppress">
                <FileCode className="mr-2 h-4 w-4" />
                Suppress in the scanner
              </TabsTrigger>
              <TabsTrigger value="delete">
                <Trash2 className="mr-2 h-4 w-4" />
                Delete as false positives
              </TabsTrigger>
            </TabsList>

            <TabsContent value="suppress" className="space-y-4 pt-4">
              {rulesLoading && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Generating rules…
                </div>
              )}

              {rulesError && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>The rules could not be generated</AlertTitle>
                  <AlertDescription>{rulesError}</AlertDescription>
                </Alert>
              )}

              {rules && (
                <>
                  {/* The overreach figure. This is the whole reason the
                      suppress path is measured rather than just generated. */}
                  {rules.collateral_count > 0 ? (
                    <Alert variant="destructive">
                      <AlertTriangle className="h-4 w-4" />
                      <AlertTitle>
                        These rules suppress more than you selected
                      </AlertTitle>
                      <AlertDescription>
                        You selected <strong>{rules.selected_count}</strong> finding(s).
                        Applied as written, these rules would stop{" "}
                        <strong>{rules.affected_count}</strong> finding(s) being reported
                        — <strong>{rules.collateral_count}</strong> that you did not
                        select. Scanner rules key on a file path and cannot be narrowed to
                        individual findings, so this gap is a property of the scanners, not
                        a mistake here. Review each rule before pasting it.
                      </AlertDescription>
                    </Alert>
                  ) : (
                    <Alert>
                      <CheckCircle2 className="h-4 w-4" />
                      <AlertTitle>These rules are exact</AlertTitle>
                      <AlertDescription>
                        They suppress the {rules.selected_count} selected finding(s) and
                        nothing else.
                      </AlertDescription>
                    </Alert>
                  )}

                  <div className="space-y-3">
                    {rules.rules.map((rule, index) => (
                      <div
                        key={`${rule.scanner_name}:${rule.file_path ?? index}`}
                        className="rounded-md border p-3 space-y-2"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="space-y-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <Badge variant="secondary">{rule.scanner_name}</Badge>
                              <Badge variant="outline">{rule.rule_type}</Badge>
                            </div>
                            <p className="text-xs text-muted-foreground break-all">
                              {rule.file_path ?? "no path recorded"}
                            </p>
                            <p className="text-xs">
                              Covers {rule.selected_count} selected;{" "}
                              <span
                                className={
                                  rule.affected_count > rule.selected_count
                                    ? "text-warning-text font-medium"
                                    : undefined
                                }
                              >
                                suppresses {rule.affected_count} in total
                              </span>
                            </p>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              void navigator.clipboard?.writeText(rule.rule_content);
                              toast({ title: "Rule copied" });
                            }}
                          >
                            <ClipboardCopy className="mr-2 h-3.5 w-3.5" />
                            Copy
                          </Button>
                        </div>
                        <pre className="max-h-40 overflow-auto rounded bg-muted/40 p-2 text-xs whitespace-pre-wrap">
                          {rule.rule_content}
                        </pre>
                        <p className="text-xs text-muted-foreground">{rule.instruction}</p>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </TabsContent>

            <TabsContent value="delete" className="space-y-4 pt-4">
              {dryRunLoading && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Checking what this would remove…
                </div>
              )}

              {dryRunError && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>The delete could not be previewed</AlertTitle>
                  <AlertDescription>
                    {dryRunError}. Nothing has been deleted.
                  </AlertDescription>
                </Alert>
              )}

              {dryRun && (
                <>
                  <Alert variant="destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>
                      {dryRun.count} finding(s) will be permanently removed
                    </AlertTitle>
                    <AlertDescription>
                      Exactly the findings you selected, across {dryRun.scanner_name} and{" "}
                      {dryRun.file_path}. Each finding&apos;s comments, journal entries and
                      history go with it. A rescan will report the defect again if it is
                      still in the code.
                    </AlertDescription>
                  </Alert>

                  {dryRun.auditboard_issues.length > 0 && (
                    <div className="rounded-md border p-3 space-y-2">
                      <p className="text-sm font-medium">
                        {dryRun.auditboard_issues.length} AuditBoard issue(s) cover these
                        findings
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Deleting findings does not close a GRC issue, by design — a filing
                        that happened really happened. An issue left with 0 findings behind
                        it has to be closed in AuditBoard by hand.
                      </p>
                      <ul className="space-y-1 text-xs">
                        {dryRun.auditboard_issues.map((issue) => (
                          <li key={issue.issue_id} className="flex items-center gap-2">
                            {issue.issue_url ? (
                              <a
                                href={issue.issue_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 underline"
                              >
                                {issue.issue_uid || issue.issue_id}
                                <ExternalLink className="h-3 w-3" />
                              </a>
                            ) : (
                              <span>{issue.issue_uid || issue.issue_id}</span>
                            )}
                            <Badge variant="outline">{issue.scope}</Badge>
                            {issue.remaining_findings === 0 ? (
                              <span className="text-destructive font-medium">
                                0 findings left — will be orphaned
                              </span>
                            ) : (
                              <span className="text-muted-foreground">
                                {issue.remaining_findings} finding(s) left, still valid
                              </span>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {dryRun.sample_findings.length > 0 && (
                    <div className="rounded-md border p-3">
                      <p className="mb-2 text-sm font-medium">
                        Sample of what would be deleted
                      </p>
                      <ul className="space-y-1 text-xs text-muted-foreground">
                        {dryRun.sample_findings.map((finding) => (
                          <li key={finding.id} className="break-all">
                            [{finding.scanner_name}] {finding.title} — {finding.file_path}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              )}

              {deleteError && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>The delete failed</AlertTitle>
                  <AlertDescription>{deleteError}</AlertDescription>
                </Alert>
              )}

              <div className="flex justify-end gap-2">
                {armed ? (
                  <Button
                    variant="destructive"
                    onClick={remove}
                    disabled={deleting || !dryRun}
                  >
                    {deleting ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Deleting…
                      </>
                    ) : (
                      <>Confirm — delete {dryRun?.count ?? findingIds.length} finding(s)</>
                    )}
                  </Button>
                ) : (
                  <Button
                    variant="destructive"
                    onClick={() => setArmed(true)}
                    disabled={!dryRun || dryRunLoading}
                  >
                    <Trash2 className="mr-2 h-4 w-4" />
                    Delete as false positives
                  </Button>
                )}
              </div>
            </TabsContent>
          </Tabs>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={deleting}>
            {deletedCount !== null ? "Done" : "Close"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
