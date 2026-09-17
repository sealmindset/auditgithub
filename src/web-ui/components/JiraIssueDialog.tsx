"use client";

/**
 * Report a finding to Jira.
 *
 * Sits beside Create Exception and takes the same scope decision, keyed the
 * same way, so "global" means one thing in this app rather than one thing per
 * dialog: specific is this instance, global is every finding from this scanner
 * in this file path — one issue for a defect that was reported N times.
 *
 * Deep link, not an API call. The app stores no Jira credential, the user
 * authenticates to Jira as themselves, and the issue exists only once they
 * press Create on Jira's own screen. Filing an issue is outbound, so a human
 * stays in the loop by construction rather than by policy.
 *
 * The dialog shows exactly what will be prefilled, because a normalization
 * nobody can inspect is a normalization nobody will trust.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ClipboardCopy,
  ExternalLink,
  Loader2,
  SquareArrowOutUpRight,
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
  DialogTrigger,
} from "@/components/ui/dialog";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useToast } from "@/components/ui/use-toast";
import { API_BASE, apiFetch } from "@/lib/api";
import { SEVERITY_TONE } from "@/lib/severity";
import {
  buildCreateIssueUrl,
  EMPTY_JIRA_CONFIG,
  normalizeFinding,
  type FindingLike,
  type IssueScope,
  type JiraConfig,
  type OccurrenceGroup,
} from "@/lib/jira";

interface JiraIssueDialogProps {
  finding: FindingLike;
}

export function JiraIssueDialog({ finding }: JiraIssueDialogProps) {
  const { toast } = useToast();

  const [open, setOpen] = useState(false);
  const [scope, setScope] = useState<IssueScope>("specific");

  const [config, setConfig] = useState<JiraConfig | null>(null);
  const [configError, setConfigError] = useState(false);

  const [group, setGroup] = useState<OccurrenceGroup | null>(null);
  const [groupLoading, setGroupLoading] = useState(false);
  const [groupError, setGroupError] = useState<string | null>(null);

  // Runtime config, fetched once the dialog is first opened. A failure is not
  // worth a toast — the footer button stays disabled and says why.
  useEffect(() => {
    if (!open || config || configError) return;
    let cancelled = false;
    fetch("/api/jira-config", { cache: "no-store" })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(String(res.status)))))
      .then((data: JiraConfig) => {
        if (!cancelled) setConfig({ ...EMPTY_JIRA_CONFIG, ...data });
      })
      .catch(() => {
        if (!cancelled) setConfigError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [open, config, configError]);

  /**
   * Occurrence count for the global option. Read-only endpoint — it reports
   * the population a global filing would speak for without touching it. Read
   * as soon as the dialog opens, so the radio can carry the count the user is
   * choosing between rather than making them pick blind.
   */
  const loadGroup = useCallback(async () => {
    if (!finding?.id) return;
    setGroupLoading(true);
    setGroupError(null);
    try {
      const res = await apiFetch(
        `${API_BASE}/findings/${finding.id}/occurrences?scope=global`,
      );
      if (!res.ok) throw new Error(`Occurrence lookup failed (${res.status})`);
      setGroup(await res.json());
    } catch (err) {
      setGroupError(err instanceof Error ? err.message : "Occurrence lookup failed");
      setGroup(null);
    } finally {
      setGroupLoading(false);
    }
  }, [finding?.id]);

  useEffect(() => {
    if (open) loadGroup();
  }, [open, loadGroup]);

  const issue = useMemo(
    () =>
      normalizeFinding(finding, config ?? EMPTY_JIRA_CONFIG, {
        scope,
        group,
        appOrigin: typeof window === "undefined" ? null : window.location.origin,
      }),
    [finding, config, scope, group],
  );

  const createUrl = useMemo(
    () => (config ? buildCreateIssueUrl(config, issue) : null),
    [config, issue],
  );

  const configured = !!config?.configured;
  const loadingConfig = !config && !configError;

  // Global scope without a count would file a ticket claiming a population we
  // have not measured. Block it rather than guess.
  const blockedReason = configError
    ? "Could not read the Jira configuration"
    : loadingConfig
      ? "Checking the Jira configuration…"
      : !configured
        ? "Jira is not configured — set JIRA_BASE_URL, JIRA_PROJECT_ID and JIRA_ISSUE_TYPE_ID"
        : scope === "global" && !group
          ? "Occurrence count unavailable — cannot file a grouped issue without it"
          : null;

  const handleCopyDescription = async () => {
    try {
      await navigator.clipboard.writeText(issue.description);
      toast({
        title: "Description copied",
        description: "Paste it into Jira if any of it was shortened in transit.",
      });
    } catch {
      toast({
        variant: "destructive",
        title: "Could not copy",
        description: "Clipboard access was refused. Select the text below and copy it.",
      });
    }
  };

  const handleOpenJira = () => {
    if (!createUrl) return;
    window.open(createUrl.url, "_blank", "noopener,noreferrer");
    setOpen(false);
  };

  const globalCount = group?.count;
  const repoCount = group?.repo_names?.length ?? 0;

  return (
    <Dialog
      open={open}
      onOpenChange={(isOpen) => {
        setOpen(isOpen);
        if (!isOpen) setScope("specific");
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="gap-2">
          <SquareArrowOutUpRight className="h-4 w-4" />
          Report to Jira
        </Button>
      </DialogTrigger>

      <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
        <DialogHeader>
          <DialogTitle>Report Finding to Jira</DialogTitle>
          <DialogDescription>
            Prefills Jira&apos;s create screen. Nothing is created until you press
            Create in Jira.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-6 py-4">
          {/* Finding summary — same shape as the exception dialog */}
          <div className="rounded-md border p-4 bg-muted/50">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-medium">{finding.title}</h4>
                <p className="text-sm text-muted-foreground">{finding.file_path}</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline">{finding.scanner_name}</Badge>
                <Badge className={SEVERITY_TONE[issue.severity].soft}>
                  {finding.severity}
                </Badge>
              </div>
            </div>
          </div>

          {/* Scope — same vocabulary and same grouping key as Create Exception */}
          <div className="space-y-3">
            <Label className="text-base font-semibold">Report Scope</Label>
            <RadioGroup value={scope} onValueChange={(v) => setScope(v as IssueScope)}>
              <div className="flex items-start space-x-3 p-3 rounded-md border hover:bg-muted/50 cursor-pointer">
                <RadioGroupItem value="specific" id="jira-specific" className="mt-1" />
                <div className="flex-1">
                  <Label htmlFor="jira-specific" className="font-medium cursor-pointer">
                    Specific
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    One issue for this finding instance in{" "}
                    <strong>{finding.repo_name}</strong>.
                  </p>
                </div>
              </div>
              <div className="flex items-start space-x-3 p-3 rounded-md border hover:bg-muted/50 cursor-pointer">
                <RadioGroupItem value="global" id="jira-global" className="mt-1" />
                <div className="flex-1">
                  <Label htmlFor="jira-global" className="font-medium cursor-pointer">
                    Global
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    One issue covering all findings from{" "}
                    <strong>{finding.scanner_name}</strong> in{" "}
                    <strong>{finding.file_path}</strong>
                    {groupLoading && (
                      <span className="ml-1 inline-flex items-center gap-1">
                        <Loader2 className="h-3 w-3 animate-spin" />
                        counting…
                      </span>
                    )}
                    {globalCount !== undefined && (
                      <>
                        {" — "}
                        <strong>
                          {globalCount} occurrence{globalCount === 1 ? "" : "s"}
                        </strong>
                        {repoCount > 1 && <> across {repoCount} repositories</>}
                      </>
                    )}
                    .
                  </p>
                  {groupError && (
                    <p className="mt-1 text-xs text-danger-text">
                      {groupError}. Retry, or file the specific finding instead.
                    </p>
                  )}
                </div>
              </div>
            </RadioGroup>

            {scope === "global" && group && !group.org_scoped && (
              <Alert>
                <AlertTitle>This count is tenant-wide</AlertTitle>
                <AlertDescription>
                  No organization filter was in effect, so {group.count} covers every
                  organization in this tenant — not just the current one. The figure is
                  stated that way in the issue description.
                </AlertDescription>
              </Alert>
            )}
          </div>

          {/* Exactly what Jira will receive */}
          <div className="space-y-4 text-sm">
            <Field label="Summary">
              <p className="font-medium">{issue.summary}</p>
            </Field>

            <div className="grid grid-cols-2 gap-4">
              <Field label="Priority">
                <span className="inline-flex items-center gap-2">
                  <Badge className={SEVERITY_TONE[issue.severity].soft}>
                    {issue.priorityName}
                  </Badge>
                  {!issue.priorityId && (
                    <span className="text-xs text-muted-foreground">
                      name only — no priority ID configured
                    </span>
                  )}
                </span>
              </Field>
              <Field label="Project / issue type">
                <span className="font-mono text-xs">
                  project {config?.projectId ?? "—"}, type {config?.issueTypeId ?? "—"}
                </span>
              </Field>
            </div>

            <Field label="Labels">
              <span className="flex flex-wrap gap-1.5">
                {issue.labels.map((label) => (
                  <Badge key={label} variant="secondary" className="font-mono text-xs">
                    {label}
                  </Badge>
                ))}
              </span>
            </Field>

            <Field label="Description">
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs text-muted-foreground">
                {issue.description}
              </pre>
            </Field>

            {createUrl?.truncated && (
              <Alert>
                <AlertTitle>Description will arrive shortened</AlertTitle>
                <AlertDescription>
                  It is too long to carry in a link. Copy the full text before opening
                  Jira, then paste it over the prefilled description.
                </AlertDescription>
              </Alert>
            )}
          </div>
        </div>

        <DialogFooter className="gap-2 sm:justify-between">
          <Button variant="outline" size="sm" onClick={handleCopyDescription}>
            <ClipboardCopy className="h-4 w-4" />
            Copy description
          </Button>
          <div className="flex items-center gap-3">
            {blockedReason && (
              <span className="text-xs text-muted-foreground">{blockedReason}</span>
            )}
            <Button size="sm" onClick={handleOpenJira} disabled={!!blockedReason || !createUrl}>
              <ExternalLink className="h-4 w-4" />
              Open in Jira
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </p>
      {children}
    </div>
  );
}
