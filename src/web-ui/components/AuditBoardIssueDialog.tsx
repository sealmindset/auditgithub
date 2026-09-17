"use client";

/**
 * Report a finding to AuditBoard as a GRC issue.
 *
 * Files at one of three tiers, and a defect is identified by its scanner and
 * rule rather than by the file it was found in:
 *
 * *   `specific` — this one finding instance.
 * *   `project`  — this defect everywhere in this project, with every location
 *                  inside it listed in the body.
 * *   `org`      — this defect across every project, listed per project.
 *
 * One press files exactly one issue, whichever tier is chosen. The tier the
 * volume rule points to is pre-selected, so the common case is to press once
 * without choosing anything.
 *
 * This does not offer the `global` scope the exception flow and the Jira deep
 * link use. Grouping on scanner plus file path put 11,517 findings from 1,287
 * unrelated advisories behind one key, because they all sat in a file called
 * package-lock.json; the filing endpoint refuses it.
 *
 * Every figure shown here is measured by the server, from the same service
 * the filing endpoint counts with, so the preview and the issue cannot
 * disagree. Nothing is counted in the browser.
 *
 * Unlike the Jira dialog, this is not a deep link. AuditBoard has no
 * prefill-a-form URL, so filing is an authenticated API write performed by our
 * own backend, and the record exists the moment it succeeds — there is no
 * Create button on the far side to reconsider at. Two consequences the UI
 * carries deliberately:
 *
 * *   the exact title and body are shown before anything is sent, because
 *     nobody can review a normalization they cannot see; and
 * *   the action is armed then confirmed, rather than fired on one click.
 *
 * The AuditBoard credential never reaches the browser. This component talks
 * only to our API.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
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
  DialogTrigger,
} from "@/components/ui/dialog";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
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
import { SEVERITY_TONE } from "@/lib/severity";
import {
  buildAuditBoardDraft,
  EMPTY_AUDITBOARD_CONFIG,
  ESCALATED_DEFICIENCY_LEVEL_IDS,
  type AuditBoardConfig,
  type AuditBoardIssueResult,
  type FilingTier,
  type FindingLike,
  type GroupSummary,
} from "@/lib/auditboard";

interface AuditBoardIssueDialogProps {
  finding: FindingLike;
  /** Called once AuditBoard confirms a create, so the page can re-read the
   *  filing history rather than waiting for a reload to show it. */
  onFiled?: () => void;
}

export function AuditBoardIssueDialog({ finding, onFiled }: AuditBoardIssueDialogProps) {
  const { toast } = useToast();

  const [open, setOpen] = useState(false);
  const [tier, setTier] = useState<FilingTier>("specific");
  // Set once, when the measurement first arrives, so the recommendation does
  // not keep overriding a person who deliberately chose another tier.
  const [tierPreselected, setTierPreselected] = useState(false);
  const [levelOverride, setLevelOverride] = useState<number | null>(null);

  const [config, setConfig] = useState<AuditBoardConfig | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);

  // Null means "use the generated line". Kept separate from the generated
  // value so changing scope still refreshes the suggestion, while an edit a
  // person actually typed survives it.
  const [summaryEdit, setSummaryEdit] = useState<string | null>(null);

  // One measurement per tier, kept because switching tiers is a normal thing
  // to do while deciding and re-measuring on every click would make the
  // figures flicker.
  const [groups, setGroups] = useState<Partial<Record<FilingTier, GroupSummary>>>({});
  const [groupLoading, setGroupLoading] = useState(false);
  const [groupError, setGroupError] = useState<string | null>(null);

  // Armed-then-confirmed, because the next click writes to a system of record.
  const [armed, setArmed] = useState(false);
  const [filing, setFiling] = useState(false);
  const [result, setResult] = useState<AuditBoardIssueResult | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);

  /**
   * Availability and vocabulary. Served by our API, not AuditBoard, and it
   * carries no credential — only whether filing works and which deficiency
   * levels a person may pick from.
   */
  useEffect(() => {
    if (!open || config || configError) return;
    let cancelled = false;
    apiFetch(`${API_BASE}/findings/auditboard/config`)
      .then((res) =>
        res.ok ? res.json() : Promise.reject(new Error(`Config lookup failed (${res.status})`)),
      )
      .then((data: AuditBoardConfig) => {
        if (!cancelled) setConfig({ ...EMPTY_AUDITBOARD_CONFIG, ...data });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setConfigError(
            err instanceof Error ? err.message : "Could not read the AuditBoard configuration",
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, [open, config, configError]);

  /**
   * Measure both grouped tiers. Read-only — it reports the population a
   * filing would speak for without touching it. The server re-measures at
   * filing time and its figures are the ones written; these exist so the
   * choice is not made blind, and they come from the same service, so they
   * agree.
   *
   * Both tiers are fetched up front rather than on selection, because the
   * project-tier answer carries the organization-wide project count that
   * decides whether `org` is the right choice at all.
   */
  const loadGroups = useCallback(async () => {
    if (!finding?.id) return;
    setGroupLoading(true);
    setGroupError(null);
    try {
      const measured = await Promise.all(
        (["project", "org"] as const).map(async (t) => {
          const res = await apiFetch(`${API_BASE}/findings/${finding.id}/group?tier=${t}`);
          if (!res.ok) throw new Error(`Group lookup failed (${res.status})`);
          return [t, (await res.json()) as GroupSummary] as const;
        }),
      );
      setGroups(Object.fromEntries(measured));
    } catch (err) {
      setGroupError(err instanceof Error ? err.message : "Group lookup failed");
      setGroups({});
    } finally {
      setGroupLoading(false);
    }
  }, [finding?.id]);

  useEffect(() => {
    if (open) loadGroups();
  }, [open, loadGroups]);

  const summary = groups[tier] ?? null;
  // Measured at project tier, which reports it organization-wide; the org-tier
  // response reports the same figure, so either will do.
  const recommended = groups.project?.recommended_tier ?? null;

  // Pre-select the tier the volume rule points to. A defect in one project is
  // one team's to fix; a defect in more projects than the threshold is not,
  // and defaulting to `specific` would have someone file it a hundred times.
  useEffect(() => {
    if (tierPreselected || !recommended) return;
    if (recommended === "project" || recommended === "org") setTier(recommended);
    setTierPreselected(true);
  }, [recommended, tierPreselected]);

  const draft = useMemo(
    () =>
      buildAuditBoardDraft(finding, {
        scope: tier,
        groupSummary: summary,
        config: config ?? EMPTY_AUDITBOARD_CONFIG,
        deficiencyLevelId: levelOverride,
        appOrigin: typeof window === "undefined" ? null : window.location.origin,
      }),
    [finding, tier, summary, config, levelOverride],
  );

  const executiveSummary = summaryEdit ?? draft.executiveSummary;
  const summaryTarget = config?.executive_summary_target_chars ?? 30;
  const summaryOverTarget = executiveSummary.trim().length > summaryTarget;

  // Any change to what would be sent disarms the button, so a confirmation
  // can never apply to a body other than the one it was given for.
  useEffect(() => {
    setArmed(false);
  }, [draft.title, draft.description, draft.deficiencyLevelId, executiveSummary]);

  const loadingConfig = !config && !configError;

  const blockedReason = configError
    ? configError
    : loadingConfig
      ? "Checking the AuditBoard configuration…"
      : config && !config.enabled
        ? config.problem || "AuditBoard filing is not configured"
        : tier !== "specific" && !summary
          ? "Group measurement unavailable — cannot file a grouped issue without it"
          : tier !== "specific" && summary && !summary.fileable
            ? (summary.blocked_reason ?? "This finding cannot be filed as a group")
            : config?.executive_summary_required && !executiveSummary.trim()
              ? "This category needs an Executive Summary"
              : result
                ? "Already filed in this dialog"
                : null;

  const escalated =
    draft.deficiencyLevelId !== null &&
    ESCALATED_DEFICIENCY_LEVEL_IDS.has(draft.deficiencyLevelId);

  const handleCopyDescription = async () => {
    try {
      await navigator.clipboard.writeText(
        `${draft.title}\n\nExecutive summary: ${executiveSummary}\n\n${draft.description}`,
      );
      toast({
        title: "Issue text copied",
        description: "Title, executive summary and body, as they would be sent.",
      });
    } catch {
      toast({
        variant: "destructive",
        title: "Could not copy",
        description: "Clipboard access was refused. Select the text below and copy it.",
      });
    }
  };

  const handleFile = async () => {
    if (!armed) {
      setArmed(true);
      return;
    }
    setFiling(true);
    setFileError(null);
    try {
      const res = await apiFetch(`${API_BASE}/findings/${finding.id}/auditboard-issue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scope: tier,
          title: draft.title,
          description: draft.description,
          deficiency_level_id: levelOverride,
          executive_summary: executiveSummary.trim() || null,
        }),
      });
      if (!res.ok) {
        // The API forwards AuditBoard's own rejection text, which usually
        // names the field it refused. That is the whole value of the message.
        let detail = `AuditBoard filing failed (${res.status})`;
        try {
          const body = await res.json();
          if (body?.detail) detail = String(body.detail);
        } catch {
          /* non-JSON error body; the status is all we have */
        }
        throw new Error(detail);
      }
      const created: AuditBoardIssueResult = await res.json();
      setResult(created);
      setArmed(false);
      onFiled?.();
      toast({
        title: "AuditBoard issue created",
        description: created.issue_id
          ? `Issue ${created.issue_id} at ${created.deficiency_level_name}.`
          : `Filed at ${created.deficiency_level_name}.`,
      });
    } catch (err) {
      setFileError(err instanceof Error ? err.message : "AuditBoard filing failed");
      setArmed(false);
    } finally {
      setFiling(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(isOpen) => {
        setOpen(isOpen);
        if (!isOpen) {
          setTier("specific");
          setTierPreselected(false);
          setLevelOverride(null);
          setSummaryEdit(null);
          setArmed(false);
          setResult(null);
          setFileError(null);
        }
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="gap-2">
          <ShieldAlert className="h-4 w-4" />
          Report to AuditBoard
        </Button>
      </DialogTrigger>

      <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
        <DialogHeader>
          <DialogTitle>Report Finding to AuditBoard</DialogTitle>
          <DialogDescription>
            Creates a GRC issue directly. AuditBoard has no confirmation screen —
            review the text below, then confirm.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-6 py-4">
          {/* Finding summary — same shape as the exception and Jira dialogs */}
          <div className="rounded-md border p-4 bg-muted/50">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-medium">{finding.title}</h4>
                <p className="text-sm text-muted-foreground">{finding.file_path}</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline">{finding.scanner_name}</Badge>
                <Badge className={SEVERITY_TONE[draft.severity].soft}>
                  {finding.severity}
                </Badge>
              </div>
            </div>
          </div>

          {result && (
            <Alert>
              <AlertTitle>Issue created</AlertTitle>
              <AlertDescription className="space-y-1">
                <p>
                  Filed at <strong>{result.deficiency_level_name}</strong>, covering{" "}
                  <strong>{result.occurrence_count}</strong> finding
                  {result.occurrence_count === 1 ? "" : "s"}
                  {result.scope !== "specific" && (
                    <>
                      {" in "}
                      <strong>
                        {result.project_count} project
                        {result.project_count === 1 ? "" : "s"}
                      </strong>
                      {result.location_count > 0 && (
                        <> at {result.location_count} locations</>
                      )}
                    </>
                  )}
                  , counted by the server at filing time.
                </p>
                {result.identity_key && (
                  <p className="font-mono text-xs">Defect: {result.identity_key}</p>
                )}
                {result.issue_url && (
                  <a
                    className="inline-flex items-center gap-1 underline"
                    href={result.issue_url}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <ExternalLink className="h-3 w-3" />
                    Open issue {result.issue_id}
                  </a>
                )}
              </AlertDescription>
            </Alert>
          )}

          {fileError && (
            <Alert variant="destructive">
              <AlertTitle>AuditBoard refused the issue</AlertTitle>
              <AlertDescription className="font-mono text-xs">{fileError}</AlertDescription>
            </Alert>
          )}

          {/* Tier — what the issue speaks for. One press files one issue at
              whichever of these is selected. */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Label className="text-base font-semibold">What this issue covers</Label>
              {groupLoading && (
                <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  measuring…
                </span>
              )}
            </div>
            <RadioGroup value={tier} onValueChange={(v) => setTier(v as FilingTier)}>
              <TierOption
                value="specific"
                id="ab-specific"
                title="This finding only"
                recommended={recommended === "specific"}
              >
                One issue for this finding instance in{" "}
                <strong>{finding.repo_name}</strong>.
              </TierOption>

              <TierOption
                value="project"
                id="ab-project"
                title="This defect in this project"
                recommended={recommended === "project"}
                disabled={!groups.project}
              >
                One issue covering every occurrence of{" "}
                <strong>{groups.project?.identity_key ?? finding.scanner_name}</strong> in{" "}
                <strong>
                  {groups.project?.projects?.[0]?.repo_name ?? finding.repo_name}
                </strong>
                {groups.project && (
                  <>
                    {" — "}
                    <strong>
                      {groups.project.finding_count} occurrence
                      {groups.project.finding_count === 1 ? "" : "s"}
                    </strong>
                    {groups.project.location_count > 1 && (
                      <> in {groups.project.location_count} places</>
                    )}
                  </>
                )}
                . Every location is listed in the issue body.
              </TierOption>

              <TierOption
                value="org"
                id="ab-org"
                title="This defect in every project"
                recommended={recommended === "org"}
                disabled={!groups.org}
              >
                One issue covering the same defect everywhere it was found
                {groups.org && (
                  <>
                    {" — "}
                    <strong>
                      {groups.org.finding_count} occurrence
                      {groups.org.finding_count === 1 ? "" : "s"}
                    </strong>
                    {" across "}
                    <strong>
                      {groups.org.project_count} project
                      {groups.org.project_count === 1 ? "" : "s"}
                    </strong>
                  </>
                )}
                . Locations are listed per project.
              </TierOption>
            </RadioGroup>

            {groupError && (
              <p className="text-xs text-danger-text">
                {groupError}. Retry, or file this finding on its own.
              </p>
            )}

            {tier === "project" && groups.project?.exceeds_threshold && (
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>This defect is wider than one project</AlertTitle>
                <AlertDescription>
                  It affects {groups.project.project_count} projects, above the
                  escalation threshold of {groups.project.escalation_threshold}. Filing
                  at project level means {groups.project.project_count - 1} more issues
                  for the same defect. The body says so, but &ldquo;every project&rdquo;
                  is likely the right choice.
                </AlertDescription>
              </Alert>
            )}

            {summary && summary.members.length > 1 && (
              <Alert>
                <AlertTitle>Two scanners, one defect</AlertTitle>
                <AlertDescription>
                  A reviewer approved treating{" "}
                  <span className="font-mono text-xs">{summary.members.join(", ")}</span>{" "}
                  as the same defect, so this issue covers findings from all of them.
                </AlertDescription>
              </Alert>
            )}

            {summary && summary.locations_omitted > 0 && (
              <Alert>
                <AlertTitle>
                  {summary.locations_omitted} location
                  {summary.locations_omitted === 1 ? "" : "s"} will not be listed
                </AlertTitle>
                <AlertDescription>
                  The body lists the first {summary.location_count - summary.locations_omitted}{" "}
                  of {summary.location_count} and says how many it left out. The count is
                  complete; the list is not.
                </AlertDescription>
              </Alert>
            )}

            {summary && !summary.org_scoped && tier !== "specific" && (
              <Alert>
                <AlertTitle>These figures are tenant-wide</AlertTitle>
                <AlertDescription>
                  No organization filter was in effect, so {summary.finding_count} covers
                  every organization in this tenant — not just the current one. The issue
                  body states it that way.
                </AlertDescription>
              </Alert>
            )}
          </div>

          {/* Deficiency level — the severity-shaped field, and a loaded one */}
          <div className="space-y-3">
            <Label className="text-base font-semibold">Deficiency Level</Label>
            <p className="text-sm text-muted-foreground">
              Defaults from the finding&apos;s severity. The default never goes above
              Control Deficiency: a scanner hit is evidence of a control weakness, not a
              determination of one.
            </p>
            <Select
              value={levelOverride === null ? "default" : String(levelOverride)}
              onValueChange={(v) => setLevelOverride(v === "default" ? null : Number(v))}
              disabled={!config?.deficiency_levels?.length}
            >
              <SelectTrigger className="w-[420px]">
                <SelectValue placeholder="Loading levels…" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">
                  Default for {draft.severity}
                  {draft.deficiencyLevelName && !draft.deficiencyOverridden
                    ? ` — ${draft.deficiencyLevelName}`
                    : ""}
                </SelectItem>
                {(config?.deficiency_levels ?? []).map((level) => (
                  <SelectItem key={level.id} value={String(level.id)}>
                    {level.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {escalated && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>
                  {draft.deficiencyLevelName} is an audit determination
                </AlertTitle>
                <AlertDescription>
                  Significant Deficiency and Material Weakness are terms of art with
                  reporting consequences, and this app is asserting one on your behalf if
                  you file at this level. Choose it only if that determination has
                  actually been made.
                </AlertDescription>
              </Alert>
            )}
          </div>

          {/* Executive Summary — custom_text4, required by category 10 */}
          <div className="space-y-2">
            <Label htmlFor="ab-exec-summary" className="text-base font-semibold">
              Executive Summary
            </Label>
            <p className="text-sm text-muted-foreground">
              One line for a reader who does not work in security: what is wrong and
              what it could cost. Generated from the scanner and severity — rewrite it
              if you know the business context. AuditBoard&apos;s form asks for under{" "}
              {summaryTarget} characters.
            </p>
            <Input
              id="ab-exec-summary"
              value={executiveSummary}
              onChange={(e) => setSummaryEdit(e.target.value)}
              placeholder="e.g. Password left in our code — outsiders could get in"
            />
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span className={summaryOverTarget ? "text-warning-text" : undefined}>
                {executiveSummary.trim().length} / {summaryTarget} characters
                {summaryOverTarget && " — over the form's guidance, which AuditBoard does not enforce"}
              </span>
              {summaryEdit !== null && (
                <button
                  type="button"
                  className="underline"
                  onClick={() => setSummaryEdit(null)}
                >
                  Reset to generated
                </button>
              )}
            </div>
          </div>

          {(config?.unstamped_required_fields?.length ?? 0) > 0 && (
            <Alert>
              <AlertTitle>This issue will land incomplete</AlertTitle>
              <AlertDescription className="space-y-1">
                <p>
                  {config?.issue_category_name ?? "This category"} requires{" "}
                  <span className="font-mono text-xs">
                    {config?.unstamped_required_fields.join(", ")}
                  </span>
                  , and this app has no configured value for{" "}
                  {config?.unstamped_required_fields.length === 1 ? "it" : "them"}.
                  AuditBoard accepts the issue anyway — it does not enforce its own
                  required fields over the API — so the record will need finishing by
                  hand in AuditBoard.
                </p>
              </AlertDescription>
            </Alert>
          )}

          {/* Exactly what AuditBoard will receive */}
          <div className="space-y-4 text-sm">
            <Field label="Title">
              <p className="font-medium">{draft.title}</p>
            </Field>

            <div className="grid grid-cols-2 gap-4">
              <Field label="Deficiency level">
                <span className="inline-flex items-center gap-2">
                  <Badge className={SEVERITY_TONE[draft.severity].soft}>
                    {draft.deficiencyLevelName ?? "—"}
                  </Badge>
                  {draft.deficiencyOverridden && (
                    <span className="text-xs text-muted-foreground">
                      overridden from the severity default
                    </span>
                  )}
                </span>
              </Field>
              <Field label="Filed under">
                <span className="text-xs">
                  {config?.issue_category_name ?? "—"}
                  <span className="font-mono text-muted-foreground">
                    {config?.issue_category_id ? ` (${config.issue_category_id})` : ""}
                  </span>
                  {config?.source_type && config?.source_id && (
                    <>
                      {", attached to "}
                      <span className="font-mono">
                        {config.source_type} {config.source_id}
                      </span>
                    </>
                  )}
                  {", status "}
                  <span className="font-mono">{config?.create_status ?? "—"}</span>
                </span>
              </Field>
            </div>

            <Field label="Description">
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs text-muted-foreground">
                {draft.description}
              </pre>
            </Field>

            {draft.locationText && (
              <Field
                label={
                  tier === "org"
                    ? `Locations — ${summary?.location_count ?? 0} across ${
                        summary?.project_count ?? 0
                      } project${summary?.project_count === 1 ? "" : "s"}`
                    : `Locations — ${summary?.location_count ?? 0} in this project`
                }
              >
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs text-muted-foreground">
                  {draft.locationText}
                </pre>
                <p className="text-xs text-muted-foreground">
                  Appended to the body by the server, from the same measurement it counted
                  from — so the list and the count cannot drift apart. Paths are shown
                  relative to the repository, with the scanner&apos;s temporary directory
                  stripped, because a path under a per-scan directory stops resolving as
                  soon as the scan is gone.
                </p>
              </Field>
            )}

            <p className="text-xs text-muted-foreground">
              A provenance footer is appended by the server — reference finding ID, tier,
              defect identity, the occurrence and project counts it measured at filing
              time, and your identity. It is not built here so the numbers that get
              written are ones the server counted.
            </p>
          </div>
        </div>

        <DialogFooter className="gap-2 sm:justify-between">
          <Button variant="outline" size="sm" onClick={handleCopyDescription}>
            <ClipboardCopy className="h-4 w-4" />
            Copy issue text
          </Button>
          <div className="flex items-center gap-3">
            {blockedReason ? (
              <span className="text-xs text-muted-foreground">{blockedReason}</span>
            ) : (
              armed && (
                <span className="text-xs font-medium text-danger-text">
                  This creates the issue in AuditBoard now.
                </span>
              )
            )}
            <Button
              size="sm"
              variant={armed ? "destructive" : "default"}
              onClick={handleFile}
              disabled={!!blockedReason || filing}
            >
              {filing && <Loader2 className="h-4 w-4 animate-spin" />}
              {armed ? "Confirm — create issue" : "Create AuditBoard Issue"}
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

/**
 * One tier choice.
 *
 * The recommendation is marked rather than enforced. The volume rule knows how
 * many projects a defect touches and nothing else — it does not know that one
 * of them is being decommissioned next month — so it advises and a person
 * decides. A tier is disabled only when its measurement failed to load, since
 * choosing it would mean filing a grouped issue with no measured count behind
 * it.
 */
function TierOption({
  value,
  id,
  title,
  recommended,
  disabled,
  children,
}: {
  value: string;
  id: string;
  title: string;
  recommended?: boolean;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className={`flex items-start space-x-3 p-3 rounded-md border ${
        disabled ? "opacity-50" : "hover:bg-muted/50 cursor-pointer"
      }`}
    >
      <RadioGroupItem value={value} id={id} className="mt-1" disabled={disabled} />
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <Label htmlFor={id} className="font-medium cursor-pointer">
            {title}
          </Label>
          {recommended && (
            <Badge variant="outline" className="text-xs">
              Recommended
            </Badge>
          )}
        </div>
        <p className="text-sm text-muted-foreground">{children}</p>
      </div>
    </div>
  );
}
