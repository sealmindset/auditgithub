"use client";

/**
 * Shows that a finding has already been filed into AuditBoard.
 *
 * Exists to stop the second person filing the same thing. Someone opening a
 * finding that is already a GRC issue needs to see that before they reach for
 * the Report button, not after.
 *
 * Two kinds of record, kept visually distinct because they mean different
 * things to the reader:
 *
 * *   filed from this finding — this exact instance was reported; and
 * *   covered by a global filing made from a sibling finding, where the defect
 *     is reported but nobody opened this instance to do it.
 *
 * The status shown is the status at filing time. This reads a local record and
 * does not call AuditBoard, so an issue closed over there still shows as it
 * was created — the label says so rather than implying live state.
 */

import { useEffect, useState } from "react";
import { ExternalLink, ShieldCheck, Users } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { API_BASE, apiFetch } from "@/lib/api";

/** One row of `GET /findings/{id}/auditboard-issues`. */
export interface AuditBoardFilingRecord {
  issue_id: string;
  issue_uid: string | null;
  issue_url: string | null;
  issue_status: string | null;
  scope: "specific" | "global";
  occurrence_count: number;
  deficiency_level_id: number | null;
  deficiency_level_name: string | null;
  filed_by: string | null;
  filed_at: string | null;
  /** False when a sibling finding's global filing covers this one. */
  direct: boolean;
}

interface AuditBoardFiledBadgeProps {
  findingId?: string | null;
  /** Bump to re-read after a filing completes. */
  refreshKey?: number;
}

export function AuditBoardFiledBadge({
  findingId,
  refreshKey = 0,
}: AuditBoardFiledBadgeProps) {
  const [records, setRecords] = useState<AuditBoardFilingRecord[]>([]);

  useEffect(() => {
    if (!findingId) return;
    let cancelled = false;
    apiFetch(`${API_BASE}/findings/${findingId}/auditboard-issues`)
      // Nothing to show is the same as nothing to say: a filing history we
      // cannot read is not worth an error banner in a page header.
      .then((res) => (res.ok ? res.json() : []))
      .then((data: AuditBoardFilingRecord[]) => {
        if (!cancelled) setRecords(Array.isArray(data) ? data : []);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [findingId, refreshKey]);

  if (records.length === 0) return null;

  return (
    <TooltipProvider>
      <span className="flex flex-wrap items-center gap-1.5">
        {records.map((r) => {
          const label = r.issue_uid || `I#${r.issue_id}`;
          const Icon = r.direct ? ShieldCheck : Users;
          const badge = (
            <Badge
              variant={r.direct ? "default" : "secondary"}
              className="gap-1 font-mono text-xs"
            >
              <Icon className="h-3 w-3" />
              {label}
              {r.issue_url && <ExternalLink className="h-3 w-3 opacity-70" />}
            </Badge>
          );

          return (
            <Tooltip key={`${r.issue_id}-${r.direct}`}>
              <TooltipTrigger asChild>
                {r.issue_url ? (
                  <a
                    href={r.issue_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`Open AuditBoard issue ${label}`}
                  >
                    {badge}
                  </a>
                ) : (
                  badge
                )}
              </TooltipTrigger>
              <TooltipContent className="max-w-xs space-y-1">
                <p className="font-medium">
                  {r.direct
                    ? "Filed to AuditBoard from this finding"
                    : "Covered by a global filing from a sibling finding"}
                </p>
                <p className="text-xs">
                  Scope {r.scope}, spoke for {r.occurrence_count} finding
                  {r.occurrence_count === 1 ? "" : "s"} when filed.
                </p>
                {r.deficiency_level_name && (
                  <p className="text-xs">Level: {r.deficiency_level_name}</p>
                )}
                {r.filed_by && (
                  <p className="text-xs">
                    By {r.filed_by}
                    {r.filed_at ? ` on ${new Date(r.filed_at).toLocaleDateString()}` : ""}
                  </p>
                )}
                {r.issue_status && (
                  <p className="text-xs text-muted-foreground">
                    Status at filing: {r.issue_status}. Not kept in sync with
                    AuditBoard.
                  </p>
                )}
              </TooltipContent>
            </Tooltip>
          );
        })}
      </span>
    </TooltipProvider>
  );
}
