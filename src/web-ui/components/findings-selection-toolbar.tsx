"use client";

/**
 * The bar that appears above the findings table while rows are ticked.
 *
 * It states the count, states the limits of that count, and carries the two
 * actions a selection is for: create an exception, and report to AuditBoard.
 *
 * The count is the load-bearing part. Two things can make it mean less than it
 * appears to:
 *
 *   * **Filters.** Selection follows the filters. A row that was ticked and
 *     then filtered out of view is not included, which is the right behaviour
 *     but a silent change in a number — so it is named rather than left to be
 *     noticed.
 *   * **The table cap.** The findings table loads a capped slice of the
 *     database and filters over it in the browser. So "select all" means "all
 *     the rows that were loaded and pass my filters", not "all matching rows in
 *     the database". This is stated here and enforced as a gate in the
 *     AuditBoard dialog, where it matters most: an issue cannot be deleted.
 */

import { useState } from "react";
import { FileWarning, ShieldAlert, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SelectionAuditBoardDialog } from "@/components/SelectionAuditBoardDialog";
import { SelectionExceptionDialog } from "@/components/SelectionExceptionDialog";
import type { FindingLike } from "@/lib/finding-issue";

interface FindingsSelectionToolbarProps {
  /** Ticked rows that still pass the current filters. */
  findings: FindingLike[];
  /** Ticked rows a filter has since hidden. Not included in the actions. */
  hiddenCount: number;
  /** Rows currently passing the filters, for "N of M". */
  filteredCount: number;
  /** Findings loaded into the table. */
  loadedCount: number;
  /** Findings in the database. */
  totalCount: number;
  onClear: () => void;
  /** Re-read the filing index / findings after an action changes them. */
  onChanged?: () => void;
}

export function FindingsSelectionToolbar({
  findings,
  hiddenCount,
  filteredCount,
  loadedCount,
  totalCount,
  onClear,
  onChanged,
}: FindingsSelectionToolbarProps) {
  const [exceptionOpen, setExceptionOpen] = useState(false);
  const [auditBoardOpen, setAuditBoardOpen] = useState(false);

  const count = findings.length;
  // Truncated means the table never loaded every finding, so no filter applied
  // in the browser can be answered completely from it.
  const truncated = totalCount > 0 && loadedCount < totalCount;

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/50 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge variant="secondary" className="font-medium">
          {count.toLocaleString()} selected
        </Badge>
        <span className="text-muted-foreground">
          of {filteredCount.toLocaleString()} shown
        </span>
        {hiddenCount > 0 && (
          <span className="text-warning-text">
            • {hiddenCount.toLocaleString()} previously ticked row
            {hiddenCount === 1 ? "" : "s"} {hiddenCount === 1 ? "is" : "are"} hidden by
            the current filters and {hiddenCount === 1 ? "is" : "are"} not included
          </span>
        )}
        {truncated && (
          <span className="text-muted-foreground">
            • this table holds {loadedCount.toLocaleString()} of{" "}
            {totalCount.toLocaleString()} findings, so a filter here is not the whole
            database
          </span>
        )}
      </div>

      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => setExceptionOpen(true)}
          disabled={count === 0}
        >
          <FileWarning className="mr-2 h-4 w-4" />
          Create Exception
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setAuditBoardOpen(true)}
          disabled={count === 0}
        >
          <ShieldAlert className="mr-2 h-4 w-4" />
          Report To AuditBoard
        </Button>
        <Button variant="ghost" size="sm" onClick={onClear}>
          <X className="mr-2 h-4 w-4" />
          Clear
        </Button>
      </div>

      <SelectionExceptionDialog
        open={exceptionOpen}
        onOpenChange={setExceptionOpen}
        findings={findings}
        onDeleted={() => {
          // The deleted rows no longer exist, so a selection pointing at them
          // is stale. Cleared rather than left to fail on the next action.
          onClear();
          onChanged?.();
        }}
      />

      <SelectionAuditBoardDialog
        open={auditBoardOpen}
        onOpenChange={setAuditBoardOpen}
        findings={findings}
        tableTruncated={truncated}
        loadedCount={loadedCount}
        totalCount={totalCount}
        onFiled={onChanged}
      />
    </div>
  );
}
