import * as vscode from "vscode";
import type { DiagnosticProvider, NormalizedFinding } from "./diagnosticProvider";

export class AghCodeLensProvider implements vscode.CodeLensProvider {
  private diagnosticProvider: DiagnosticProvider;
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  constructor(diagnosticProvider: DiagnosticProvider) {
    this.diagnosticProvider = diagnosticProvider;
  }

  provideCodeLenses(
    document: vscode.TextDocument,
    _token: vscode.CancellationToken
  ): vscode.CodeLens[] {
    const findings = this.diagnosticProvider.getFindingsForFile(
      document.uri.fsPath
    );
    if (findings.length === 0) return [];

    // Group findings by line
    const byLine = new Map<number, NormalizedFinding[]>();
    for (const f of findings) {
      const line = Math.max(0, (f.line || 1) - 1);
      const existing = byLine.get(line) || [];
      existing.push(f);
      byLine.set(line, existing);
    }

    const lenses: vscode.CodeLens[] = [];
    for (const [line, lineFindings] of byLine) {
      const range = new vscode.Range(line, 0, line, 0);

      // Summary lens
      const counts = summarize(lineFindings);
      lenses.push(
        new vscode.CodeLens(range, {
          title: `$(shield) ${counts}`,
          command: "agh.showFindings",
          tooltip: lineFindings.map((f) => `[${f.severity}] ${f.title}`).join("\n"),
        })
      );

      // Details lens
      lenses.push(
        new vscode.CodeLens(range, {
          title: "Show Details",
          command: "workbench.actions.view.problems",
          tooltip: "Open Problems panel",
        })
      );
    }

    return lenses;
  }

  fire() {
    this._onDidChangeCodeLenses.fire();
  }
}

function summarize(findings: NormalizedFinding[]): string {
  const parts: string[] = [];
  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  const total = findings.length;
  const detail: string[] = [];
  for (const sev of ["critical", "high", "medium", "low"]) {
    if (counts[sev]) {
      detail.push(`${counts[sev]} ${sev}`);
    }
  }
  parts.push(`${total} finding${total === 1 ? "" : "s"}`);
  if (detail.length > 0) {
    parts.push(detail.join(", "));
  }
  return parts.join(": ");
}
