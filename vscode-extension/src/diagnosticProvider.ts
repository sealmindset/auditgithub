import * as vscode from "vscode";
import type { Finding } from "./aghClient";

export interface NormalizedFinding {
  id?: string;
  title: string;
  severity: string;
  scanner: string;
  filePath: string;
  line: number;
  endLine?: number;
  column: number;
  description?: string;
  ruleId?: string;
  source: "local" | "server";
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Information,
};

export class DiagnosticProvider implements vscode.Disposable {
  private collection: vscode.DiagnosticCollection;
  private localFindings: NormalizedFinding[] = [];
  private serverFindings: NormalizedFinding[] = [];

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("agh");
  }

  setLocalFindings(findings: NormalizedFinding[]) {
    this.localFindings = findings;
    this.updateDiagnostics();
  }

  setServerFindings(serverItems: Finding[]) {
    this.serverFindings = serverItems.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      scanner: f.scanner_name || "unknown",
      filePath: f.file_path || "",
      line: f.line_start || 1,
      endLine: f.line_end,
      column: 1,
      description: f.description,
      source: "server" as const,
    }));
    this.updateDiagnostics();
  }

  getAllFindings(): NormalizedFinding[] {
    return [...this.localFindings, ...this.serverFindings];
  }

  getSeverityCounts(): SeverityCounts {
    const all = this.getAllFindings();
    return {
      critical: all.filter((f) => f.severity === "critical").length,
      high: all.filter((f) => f.severity === "high").length,
      medium: all.filter((f) => f.severity === "medium").length,
      low: all.filter((f) => f.severity === "low").length,
    };
  }

  getFindingsForFile(filePath: string): NormalizedFinding[] {
    return this.getAllFindings().filter((f) => {
      if (!f.filePath) return false;
      return (
        f.filePath === filePath ||
        filePath.endsWith(f.filePath) ||
        f.filePath.endsWith(filePath.replace(/^\//, ""))
      );
    });
  }

  private updateDiagnostics() {
    // Clear all existing
    this.collection.clear();

    // Group findings by file
    const byFile = new Map<string, NormalizedFinding[]>();
    for (const f of this.getAllFindings()) {
      if (!f.filePath) continue;
      const existing = byFile.get(f.filePath) || [];
      existing.push(f);
      byFile.set(f.filePath, existing);
    }

    // Convert to diagnostics
    for (const [filePath, findings] of byFile) {
      const uri = this.resolveUri(filePath);
      if (!uri) continue;

      const diagnostics: vscode.Diagnostic[] = findings.map((f) => {
        const line = Math.max(0, (f.line || 1) - 1);
        const endLine = f.endLine ? Math.max(0, f.endLine - 1) : line;
        const range = new vscode.Range(line, 0, endLine, Number.MAX_SAFE_INTEGER);

        const diagnostic = new vscode.Diagnostic(
          range,
          `[${f.scanner}] ${f.title}`,
          SEVERITY_MAP[f.severity] ?? vscode.DiagnosticSeverity.Warning
        );
        diagnostic.source = "AGH";
        diagnostic.code = f.ruleId || f.scanner;
        return diagnostic;
      });

      this.collection.set(uri, diagnostics);
    }
  }

  private resolveUri(filePath: string): vscode.Uri | null {
    // Try absolute path first
    if (filePath.startsWith("/")) {
      return vscode.Uri.file(filePath);
    }
    // Resolve relative to workspace
    const folders = vscode.workspace.workspaceFolders;
    if (folders?.length) {
      return vscode.Uri.joinPath(folders[0].uri, filePath);
    }
    return null;
  }

  dispose() {
    this.collection.dispose();
  }
}
