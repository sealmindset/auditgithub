import * as vscode from "vscode";
import * as cp from "child_process";
import * as path from "path";
import type { DiagnosticProvider, NormalizedFinding } from "./diagnosticProvider";
import type { FindingsTreeProvider } from "./findingsTreeProvider";

interface ScannerDef {
  binary: string;
  buildCmd: (target: string) => string[];
  parse: (stdout: string, target: string) => NormalizedFinding[];
}

const SCANNERS: Record<string, ScannerDef> = {
  gitleaks: {
    binary: "gitleaks",
    buildCmd: (t) => [
      "gitleaks",
      "detect",
      "--source",
      t,
      "--report-format",
      "json",
      "--report-path",
      "/dev/stdout",
      "--no-git",
    ],
    parse: (stdout, target) => {
      const data = safeParseJson(stdout);
      if (!Array.isArray(data)) return [];
      return data.map((item: any) => ({
        title: `[${item.RuleID || "secret"}] ${item.Description || "Secret detected"}`,
        severity: "critical",
        scanner: "gitleaks",
        filePath: item.File || "",
        line: item.StartLine || 1,
        column: item.StartColumn || 1,
        ruleId: item.RuleID,
        source: "local" as const,
      }));
    },
  },

  semgrep: {
    binary: "semgrep",
    buildCmd: (t) => ["semgrep", "scan", "--json", "--config", "auto", t],
    parse: (stdout) => {
      const data = safeParseJson(stdout);
      if (!data?.results) return [];
      const sevMap: Record<string, string> = {
        ERROR: "high",
        WARNING: "medium",
        INFO: "low",
      };
      return data.results.map((r: any) => ({
        title: r.extra?.message || r.check_id || "Finding",
        severity: sevMap[(r.extra?.severity || "WARNING").toUpperCase()] || "medium",
        scanner: "semgrep",
        filePath: r.path || "",
        line: r.start?.line || 1,
        column: r.start?.col || 1,
        ruleId: r.check_id,
        source: "local" as const,
      }));
    },
  },

  bandit: {
    binary: "bandit",
    buildCmd: (t) => ["bandit", "-r", t, "-f", "json", "-q"],
    parse: (stdout) => {
      const data = safeParseJson(stdout);
      if (!data?.results) return [];
      const sevMap: Record<string, string> = {
        HIGH: "high",
        MEDIUM: "medium",
        LOW: "low",
      };
      return data.results.map((r: any) => ({
        title: `[${r.test_id || "B000"}] ${r.issue_text || "Issue"}`,
        severity: sevMap[(r.issue_severity || "MEDIUM").toUpperCase()] || "medium",
        scanner: "bandit",
        filePath: r.filename || "",
        line: r.line_number || 1,
        column: 1,
        ruleId: r.test_id,
        source: "local" as const,
      }));
    },
  },

  checkov: {
    binary: "checkov",
    buildCmd: (t) => ["checkov", "-d", t, "-o", "json"],
    parse: (stdout) => {
      let data = safeParseJson(stdout);
      if (!data) return [];
      const frameworks = Array.isArray(data) ? data : [data];
      const findings: NormalizedFinding[] = [];
      for (const fw of frameworks) {
        for (const check of fw?.results?.failed_checks || []) {
          const lineRange = check.file_line_range || [1];
          findings.push({
            title: `[${check.check_id || "CKV"}] ${check.name || "IaC issue"}`,
            severity:
              (check.severity || "").toLowerCase() === "critical"
                ? "critical"
                : "medium",
            scanner: "checkov",
            filePath: check.file_path || "",
            line: lineRange[0] || 1,
            column: 1,
            ruleId: check.check_id,
            source: "local" as const,
          });
        }
      }
      return findings;
    },
  },

  trivy: {
    binary: "trivy",
    buildCmd: (t) => ["trivy", "fs", "-q", "-f", "json", "--scanners", "vuln", t],
    parse: (stdout) => {
      const data = safeParseJson(stdout);
      if (!data?.Results) return [];
      const sevMap: Record<string, string> = {
        CRITICAL: "critical",
        HIGH: "high",
        MEDIUM: "medium",
        LOW: "low",
      };
      const findings: NormalizedFinding[] = [];
      for (const result of data.Results) {
        for (const vuln of result.Vulnerabilities || []) {
          const pkg = vuln.PkgName || "";
          const ver = vuln.InstalledVersion || "";
          const fixed = vuln.FixedVersion ? ` -> ${vuln.FixedVersion}` : "";
          findings.push({
            title: `[${vuln.VulnerabilityID}] ${vuln.Title || "Vulnerability"} (${pkg}@${ver}${fixed})`,
            severity: sevMap[(vuln.Severity || "UNKNOWN").toUpperCase()] || "low",
            scanner: "trivy",
            filePath: result.Target || "",
            line: 1,
            column: 1,
            ruleId: vuln.VulnerabilityID,
            source: "local" as const,
          });
        }
      }
      return findings;
    },
  },
};

function safeParseJson(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export class ScanRunner {
  private diagnosticProvider: DiagnosticProvider;
  private treeProvider: FindingsTreeProvider;

  constructor(
    diagnosticProvider: DiagnosticProvider,
    treeProvider: FindingsTreeProvider
  ) {
    this.diagnosticProvider = diagnosticProvider;
    this.treeProvider = treeProvider;
  }

  async scanFile(filePath: string): Promise<NormalizedFinding[]> {
    // For file-level scanning, use semgrep and bandit (they support file targets)
    const config = vscode.workspace.getConfiguration("agh");
    const enabledScanners = config.get<string[]>("scanners") || Object.keys(SCANNERS);
    const fileScanners = ["semgrep", "bandit"];
    const toRun = enabledScanners.filter((s) => fileScanners.includes(s));

    const allFindings: NormalizedFinding[] = [];
    for (const name of toRun) {
      const scanner = SCANNERS[name];
      if (!scanner) continue;
      const findings = await this.runScanner(name, scanner, filePath);
      allFindings.push(...findings);
    }

    this.diagnosticProvider.setLocalFindings(allFindings);
    this.treeProvider.refresh(this.diagnosticProvider.getAllFindings());
    return allFindings;
  }

  async scanWorkspace(workspacePath: string): Promise<NormalizedFinding[]> {
    const config = vscode.workspace.getConfiguration("agh");
    const enabledScanners = config.get<string[]>("scanners") || Object.keys(SCANNERS);

    const allFindings: NormalizedFinding[] = [];
    for (const name of enabledScanners) {
      const scanner = SCANNERS[name];
      if (!scanner) continue;
      const findings = await this.runScanner(name, scanner, workspacePath);
      allFindings.push(...findings);
    }

    this.diagnosticProvider.setLocalFindings(allFindings);
    this.treeProvider.refresh(this.diagnosticProvider.getAllFindings());
    return allFindings;
  }

  private runScanner(
    name: string,
    scanner: ScannerDef,
    target: string
  ): Promise<NormalizedFinding[]> {
    return new Promise((resolve) => {
      const cmd = scanner.buildCmd(target);
      const proc = cp.spawn(cmd[0], cmd.slice(1), {
        cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
        env: { ...process.env },
      });

      let stdout = "";
      let stderr = "";

      proc.stdout.on("data", (data) => (stdout += data.toString()));
      proc.stderr.on("data", (data) => (stderr += data.toString()));

      proc.on("close", () => {
        try {
          const findings = scanner.parse(stdout, target);
          resolve(findings);
        } catch (err) {
          console.error(`AGH: ${name} parse error:`, err);
          resolve([]);
        }
      });

      proc.on("error", (err) => {
        if ((err as any).code === "ENOENT") {
          // Scanner binary not found — skip silently
        } else {
          console.error(`AGH: ${name} error:`, err);
        }
        resolve([]);
      });
    });
  }
}
