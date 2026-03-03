import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import type { ScanRunner } from "./scanRunner";
import type { NormalizedFinding } from "./diagnosticProvider";

interface GateConfig {
  max_findings?: number;
  max_flows?: number;
  max_severity?: string;
  max_counts?: Record<string, number>;
  require_no_kev?: boolean;
  max_epss?: number;
  respect_vex?: boolean;
  include_history?: boolean;
}

interface PolicyConfig {
  version: number;
  policy: { mode: string; short_circuit_fail: boolean };
  gates: Record<string, GateConfig>;
}

export interface PolicyResult {
  passed: boolean;
  failures: string[];
  gateResults: Array<{ gate: string; status: string; reason: string }>;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const GATE_TO_SCANNER: Record<string, string> = {
  secrets: "gitleaks",
  trivy_fs: "trivy",
  grype: "grype",
};

export class PolicyChecker {
  private scanRunner: ScanRunner;

  constructor(scanRunner: ScanRunner) {
    this.scanRunner = scanRunner;
  }

  async check(workspacePath: string): Promise<PolicyResult> {
    const policyPath = this.findPolicyFile(workspacePath);
    if (!policyPath) {
      return {
        passed: true,
        failures: [],
        gateResults: [
          { gate: "-", status: "skip", reason: "No policy.yaml found" },
        ],
      };
    }

    const policy = this.loadPolicy(policyPath);
    if (!policy) {
      return {
        passed: false,
        failures: ["Failed to parse policy.yaml"],
        gateResults: [],
      };
    }

    // Run workspace scan to get findings
    const findings = await this.scanRunner.scanWorkspace(workspacePath);

    const mode = policy.policy?.mode || "fail";
    const shortCircuit = policy.policy?.short_circuit_fail || false;
    const gateResults: Array<{ gate: string; status: string; reason: string }> =
      [];
    const failures: string[] = [];

    for (const [gateName, gateCfg] of Object.entries(policy.gates || {})) {
      const result = this.evaluateGate(gateName, gateCfg, findings);
      gateResults.push(result);
      if (result.status === "fail") {
        failures.push(`${gateName}: ${result.reason}`);
        if (shortCircuit) break;
      }
    }

    return {
      passed: failures.length === 0 || mode === "warn",
      failures,
      gateResults,
    };
  }

  private evaluateGate(
    gateName: string,
    cfg: GateConfig,
    allFindings: NormalizedFinding[]
  ): { gate: string; status: string; reason: string } {
    const scannerName = GATE_TO_SCANNER[gateName] || gateName;
    const gateFindings = allFindings.filter((f) => f.scanner === scannerName);

    // max_findings
    if (cfg.max_findings !== undefined && gateFindings.length > cfg.max_findings) {
      return {
        gate: gateName,
        status: "fail",
        reason: `${gateFindings.length} findings exceed max ${cfg.max_findings}`,
      };
    }

    // max_flows
    if (cfg.max_flows !== undefined && gateFindings.length > cfg.max_flows) {
      return {
        gate: gateName,
        status: "fail",
        reason: `${gateFindings.length} flows exceed max ${cfg.max_flows}`,
      };
    }

    // max_severity
    if (cfg.max_severity) {
      const threshold = SEVERITY_ORDER[cfg.max_severity.toLowerCase()] ?? 3;
      for (const f of gateFindings) {
        const fSev = SEVERITY_ORDER[f.severity.toLowerCase()] ?? 0;
        if (fSev >= threshold) {
          return {
            gate: gateName,
            status: "fail",
            reason: `Finding with severity '${f.severity}' exceeds max '${cfg.max_severity}'`,
          };
        }
      }
    }

    // max_counts
    if (cfg.max_counts) {
      for (const [sev, maxCount] of Object.entries(cfg.max_counts)) {
        const actual = gateFindings.filter(
          (f) => f.severity.toLowerCase() === sev.toLowerCase()
        ).length;
        if (actual > maxCount) {
          return {
            gate: gateName,
            status: "fail",
            reason: `${actual} ${sev} findings exceed max ${maxCount}`,
          };
        }
      }
    }

    return {
      gate: gateName,
      status: "pass",
      reason: `${gateFindings.length} findings within thresholds`,
    };
  }

  private findPolicyFile(workspacePath: string): string | null {
    let dir = workspacePath;
    while (true) {
      const candidate = path.join(dir, "policy.yaml");
      if (fs.existsSync(candidate)) return candidate;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return null;
  }

  private loadPolicy(filePath: string): PolicyConfig | null {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      // Simple YAML parsing for the policy structure
      // In production, use a proper YAML parser — for the extension we parse
      // the known structure with a lightweight approach
      return this.parseSimpleYaml(content);
    } catch {
      return null;
    }
  }

  private parseSimpleYaml(content: string): PolicyConfig | null {
    // Use JSON-compatible parsing via line-by-line state machine
    // This handles the known policy.yaml structure
    try {
      const lines = content.split("\n").filter((l) => !l.trim().startsWith("#") && l.trim());
      const result: any = { gates: {} };
      let currentSection = "";
      let currentGate = "";
      let inMaxCounts = false;

      for (const line of lines) {
        const trimmed = line.trim();
        const indent = line.length - line.trimStart().length;

        if (trimmed.startsWith("version:")) {
          result.version = parseInt(trimmed.split(":")[1].trim());
        } else if (trimmed === "policy:") {
          currentSection = "policy";
          result.policy = {};
        } else if (trimmed === "allowlist:") {
          currentSection = "allowlist";
        } else if (trimmed === "gates:") {
          currentSection = "gates";
        } else if (trimmed === "overrides:") {
          currentSection = "overrides";
        } else if (currentSection === "policy" && indent >= 2) {
          const [key, ...valParts] = trimmed.split(":");
          const val = valParts.join(":").trim();
          if (key.trim() === "mode") result.policy.mode = val;
          if (key.trim() === "short_circuit_fail") result.policy.short_circuit_fail = val === "true";
        } else if (currentSection === "gates") {
          if (indent === 2 && trimmed.endsWith(":")) {
            currentGate = trimmed.slice(0, -1).trim();
            result.gates[currentGate] = {};
            inMaxCounts = false;
          } else if (indent === 4 && trimmed === "max_counts:") {
            inMaxCounts = true;
            result.gates[currentGate].max_counts = {};
          } else if (indent === 6 && inMaxCounts && currentGate) {
            const [key, ...valParts] = trimmed.split(":");
            const val = valParts.join(":").trim();
            result.gates[currentGate].max_counts[key.trim()] = parseInt(val);
          } else if (indent === 4 && currentGate) {
            inMaxCounts = false;
            const [key, ...valParts] = trimmed.split(":");
            const val = valParts.join(":").trim();
            const k = key.trim();
            if (val === "true") result.gates[currentGate][k] = true;
            else if (val === "false") result.gates[currentGate][k] = false;
            else if (/^\d+$/.test(val)) result.gates[currentGate][k] = parseInt(val);
            else if (/^\d+\.\d+$/.test(val)) result.gates[currentGate][k] = parseFloat(val);
            else result.gates[currentGate][k] = val;
          }
        }
      }
      return result;
    } catch {
      return null;
    }
  }
}
