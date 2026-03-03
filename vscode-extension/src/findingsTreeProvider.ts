import * as vscode from "vscode";
import type { NormalizedFinding } from "./diagnosticProvider";

type TreeItem = SeverityGroup | FindingItem;

class SeverityGroup extends vscode.TreeItem {
  constructor(
    public readonly severity: string,
    public readonly count: number,
    public readonly findings: NormalizedFinding[]
  ) {
    super(
      `${severity.toUpperCase()} (${count})`,
      vscode.TreeItemCollapsibleState.Expanded
    );
    this.contextValue = "severityGroup";
    this.iconPath = SeverityGroup.getIcon(severity);
  }

  private static getIcon(severity: string): vscode.ThemeIcon {
    switch (severity) {
      case "critical":
        return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
      case "high":
        return new vscode.ThemeIcon("warning", new vscode.ThemeColor("errorForeground"));
      case "medium":
        return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
      case "low":
        return new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground"));
      default:
        return new vscode.ThemeIcon("circle-outline");
    }
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(public readonly finding: NormalizedFinding) {
    super(finding.title, vscode.TreeItemCollapsibleState.None);
    this.contextValue = "finding";
    this.description = `${finding.scanner} — ${finding.filePath}:${finding.line}`;
    this.tooltip = new vscode.MarkdownString(
      `**${finding.title}**\n\n` +
        `- Severity: ${finding.severity}\n` +
        `- Scanner: ${finding.scanner}\n` +
        `- File: ${finding.filePath}:${finding.line}\n` +
        (finding.description ? `\n${finding.description}` : "")
    );

    // Click to navigate
    if (finding.filePath) {
      this.command = {
        command: "vscode.open",
        title: "Open Finding",
        arguments: [
          this.resolveUri(finding.filePath),
          {
            selection: new vscode.Range(
              Math.max(0, (finding.line || 1) - 1),
              0,
              Math.max(0, (finding.line || 1) - 1),
              0
            ),
          },
        ],
      };
    }
  }

  private resolveUri(filePath: string): vscode.Uri {
    if (filePath.startsWith("/")) {
      return vscode.Uri.file(filePath);
    }
    const folders = vscode.workspace.workspaceFolders;
    if (folders?.length) {
      return vscode.Uri.joinPath(folders[0].uri, filePath);
    }
    return vscode.Uri.file(filePath);
  }
}

export class FindingsTreeProvider implements vscode.TreeDataProvider<TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeItem | undefined | null>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: NormalizedFinding[] = [];

  refresh(findings: NormalizedFinding[]) {
    this.findings = findings;
    this._onDidChangeTreeData.fire(null);
  }

  getTreeItem(element: TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeItem): TreeItem[] {
    if (!element) {
      // Root level: severity groups
      return this.getSeverityGroups();
    }
    if (element instanceof SeverityGroup) {
      return element.findings.map((f) => new FindingItem(f));
    }
    return [];
  }

  private getSeverityGroups(): SeverityGroup[] {
    const order = ["critical", "high", "medium", "low", "info"];
    const groups: SeverityGroup[] = [];

    for (const severity of order) {
      const filtered = this.findings.filter(
        (f) => f.severity.toLowerCase() === severity
      );
      if (filtered.length > 0) {
        groups.push(new SeverityGroup(severity, filtered.length, filtered));
      }
    }
    return groups;
  }
}
