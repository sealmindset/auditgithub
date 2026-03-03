import * as vscode from "vscode";
import type { SeverityCounts } from "./diagnosticProvider";

export class StatusBarManager implements vscode.Disposable {
  private item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      50
    );
    this.item.command = "agh.showFindings";
    this.item.show();
  }

  update(counts: SeverityCounts) {
    const total = counts.critical + counts.high + counts.medium + counts.low;

    if (total === 0) {
      this.item.text = "$(shield) AGH: Clean";
      this.item.backgroundColor = undefined;
      this.item.tooltip = "No security findings";
      return;
    }

    const parts: string[] = [];
    if (counts.critical > 0) parts.push(`${counts.critical}C`);
    if (counts.high > 0) parts.push(`${counts.high}H`);
    if (counts.medium > 0) parts.push(`${counts.medium}M`);
    if (counts.low > 0) parts.push(`${counts.low}L`);

    this.item.text = `$(shield) AGH: ${parts.join(" ")}`;
    this.item.tooltip = `Security findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`;

    if (counts.critical > 0 || counts.high > 0) {
      this.item.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.errorBackground"
      );
    } else if (counts.medium > 0) {
      this.item.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.warningBackground"
      );
    } else {
      this.item.backgroundColor = undefined;
    }
  }

  dispose() {
    this.item.dispose();
  }
}
