import * as vscode from "vscode";
import { AghClient } from "./aghClient";
import { DeviceFlowAuth } from "./auth";
import { DiagnosticProvider } from "./diagnosticProvider";
import { FindingsTreeProvider } from "./findingsTreeProvider";
import { ScanRunner } from "./scanRunner";
import { StatusBarManager } from "./statusBar";
import { AghCodeLensProvider } from "./codeLensProvider";
import { PolicyChecker } from "./policyChecker";

let diagnosticProvider: DiagnosticProvider;
let findingsTreeProvider: FindingsTreeProvider;
let scanRunner: ScanRunner;
let statusBar: StatusBarManager;
let client: AghClient;
let auth: DeviceFlowAuth;

export function activate(context: vscode.ExtensionContext) {
  auth = new DeviceFlowAuth(context);
  client = new AghClient(auth);
  diagnosticProvider = new DiagnosticProvider();
  findingsTreeProvider = new FindingsTreeProvider();
  scanRunner = new ScanRunner(diagnosticProvider, findingsTreeProvider);
  statusBar = new StatusBarManager();

  const codeLensProvider = new AghCodeLensProvider(diagnosticProvider);
  const policyChecker = new PolicyChecker(scanRunner);

  // Register tree view
  vscode.window.registerTreeDataProvider(
    "agh.findingsTree",
    findingsTreeProvider
  );

  // Register CodeLens
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider({ scheme: "file" }, codeLensProvider)
  );

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("agh.scanCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("No active file to scan.");
        return;
      }
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "AGH: Scanning current file...",
          cancellable: false,
        },
        async () => {
          await scanRunner.scanFile(editor.document.uri.fsPath);
          statusBar.update(diagnosticProvider.getSeverityCounts());
        }
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("agh.scanWorkspace", async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders?.length) {
        vscode.window.showWarningMessage("No workspace folder open.");
        return;
      }
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "AGH: Scanning workspace...",
          cancellable: false,
        },
        async () => {
          await scanRunner.scanWorkspace(folders[0].uri.fsPath);
          statusBar.update(diagnosticProvider.getSeverityCounts());
        }
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("agh.showFindings", () => {
      vscode.commands.executeCommand("agh.findingsTree.focus");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("agh.fetchServerFindings", async () => {
      if (!auth.isAuthenticated()) {
        const choice = await vscode.window.showWarningMessage(
          "Not authenticated. Login first?",
          "Login"
        );
        if (choice === "Login") {
          vscode.commands.executeCommand("agh.login");
        }
        return;
      }
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "AGH: Fetching server findings...",
          cancellable: false,
        },
        async () => {
          const findings = await client.fetchFindings();
          if (findings) {
            diagnosticProvider.setServerFindings(findings);
            findingsTreeProvider.refresh(diagnosticProvider.getAllFindings());
            statusBar.update(diagnosticProvider.getSeverityCounts());
            vscode.window.showInformationMessage(
              `AGH: Loaded ${findings.length} findings from server.`
            );
          }
        }
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("agh.login", async () => {
      await auth.login(client);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("agh.checkPolicy", async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders?.length) {
        vscode.window.showWarningMessage("No workspace folder open.");
        return;
      }
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "AGH: Checking policy gates...",
          cancellable: false,
        },
        async () => {
          const result = await policyChecker.check(folders[0].uri.fsPath);
          if (result.passed) {
            vscode.window.showInformationMessage("AGH: All policy gates passed.");
          } else {
            vscode.window.showErrorMessage(
              `AGH: Policy check failed — ${result.failures.join(", ")}`
            );
          }
        }
      );
    })
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const config = vscode.workspace.getConfiguration("agh");
      if (config.get<boolean>("autoScanOnSave")) {
        await scanRunner.scanFile(doc.uri.fsPath);
        statusBar.update(diagnosticProvider.getSeverityCounts());
      }
    })
  );

  // Initialize status bar
  statusBar.update({ critical: 0, high: 0, medium: 0, low: 0 });

  // Register disposables
  context.subscriptions.push(diagnosticProvider, statusBar);
}

export function deactivate() {
  diagnosticProvider?.dispose();
  statusBar?.dispose();
}
