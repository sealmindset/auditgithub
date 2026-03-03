import * as vscode from "vscode";
import type { AghClient } from "./aghClient";

const SECRET_KEY_TOKEN = "agh.accessToken";
const SECRET_KEY_REFRESH = "agh.refreshToken";

export class DeviceFlowAuth {
  private secrets: vscode.SecretStorage;
  private cachedToken: string | null = null;

  constructor(context: vscode.ExtensionContext) {
    this.secrets = context.secrets;
  }

  isAuthenticated(): boolean {
    return this.cachedToken !== null;
  }

  async getToken(): Promise<string | null> {
    if (this.cachedToken) {
      return this.cachedToken;
    }
    const stored = await this.secrets.get(SECRET_KEY_TOKEN);
    if (stored) {
      this.cachedToken = stored;
      return stored;
    }
    return null;
  }

  async login(client: AghClient): Promise<boolean> {
    // Step 1: Request device code
    const deviceData = await client.requestDeviceCode();
    if (!deviceData) {
      return false;
    }

    const { device_code, user_code, verification_uri_complete, interval, expires_in } =
      deviceData;

    // Step 2: Open browser for user authorization
    const opened = await vscode.env.openExternal(
      vscode.Uri.parse(verification_uri_complete)
    );
    if (!opened) {
      vscode.window.showErrorMessage(
        `AGH: Could not open browser. Visit: ${verification_uri_complete}`
      );
    }

    // Step 3: Show code and poll for token
    return vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `AGH: Enter code ${user_code} in your browser`,
        cancellable: true,
      },
      async (progress, cancellation) => {
        const deadline = Date.now() + expires_in * 1000;
        let pollInterval = interval * 1000;

        while (Date.now() < deadline) {
          if (cancellation.isCancellationRequested) {
            return false;
          }

          await sleep(pollInterval);

          try {
            const tokenData = await client.pollDeviceToken(device_code);
            if (tokenData) {
              // Store tokens securely
              await this.secrets.store(SECRET_KEY_TOKEN, tokenData.access_token);
              if (tokenData.refresh_token) {
                await this.secrets.store(
                  SECRET_KEY_REFRESH,
                  tokenData.refresh_token
                );
              }
              this.cachedToken = tokenData.access_token;
              vscode.window.showInformationMessage(
                "AGH: Authentication successful!"
              );
              return true;
            }
          } catch (err: any) {
            const error = err.error || err.message || String(err);
            if (error === "authorization_pending") {
              progress.report({ message: `Waiting for authorization...` });
              continue;
            } else if (error === "slow_down") {
              pollInterval += 1000;
              continue;
            } else if (
              error === "expired_token" ||
              error === "access_denied"
            ) {
              vscode.window.showErrorMessage(
                `AGH: Authorization ${error.replace(/_/g, " ")}.`
              );
              return false;
            } else {
              vscode.window.showErrorMessage(
                `AGH: Authentication error — ${error}`
              );
              return false;
            }
          }
        }

        vscode.window.showErrorMessage("AGH: Device flow expired.");
        return false;
      }
    );
  }

  async logout(): Promise<void> {
    await this.secrets.delete(SECRET_KEY_TOKEN);
    await this.secrets.delete(SECRET_KEY_REFRESH);
    this.cachedToken = null;
    vscode.window.showInformationMessage("AGH: Logged out.");
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
