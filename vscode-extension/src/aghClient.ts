import * as vscode from "vscode";
import * as https from "https";
import * as http from "http";
import { DeviceFlowAuth } from "./auth";

export interface Finding {
  id: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  scanner_name?: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  code_snippet?: string;
  repo_name: string;
  risk_score?: number;
  risk_level?: string;
}

export interface PaginatedResponse {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export class AghClient {
  private auth: DeviceFlowAuth;

  constructor(auth: DeviceFlowAuth) {
    this.auth = auth;
  }

  private getConfig() {
    const config = vscode.workspace.getConfiguration("agh");
    return {
      apiUrl: config.get<string>("apiUrl") || "http://localhost:8000",
      orgId: config.get<string>("organizationId") || "",
    };
  }

  async fetchFindings(
    page = 1,
    pageSize = 100,
    severity?: string
  ): Promise<Finding[] | null> {
    const { apiUrl, orgId } = this.getConfig();
    const token = await this.auth.getToken();
    if (!token) {
      return null;
    }

    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (severity) {
      params.set("severity", severity);
    }

    const url = `${apiUrl}/findings/paginated?${params.toString()}`;

    try {
      const data = await this.request<PaginatedResponse>(url, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          ...(orgId ? { "X-Organization-ID": orgId } : {}),
        },
      });
      return data.items;
    } catch (err) {
      vscode.window.showErrorMessage(`AGH: Failed to fetch findings — ${err}`);
      return null;
    }
  }

  async healthCheck(): Promise<boolean> {
    const { apiUrl } = this.getConfig();
    try {
      await this.request(`${apiUrl}/`, { method: "GET" });
      return true;
    } catch {
      return false;
    }
  }

  async requestDeviceCode(): Promise<{
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    expires_in: number;
    interval: number;
  } | null> {
    const { apiUrl } = this.getConfig();
    try {
      return await this.request(`${apiUrl}/auth/device/code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "auditgh-vscode",
          client_name: "AuditGH VS Code Extension",
          scopes: [],
        }),
      });
    } catch (err) {
      vscode.window.showErrorMessage(
        `AGH: Failed to initiate device flow — ${err}`
      );
      return null;
    }
  }

  async pollDeviceToken(deviceCode: string): Promise<{
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
  } | null> {
    const { apiUrl } = this.getConfig();
    const resp = await this.request<any>(`${apiUrl}/auth/device/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: "auditgh-vscode",
      }),
    });
    if (resp.error) {
      throw new Error(resp.error);
    }
    return resp;
  }

  private request<T>(
    url: string,
    options: {
      method: string;
      headers?: Record<string, string>;
      body?: string;
    }
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const transport = parsed.protocol === "https:" ? https : http;
      const req = transport.request(
        {
          hostname: parsed.hostname,
          port: parsed.port,
          path: parsed.pathname + parsed.search,
          method: options.method,
          headers: options.headers,
        },
        (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              try {
                resolve(JSON.parse(data));
              } catch {
                reject(new Error(`Invalid JSON response from ${url}`));
              }
            } else {
              try {
                const err = JSON.parse(data);
                if (err.error) {
                  reject(err);
                } else {
                  reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                }
              } catch {
                reject(new Error(`HTTP ${res.statusCode}: ${data}`));
              }
            }
          });
        }
      );
      req.on("error", reject);
      if (options.body) {
        req.write(options.body);
      }
      req.end();
    });
  }
}
