import { test as base, Page, Route } from "@playwright/test";

/** Mock user returned by /api/proxy/auth/me */
export const MOCK_USER = {
  sub: "user-001",
  email: "testuser@auditgithub.dev",
  name: "Test User",
  role: "admin",
  access_type: "full",
  is_break_glass: false,
};

export const MOCK_VIEWER = {
  sub: "user-002",
  email: "viewer@auditgithub.dev",
  name: "Viewer User",
  role: "viewer",
  access_type: "full",
  is_break_glass: false,
};

/** Standard API mock payloads */
export const MOCK_PROVIDERS = {
  providers: [{ name: "azure-ad", display_name: "Azure AD" }],
};

export const MOCK_HERO_METRICS = {
  repositories: 42,
  criticalFindings: 7,
  underInvestigation: 3,
  aiAnalysesToday: 15,
  trends: {
    repositories: { value: 5, label: "+5 this week" },
    findings: { value: -2, label: "-2 resolved" },
    investigations: { value: 1, label: "+1 new" },
    aiAnalyses: { value: 15, label: "15 today" },
  },
};

export const MOCK_THREAT_RADAR = {
  critical: 7,
  high: 23,
  medium: 45,
  secrets: 4,
  abandoned: 8,
  staleContributors: 12,
  overallScore: 68,
};

export const MOCK_AI_INSIGHTS = [
  {
    id: "ins-1",
    type: "finding",
    title: "SQL Injection in user-service",
    description: "Critical SQL injection found in login handler",
    timestamp: new Date().toISOString(),
    severity: "critical",
    repoName: "user-service",
  },
  {
    id: "ins-2",
    type: "analysis",
    title: "Dependency vulnerability spike",
    description: "3 new CVEs affecting core dependencies",
    timestamp: new Date().toISOString(),
    severity: "high",
    repoName: "api-gateway",
  },
];

export const MOCK_RECENT_FINDINGS = [
  {
    id: "f-001-abcdef12",
    title: "Hardcoded AWS credentials in config.py",
    severity: "Critical",
    repo: "payment-service",
    status: "Open",
    date: "2026-03-05",
  },
  {
    id: "f-002-bcdef123",
    title: "XSS vulnerability in search component",
    severity: "High",
    repo: "web-frontend",
    status: "In Progress",
    date: "2026-03-04",
  },
];

export const MOCK_FINDINGS_PAGINATED = {
  items: [
    {
      id: "f-001",
      title: "SQL Injection in login",
      description: "Unsanitized input in SQL query",
      severity: "Critical",
      status: "Open",
      scanner_name: "semgrep",
      repo_name: "user-service",
      repository_id: "repo-001",
      file_path: "src/auth/login.py",
      line_start: 42,
      repo_pushed_at: "2026-03-01T10:00:00Z",
      file_last_commit_at: "2026-02-28T15:30:00Z",
      file_last_commit_author: "dev@example.com",
      is_archived: false,
      created_at: "2026-03-02T08:00:00Z",
      risk_score: 95,
      risk_level: "critical",
      snoozed_until: null,
      snooze_reason: null,
      investigation_status: null,
    },
    {
      id: "f-002",
      title: "Exposed API key in environment",
      description: "API key committed to repository",
      severity: "High",
      status: "Open",
      scanner_name: "gitleaks",
      repo_name: "api-gateway",
      repository_id: "repo-002",
      file_path: ".env.production",
      line_start: 5,
      repo_pushed_at: "2026-03-03T12:00:00Z",
      file_last_commit_at: null,
      file_last_commit_author: null,
      is_archived: false,
      created_at: "2026-03-03T14:00:00Z",
      risk_score: 82,
      risk_level: "high",
      snoozed_until: null,
      snooze_reason: null,
      investigation_status: null,
    },
    {
      id: "f-003",
      title: "Outdated dependency with known CVE",
      description: "lodash < 4.17.21 has prototype pollution",
      severity: "Medium",
      status: "Open",
      scanner_name: "npm-audit",
      repo_name: "web-frontend",
      repository_id: "repo-003",
      file_path: "package.json",
      line_start: null,
      repo_pushed_at: "2026-02-20T09:00:00Z",
      file_last_commit_at: null,
      file_last_commit_author: null,
      is_archived: false,
      created_at: "2026-03-01T11:00:00Z",
      risk_score: 55,
      risk_level: "medium",
      snoozed_until: null,
      snooze_reason: null,
      investigation_status: null,
    },
  ],
  total: 3,
  page: 1,
  page_size: 100,
  total_pages: 1,
  has_next: false,
  has_prev: false,
};

export const MOCK_PROJECTS = [
  {
    id: "repo-001",
    name: "user-service",
    visibility: "private",
    is_private: true,
    is_archived: false,
    last_commit_at: "2026-03-01T10:00:00Z",
    last_scanned_at: "2026-03-05T08:00:00Z",
    max_severity: "Critical",
    has_architecture: true,
    stats: { open_findings: 5 },
  },
  {
    id: "repo-002",
    name: "api-gateway",
    visibility: "internal",
    is_private: false,
    is_archived: false,
    last_commit_at: "2026-03-03T12:00:00Z",
    last_scanned_at: "2026-03-04T20:00:00Z",
    max_severity: "High",
    has_architecture: false,
    stats: { open_findings: 3 },
  },
  {
    id: "repo-003",
    name: "legacy-app",
    visibility: "private",
    is_private: true,
    is_archived: true,
    last_commit_at: "2024-01-15T10:00:00Z",
    last_scanned_at: null,
    max_severity: null,
    has_architecture: false,
    stats: { open_findings: 0 },
  },
];

export const MOCK_SETTINGS = {
  OPENAI_API_KEY: "sk-test-****",
  JIRA_URL: "https://test.atlassian.net",
  JIRA_EMAIL: "user@test.com",
  JIRA_API_TOKEN: "****",
};

export const MOCK_ORGANIZATIONS = [
  { id: "org-1", name: "SleepNumber", slug: "sleepnumber" },
  { id: "org-2", name: "TestOrg", slug: "testorg" },
];

/**
 * Intercept common API routes and return mock data.
 * Call this in beforeEach to set up the mock API layer.
 */
export async function mockAuthenticatedAPI(page: Page, user = MOCK_USER) {
  // Auth endpoint
  await page.route("**/api/proxy/auth/me", (route) =>
    route.fulfill({ json: user }),
  );

  // Providers
  await page.route("**/api/proxy/auth/providers", (route) =>
    route.fulfill({ json: MOCK_PROVIDERS }),
  );

  // Organizations
  await page.route("**/api/proxy/organizations**", (route) =>
    route.fulfill({ json: MOCK_ORGANIZATIONS }),
  );

  // Dashboard analytics
  await page.route("**/api/proxy/analytics/hero-metrics**", (route) =>
    route.fulfill({ json: MOCK_HERO_METRICS }),
  );
  await page.route("**/api/proxy/analytics/threat-radar**", (route) =>
    route.fulfill({ json: MOCK_THREAT_RADAR }),
  );
  await page.route("**/api/proxy/analytics/ai-insights**", (route) =>
    route.fulfill({ json: MOCK_AI_INSIGHTS }),
  );
  await page.route("**/api/proxy/analytics/recent-findings**", (route) =>
    route.fulfill({ json: MOCK_RECENT_FINDINGS }),
  );

  // Findings
  await page.route("**/api/proxy/findings/paginated**", (route) =>
    route.fulfill({ json: MOCK_FINDINGS_PAGINATED }),
  );

  // Projects / Repositories
  await page.route("**/api/proxy/projects/**", (route) =>
    route.fulfill({ json: MOCK_PROJECTS[0] }),
  );
  await page.route("**/api/proxy/projects/", (route) =>
    route.fulfill({ json: MOCK_PROJECTS }),
  );

  // Settings
  await page.route("**/api/proxy/settings/**", (route) =>
    route.fulfill({ json: MOCK_SETTINGS }),
  );
  await page.route("**/api/proxy/settings/", (route) =>
    route.fulfill({ json: MOCK_SETTINGS }),
  );

  // Cribl config
  await page.route("**/api/proxy/cribl/config", (route) =>
    route.fulfill({
      json: {
        id: "cribl-1",
        ingest_url: null,
        auth_token_set: false,
        verify_ssl: true,
        enabled: false,
        log_levels: ["INFO", "WARNING", "ERROR", "CRITICAL"],
        include_app_context: true,
        include_security_audit: true,
        minio_fallback: true,
        minio_endpoint: "http://minio:9000",
        minio_bucket: "auditgh-logs",
        minio_access_key_set: false,
        minio_secret_key_set: false,
        last_test_at: null,
        last_test_status: null,
        last_test_message: null,
      },
    }),
  );

  // Dashboard widget endpoints (catch-all for remaining analytics)
  await page.route("**/api/proxy/analytics/**", (route) =>
    route.fulfill({ json: [] }),
  );

  // Scheduler
  await page.route("**/api/proxy/scheduler/**", (route) =>
    route.fulfill({ json: [] }),
  );

  // Admin endpoints
  await page.route("**/api/proxy/admin/**", (route) =>
    route.fulfill({ json: [] }),
  );

  // RBAC
  await page.route("**/api/proxy/rbac/**", (route) =>
    route.fulfill({ json: { users: [], roles: [] } }),
  );
}

/** Mock an unauthenticated session (401 from /auth/me) */
export async function mockUnauthenticatedAPI(page: Page) {
  await page.route("**/api/proxy/auth/me", (route) =>
    route.fulfill({ status: 401, json: { detail: "Not authenticated" } }),
  );
  await page.route("**/api/proxy/auth/providers", (route) =>
    route.fulfill({ json: MOCK_PROVIDERS }),
  );
}

/** Extended test fixture with pre-configured auth mocking */
export const test = base.extend<{ authenticatedPage: Page }>({
  authenticatedPage: async ({ page }, use) => {
    await mockAuthenticatedAPI(page);
    await use(page);
  },
});

export { expect } from "@playwright/test";
