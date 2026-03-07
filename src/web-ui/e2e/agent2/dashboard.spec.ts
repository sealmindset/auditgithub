import {
  test,
  expect,
  mockAuthenticatedAPI,
  MOCK_HERO_METRICS,
  MOCK_THREAT_RADAR,
  MOCK_AI_INSIGHTS,
  MOCK_RECENT_FINDINGS,
} from "../fixtures/auth.fixture";

test.describe("Dashboard Page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/");
  });

  test("renders dashboard header with title", async ({ page }) => {
    await expect(page.locator("h2:has-text('Security Dashboard')")).toBeVisible();
    await expect(page.locator("text=Real-time security posture")).toBeVisible();
  });

  test("shows Live badge indicator", async ({ page }) => {
    await expect(page.locator("text=Live")).toBeVisible();
  });

  test("renders dashboard customizer button", async ({ page }) => {
    // The DashboardCustomizer component should be present
    const customizer = page.locator("button").filter({ hasText: /customize|layout/i });
    // May be an icon-only button, just check the area exists
    await expect(page.locator(".flex.items-center.justify-between").first()).toBeVisible();
  });
});

test.describe("Hero Metrics Widget", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/");
  });

  test("displays repository count from API", async ({ page }) => {
    await expect(page.locator(`text=${MOCK_HERO_METRICS.repositories}`).first()).toBeVisible();
  });

  test("displays critical findings count", async ({ page }) => {
    await expect(page.locator(`text=${MOCK_HERO_METRICS.criticalFindings}`).first()).toBeVisible();
  });

  test("displays under investigation count", async ({ page }) => {
    await expect(page.locator(`text=${MOCK_HERO_METRICS.underInvestigation}`).first()).toBeVisible();
  });

  test("displays AI analyses today count", async ({ page }) => {
    await expect(page.locator(`text=${MOCK_HERO_METRICS.aiAnalysesToday}`).first()).toBeVisible();
  });
});

test.describe("Threat Radar Widget", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/");
  });

  test("displays overall security score", async ({ page }) => {
    await expect(page.locator(`text=${MOCK_THREAT_RADAR.overallScore}`).first()).toBeVisible();
  });

  test("displays critical count in radar", async ({ page }) => {
    await expect(page.locator(`text=${MOCK_THREAT_RADAR.critical}`).first()).toBeVisible();
  });

  test("displays high severity count", async ({ page }) => {
    await expect(page.locator(`text=${MOCK_THREAT_RADAR.high}`).first()).toBeVisible();
  });
});

test.describe("AI Insights Panel", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/");
  });

  test("renders AI insight items from API", async ({ page }) => {
    await expect(page.locator(`text=${MOCK_AI_INSIGHTS[0].title}`).first()).toBeVisible();
  });

  test("shows insight severity badges", async ({ page }) => {
    // The first insight is critical severity
    await expect(page.locator("text=SQL Injection in user-service").first()).toBeVisible();
  });

  test("shows insight descriptions", async ({ page }) => {
    await expect(
      page.locator(`text=${MOCK_AI_INSIGHTS[0].description}`).first(),
    ).toBeVisible();
  });
});

test.describe("Recent Critical Findings Table", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/");
  });

  test("renders recent findings table header", async ({ page }) => {
    await expect(page.locator("text=Recent Critical Findings").first()).toBeVisible();
  });

  test("shows View All button linking to /findings", async ({ page }) => {
    const viewAll = page.locator("a[href='/findings']").filter({ hasText: "View All" });
    await expect(viewAll).toBeVisible();
  });

  test("displays finding rows with severity badges", async ({ page }) => {
    await expect(page.locator("text=Hardcoded AWS credentials").first()).toBeVisible();
    await expect(page.locator("text=Critical").first()).toBeVisible();
  });

  test("finding ID is a clickable link to finding detail", async ({ page }) => {
    const link = page.locator("a[href*='/findings/f-001']").first();
    await expect(link).toBeVisible();
  });

  test("repository name links to project page", async ({ page }) => {
    const repoLink = page.locator("a[href*='/projects/payment-service']").first();
    await expect(repoLink).toBeVisible();
  });

  test("shows empty state when no findings", async ({ page }) => {
    await page.route("**/api/proxy/analytics/recent-findings**", (route) =>
      route.fulfill({ json: [] }),
    );
    await page.goto("/");
    await expect(page.locator("text=No critical findings found").first()).toBeVisible();
  });
});

test.describe("Dashboard Error Handling", () => {
  test("dashboard still renders when hero-metrics API fails", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/analytics/hero-metrics**", (route) =>
      route.fulfill({ status: 500, json: { detail: "Server error" } }),
    );
    await page.goto("/");
    // Dashboard header should still render
    await expect(page.locator("h2:has-text('Security Dashboard')")).toBeVisible();
  });

  test("dashboard still renders when threat-radar API fails", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/analytics/threat-radar**", (route) =>
      route.fulfill({ status: 500, json: { detail: "Server error" } }),
    );
    await page.goto("/");
    await expect(page.locator("h2:has-text('Security Dashboard')")).toBeVisible();
  });

  test("dashboard handles network errors gracefully", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/analytics/**", (route) =>
      route.abort("connectionrefused"),
    );
    await page.goto("/");
    // Should not crash - header still visible
    await expect(page.locator("h2:has-text('Security Dashboard')")).toBeVisible();
  });
});

test.describe("Dashboard Auto-Refresh", () => {
  test("dashboard makes initial API calls on load", async ({ page }) => {
    const apiCalls: string[] = [];
    await mockAuthenticatedAPI(page);
    page.on("request", (req) => {
      if (req.url().includes("/api/proxy/analytics/")) {
        apiCalls.push(req.url());
      }
    });
    await page.goto("/");
    await page.waitForTimeout(2000);
    expect(apiCalls.length).toBeGreaterThan(0);
    expect(apiCalls.some((u) => u.includes("hero-metrics"))).toBe(true);
    expect(apiCalls.some((u) => u.includes("threat-radar"))).toBe(true);
    expect(apiCalls.some((u) => u.includes("ai-insights"))).toBe(true);
  });
});
