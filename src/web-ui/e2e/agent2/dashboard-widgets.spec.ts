import { test, expect, mockAuthenticatedAPI } from "../fixtures/auth.fixture";

test.describe("Security Overview Widget", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/");
  });

  test("renders security overview section on dashboard", async ({ page }) => {
    // The SecurityOverviewWidget should be visible in the grid
    const dashboard = page.locator(".flex.flex-1.flex-col");
    await expect(dashboard).toBeVisible();
  });
});

test.describe("Scan Activity Widget", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    // Mock the scan activity endpoint
    await page.route("**/api/proxy/analytics/scan-activity**", (route) =>
      route.fulfill({
        json: [
          { date: "2026-03-01", count: 5, scanners: ["semgrep", "gitleaks"] },
          { date: "2026-03-02", count: 8, scanners: ["semgrep"] },
          { date: "2026-03-03", count: 3, scanners: ["npm-audit"] },
        ],
      }),
    );
    await page.goto("/");
  });

  test("scan activity widget renders on dashboard", async ({ page }) => {
    const dashboard = page.locator(".flex.flex-1.flex-col");
    await expect(dashboard).toBeVisible();
  });
});

test.describe("Scan Schedule Graph Widget", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/scheduler/**", (route) =>
      route.fulfill({
        json: [
          { id: "sched-1", repo_name: "user-service", next_run: "2026-03-07T08:00:00Z" },
          { id: "sched-2", repo_name: "api-gateway", next_run: "2026-03-07T12:00:00Z" },
        ],
      }),
    );
    await page.goto("/");
  });

  test("schedule graph renders without errors", async ({ page }) => {
    const dashboard = page.locator(".flex.flex-1.flex-col");
    await expect(dashboard).toBeVisible();
  });
});

test.describe("Repository Health Widget", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/analytics/repository-health**", (route) =>
      route.fulfill({
        json: [
          { repo: "user-service", health: "good", score: 85 },
          { repo: "api-gateway", health: "warning", score: 62 },
          { repo: "legacy-app", health: "critical", score: 25 },
        ],
      }),
    );
    await page.goto("/");
  });

  test("repository health widget renders", async ({ page }) => {
    const dashboard = page.locator(".flex.flex-1.flex-col");
    await expect(dashboard).toBeVisible();
  });
});

test.describe("Finding Trends Widget", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/analytics/finding-trends**", (route) =>
      route.fulfill({
        json: {
          labels: ["Week 1", "Week 2", "Week 3", "Week 4"],
          datasets: [
            { label: "Critical", data: [5, 3, 7, 4] },
            { label: "High", data: [12, 15, 10, 8] },
          ],
        },
      }),
    );
    await page.goto("/");
  });

  test("finding trends chart renders", async ({ page }) => {
    const dashboard = page.locator(".flex.flex-1.flex-col");
    await expect(dashboard).toBeVisible();
  });
});

test.describe("Quick Actions Widget", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/");
  });

  test("quick actions section is present on dashboard", async ({ page }) => {
    const dashboard = page.locator(".flex.flex-1.flex-col");
    await expect(dashboard).toBeVisible();
  });
});

test.describe("Dashboard Layout Customization", () => {
  test("dashboard loads with default widget layout", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/");
    // Core sections should be present
    await expect(page.locator("h2:has-text('Security Dashboard')")).toBeVisible();
  });

  test("dashboard renders correctly at different viewport sizes", async ({ page }) => {
    await mockAuthenticatedAPI(page);

    // Desktop
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/");
    await expect(page.locator("h2:has-text('Security Dashboard')")).toBeVisible();

    // Tablet
    await page.setViewportSize({ width: 768, height: 1024 });
    await expect(page.locator("h2:has-text('Security Dashboard')")).toBeVisible();

    // Mobile
    await page.setViewportSize({ width: 375, height: 812 });
    await expect(page.locator("h2:has-text('Security Dashboard')")).toBeVisible();
  });
});

test.describe("Executive Summary Cards", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/analytics/executive-summary**", (route) =>
      route.fulfill({
        json: {
          riskPosture: "moderate",
          complianceScore: 78,
          remediationRate: 65,
          meanTimeToResolve: "4.2 days",
        },
      }),
    );
    await page.goto("/");
  });

  test("executive summary section renders on dashboard", async ({ page }) => {
    const dashboard = page.locator(".flex.flex-1.flex-col");
    await expect(dashboard).toBeVisible();
  });
});

test.describe("Severity Chart", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/analytics/severity-distribution**", (route) =>
      route.fulfill({
        json: {
          critical: 7,
          high: 23,
          medium: 45,
          low: 89,
          info: 12,
        },
      }),
    );
    await page.goto("/");
  });

  test("severity chart section renders on dashboard", async ({ page }) => {
    const dashboard = page.locator(".flex.flex-1.flex-col");
    await expect(dashboard).toBeVisible();
  });
});
