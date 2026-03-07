import {
  test,
  expect,
  mockAuthenticatedAPI,
  MOCK_FINDINGS_PAGINATED,
} from "../fixtures/auth.fixture";

test.describe("Findings Page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/findings");
  });

  test("renders page title and finding count", async ({ page }) => {
    await expect(page.locator("h1:has-text('All Findings')")).toBeVisible();
    await expect(page.locator("text=3 security issues")).toBeVisible();
  });

  test("shows findings in table view by default", async ({ page }) => {
    // Table headers should be visible
    await expect(page.locator("text=Severity").first()).toBeVisible();
    await expect(page.locator("text=Title").first()).toBeVisible();
    await expect(page.locator("text=Repository").first()).toBeVisible();
    await expect(page.locator("text=Scanner").first()).toBeVisible();
  });

  test("displays finding rows with correct data", async ({ page }) => {
    const firstFinding = MOCK_FINDINGS_PAGINATED.items[0];
    await expect(page.locator(`text=${firstFinding.title}`).first()).toBeVisible();
    await expect(page.locator("text=semgrep").first()).toBeVisible();
    await expect(page.locator("text=user-service").first()).toBeVisible();
  });

  test("severity badges render with correct colors", async ({ page }) => {
    await expect(page.locator("text=Critical").first()).toBeVisible();
    await expect(page.locator("text=High").first()).toBeVisible();
    await expect(page.locator("text=Medium").first()).toBeVisible();
  });

  test("finding title links to detail page", async ({ page }) => {
    const link = page.locator("a[href='/findings/f-001']");
    await expect(link).toBeVisible();
  });

  test("repository name links to project page", async ({ page }) => {
    const link = page.locator("a[href='/projects/repo-001']");
    await expect(link).toBeVisible();
  });

  test("displays risk score badges", async ({ page }) => {
    // First finding has risk_score: 95
    await expect(page.locator("text=95").first()).toBeVisible();
  });

  test("file path with line number is displayed", async ({ page }) => {
    await expect(page.locator("text=src/auth/login.py").first()).toBeVisible();
    await expect(page.locator("text=:42").first()).toBeVisible();
  });

  test("status badges are rendered", async ({ page }) => {
    await expect(page.locator("text=Open").first()).toBeVisible();
  });
});

test.describe("Findings View Toggle", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/findings");
  });

  test("table view is active by default", async ({ page }) => {
    const tableBtn = page.getByRole("button", { name: /Table/i });
    await expect(tableBtn).toBeVisible();
  });

  test("can switch to scorecard view", async ({ page }) => {
    const scorecardBtn = page.getByRole("button", { name: /Scorecard/i });
    await scorecardBtn.click();
    // Scorecard component should now be rendered instead of DataTable
    // The table headers should disappear
    await expect(page.locator("th:has-text('Scanner')")).not.toBeVisible();
  });

  test("can switch back to table view from scorecard", async ({ page }) => {
    await page.getByRole("button", { name: /Scorecard/i }).click();
    await page.getByRole("button", { name: /Table/i }).click();
    await expect(page.locator("text=Severity").first()).toBeVisible();
  });
});

test.describe("Findings Search & Filter", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/findings");
  });

  test("search input is present with placeholder", async ({ page }) => {
    const search = page.getByPlaceholder(/Search.*findings/i);
    await expect(search).toBeVisible();
  });

  test("typing in search filters the table", async ({ page }) => {
    const search = page.getByPlaceholder(/Search.*findings/i);
    await search.fill("SQL Injection");
    // After filtering, only matching rows should show
    await expect(page.locator("text=SQL Injection in login").first()).toBeVisible();
  });
});

test.describe("Findings Loading State", () => {
  test("shows loading spinner when data is being fetched", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/findings/paginated**", async (route) => {
      await new Promise((r) => setTimeout(r, 1000));
      return route.fulfill({ json: MOCK_FINDINGS_PAGINATED });
    });
    await page.goto("/findings");
    const spinner = page.locator(".animate-spin");
    await expect(spinner.first()).toBeVisible({ timeout: 2000 });
  });

  test("renders table after data loads", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/findings");
    await expect(page.locator("h1:has-text('All Findings')")).toBeVisible();
    await expect(page.locator("text=SQL Injection in login").first()).toBeVisible();
  });
});

test.describe("Findings Error State", () => {
  test("handles API failure gracefully", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/findings/paginated**", (route) =>
      route.fulfill({ status: 500, json: { detail: "Server error" } }),
    );
    await page.goto("/findings");
    // Page should still render the title
    await expect(page.locator("h1:has-text('All Findings')")).toBeVisible();
  });
});
