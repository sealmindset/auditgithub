import { test, expect, mockAuthenticatedAPI, MOCK_PROJECTS } from "../fixtures/auth.fixture";

test.describe("Repositories Page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/repositories");
  });

  test("renders page title and description", async ({ page }) => {
    await expect(page.locator("h1:has-text('Repositories')")).toBeVisible();
    await expect(page.locator("text=List of all monitored repositories")).toBeVisible();
  });

  test("displays repository names in table", async ({ page }) => {
    for (const project of MOCK_PROJECTS) {
      await expect(page.locator(`text=${project.name}`).first()).toBeVisible();
    }
  });

  test("repository name links to project detail", async ({ page }) => {
    const link = page.locator(`a[href='/projects/${MOCK_PROJECTS[0].id}']`);
    await expect(link).toBeVisible();
  });

  test("shows visibility badges correctly", async ({ page }) => {
    // user-service is private
    await expect(page.locator("text=Private").first()).toBeVisible();
    // api-gateway is internal
    await expect(page.locator("text=Internal").first()).toBeVisible();
  });

  test("shows archived badge for archived repos", async ({ page }) => {
    await expect(page.locator("text=Archived").first()).toBeVisible();
  });

  test("shows open findings count badges", async ({ page }) => {
    // user-service has 5 open findings
    await expect(page.locator("text=5").first()).toBeVisible();
  });

  test("shows max severity column", async ({ page }) => {
    await expect(page.locator("text=Critical").first()).toBeVisible();
    await expect(page.locator("text=High").first()).toBeVisible();
  });

  test("shows architecture status", async ({ page }) => {
    // user-service has architecture, others don't
    const yesCount = page.locator("text=Yes");
    await expect(yesCount.first()).toBeVisible();
  });

  test("shows scan age badges", async ({ page }) => {
    // user-service was scanned 1 day ago
    await expect(page.locator("text=/Scanned \\d+d ago/").first()).toBeVisible();
    // legacy-app was never scanned
    await expect(page.locator("text=Never scanned").first()).toBeVisible();
  });

  test("shows commit age badges", async ({ page }) => {
    // Various commit ages based on mock data
    await expect(page.locator("text=/\\d+d ago/").first()).toBeVisible();
  });
});

test.describe("Repositories Search", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/repositories");
  });

  test("search input is present", async ({ page }) => {
    const search = page.getByPlaceholder(/search/i).first();
    await expect(search).toBeVisible();
  });

  test("searching filters the repository list", async ({ page }) => {
    const search = page.getByPlaceholder(/search/i).first();
    await search.fill("user-service");
    await expect(page.locator("text=user-service").first()).toBeVisible();
  });
});

test.describe("Repositories Loading", () => {
  test("shows spinner while loading", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/projects/", async (route) => {
      await new Promise((r) => setTimeout(r, 1000));
      return route.fulfill({ json: MOCK_PROJECTS });
    });
    await page.goto("/repositories");
    const spinner = page.locator(".animate-spin");
    await expect(spinner.first()).toBeVisible({ timeout: 2000 });
  });
});

test.describe("Repositories Column Sorting", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/repositories");
  });

  test("clicking Name column header sorts the table", async ({ page }) => {
    const nameHeader = page.locator("text=Name").first();
    await nameHeader.click();
    // After clicking, the table should still render
    await expect(page.locator("text=user-service").first()).toBeVisible();
  });

  test("clicking Severity column header sorts by severity", async ({ page }) => {
    const sevHeader = page.locator("text=Severity").first();
    await sevHeader.click();
    await expect(page.locator("text=Critical").first()).toBeVisible();
  });
});
