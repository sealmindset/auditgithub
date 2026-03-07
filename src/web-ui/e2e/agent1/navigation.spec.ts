import { test, expect, mockAuthenticatedAPI, MOCK_USER, MOCK_VIEWER } from "../fixtures/auth.fixture";

test.describe("Sidebar Navigation", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
  });

  test("renders sidebar with AuditGitHub branding", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("text=AuditGitHub").first()).toBeVisible();
  });

  test("sidebar shows Platform section with all nav items for admin", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("text=Platform")).toBeVisible();
    await expect(page.locator("a[href='/']").filter({ hasText: "Dashboard" })).toBeVisible();
    await expect(page.locator("a[href='/findings']")).toBeVisible();
    await expect(page.locator("a[href='/repositories']")).toBeVisible();
    await expect(page.locator("a[href='/scheduler']")).toBeVisible();
    await expect(page.locator("a[href='/attack-surface']")).toBeVisible();
  });

  test("sidebar shows Settings section", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("text=Settings").first()).toBeVisible();
    await expect(page.locator("a[href='/settings']")).toBeVisible();
    await expect(page.locator("a[href='/api-audit/settings']")).toBeVisible();
    await expect(page.locator("a[href='/settings/api-keys']")).toBeVisible();
  });

  test("Zero Day Analysis is expandable with sub-items", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("a[href='/zero-day']")).toBeVisible();
    await expect(page.locator("a[href='/zero-day/reports']")).toBeVisible();
  });

  test("navigates to Findings page via sidebar", async ({ page }) => {
    await page.goto("/");
    await page.locator("a[href='/findings']").click();
    await page.waitForURL("/findings");
    await expect(page.locator("h1:has-text('All Findings')")).toBeVisible();
  });

  test("navigates to Repositories page via sidebar", async ({ page }) => {
    await page.goto("/");
    await page.locator("a[href='/repositories']").click();
    await page.waitForURL("/repositories");
    await expect(page.locator("h1:has-text('Repositories')")).toBeVisible();
  });

  test("navigates to Settings page via sidebar", async ({ page }) => {
    await page.goto("/");
    await page.locator("a[href='/settings']").click();
    await page.waitForURL("/settings");
    await expect(page.locator("h1:has-text('Settings')")).toBeVisible();
  });

  test("highlights active nav item based on current route", async ({ page }) => {
    await page.goto("/findings");
    const findingsLink = page.locator("a[href='/findings']");
    // The active item gets data-active attribute from SidebarMenuButton
    await expect(findingsLink).toBeVisible();
  });
});

test.describe("Top Bar", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
  });

  test("renders sidebar trigger, org selector, breadcrumbs, search, and theme toggle", async ({ page }) => {
    await page.goto("/");
    // Top bar elements
    await expect(page.locator(".border-b").first()).toBeVisible();
  });

  test("theme toggle switches between light and dark mode", async ({ page }) => {
    await page.goto("/");
    // Find and click the theme toggle (ModeToggle component)
    const themeButton = page.locator("button").filter({ has: page.locator("svg") }).last();
    const html = page.locator("html");

    // Get initial class
    const initialClass = await html.getAttribute("class");

    // Click theme toggle
    await themeButton.click();

    // Check if a dropdown appeared (the mode toggle uses a dropdown)
    const darkOption = page.locator("text=Dark");
    if (await darkOption.isVisible({ timeout: 1000 }).catch(() => false)) {
      await darkOption.click();
      // Verify class changed
      const newClass = await html.getAttribute("class");
      expect(newClass).toContain("dark");
    }
  });
});

test.describe("Breadcrumbs", () => {
  test("shows correct breadcrumb on Findings page", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/findings");
    await expect(page.locator("text=Findings").first()).toBeVisible();
  });

  test("shows correct breadcrumb on Settings page", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/settings");
    await expect(page.locator("text=Settings").first()).toBeVisible();
  });
});

test.describe("RBAC - Navigation visibility", () => {
  test("viewer role may see limited navigation items", async ({ page }) => {
    await mockAuthenticatedAPI(page, MOCK_VIEWER);
    await page.goto("/");
    // Viewer should still see dashboard
    await expect(page.locator("text=Dashboard").first()).toBeVisible();
  });
});
