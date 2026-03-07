import { test, expect, mockUnauthenticatedAPI, mockAuthenticatedAPI, MOCK_PROVIDERS } from "../fixtures/auth.fixture";

test.describe("Authentication Guard", () => {
  test("redirects unauthenticated user to /login from protected route", async ({ page }) => {
    await mockUnauthenticatedAPI(page);
    await page.goto("/");
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain("/login");
  });

  test("login redirect preserves original destination in query param", async ({ page }) => {
    await mockUnauthenticatedAPI(page);
    await page.goto("/findings");
    await page.waitForURL(/\/login\?redirect=/);
    expect(page.url()).toContain("redirect=%2Ffindings");
  });

  test("allows access to /login without authentication", async ({ page }) => {
    await mockUnauthenticatedAPI(page);
    await page.goto("/login");
    await expect(page.locator("text=AuditGitHub")).toBeVisible();
    await expect(page.locator("text=Security Scanning & Analysis Platform")).toBeVisible();
  });

  test("allows access to /invite paths without authentication", async ({ page }) => {
    await mockUnauthenticatedAPI(page);
    // The invite page should render without redirecting to login
    await page.route("**/api/proxy/**", (route) => {
      if (route.request().url().includes("/auth/me")) {
        return route.fulfill({ status: 401, json: { detail: "Not authenticated" } });
      }
      return route.fulfill({ json: {} });
    });
    await page.goto("/invite/test-token");
    // Should NOT redirect to /login
    await page.waitForTimeout(1000);
    expect(page.url()).toContain("/invite/test-token");
  });

  test("authenticated user accessing /login gets redirected to /", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/login");
    await page.waitForURL("/");
    expect(page.url()).not.toContain("/login");
  });

  test("shows loading spinner while checking auth", async ({ page }) => {
    // Delay the auth response to observe loading state
    await page.route("**/api/proxy/auth/me", async (route) => {
      await new Promise((r) => setTimeout(r, 500));
      return route.fulfill({ status: 401, json: { detail: "Not authenticated" } });
    });
    await page.route("**/api/proxy/auth/providers", (route) =>
      route.fulfill({ json: MOCK_PROVIDERS }),
    );
    await page.goto("/");
    // The spinner should be visible during loading
    const spinner = page.locator(".animate-spin");
    await expect(spinner.first()).toBeVisible({ timeout: 2000 });
  });
});
