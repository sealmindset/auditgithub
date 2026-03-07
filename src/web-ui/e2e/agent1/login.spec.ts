import { test, expect, mockUnauthenticatedAPI, MOCK_PROVIDERS } from "../fixtures/auth.fixture";

test.describe("Login Page", () => {
  test.beforeEach(async ({ page }) => {
    await mockUnauthenticatedAPI(page);
    await page.goto("/login");
  });

  test("renders the login page with branding", async ({ page }) => {
    await expect(page.locator("text=AuditGitHub")).toBeVisible();
    await expect(page.locator("text=Security Scanning & Analysis Platform")).toBeVisible();
  });

  test("displays SSO provider buttons from API", async ({ page }) => {
    await expect(page.getByRole("button", { name: /Sign in with Azure AD/i })).toBeVisible();
  });

  test("shows 'No SSO providers' message when none configured", async ({ page }) => {
    await page.route("**/api/proxy/auth/providers", (route) =>
      route.fulfill({ json: { providers: [] } }),
    );
    await page.goto("/login");
    await expect(page.locator("text=No SSO providers configured")).toBeVisible();
  });

  test("shows loading spinner while fetching providers", async ({ page }) => {
    await page.route("**/api/proxy/auth/providers", async (route) => {
      await new Promise((r) => setTimeout(r, 500));
      return route.fulfill({ json: MOCK_PROVIDERS });
    });
    await page.goto("/login");
    const spinner = page.locator(".animate-spin");
    await expect(spinner.first()).toBeVisible({ timeout: 2000 });
  });

  test("SSO button navigates to provider login URL", async ({ page }) => {
    const [request] = await Promise.all([
      page.waitForEvent("request", (r) => r.url().includes("/auth/login/azure-ad")),
      page.getByRole("button", { name: /Sign in with Azure AD/i }).click(),
    ]);
    expect(request.url()).toContain("/api/proxy/auth/login/azure-ad");
  });

  test("displays Emergency Access link", async ({ page }) => {
    await expect(page.locator("text=Emergency Access")).toBeVisible();
  });

  test("clicking Emergency Access shows break-glass form", async ({ page }) => {
    await page.locator("text=Emergency Access").click();
    await expect(page.locator("text=Emergency Break Glass Access")).toBeVisible();
    await expect(page.getByLabel("Email Address")).toBeVisible();
    await expect(page.getByLabel("Local Password")).toBeVisible();
    await expect(page.getByRole("button", { name: /Sign In \(Emergency Access\)/i })).toBeVisible();
  });

  test("break-glass form validates required fields", async ({ page }) => {
    await page.locator("text=Emergency Access").click();
    // The submit button should be present, HTML5 validation handles required
    const emailInput = page.getByLabel("Email Address");
    const passwordInput = page.getByLabel("Local Password");
    await expect(emailInput).toHaveAttribute("required", "");
    await expect(passwordInput).toHaveAttribute("required", "");
  });

  test("break-glass form shows error on invalid credentials", async ({ page }) => {
    await page.route("**/api/proxy/auth/break-glass/login", (route) =>
      route.fulfill({ status: 401, json: { detail: "Invalid credentials" } }),
    );
    await page.locator("text=Emergency Access").click();
    await page.getByLabel("Email Address").fill("bad@test.com");
    await page.getByLabel("Local Password").fill("wrong");
    await page.getByRole("button", { name: /Sign In \(Emergency Access\)/i }).click();
    await expect(page.locator("text=Invalid credentials")).toBeVisible();
  });

  test("break-glass form shows connection error on network failure", async ({ page }) => {
    await page.route("**/api/proxy/auth/break-glass/login", (route) =>
      route.abort("connectionrefused"),
    );
    await page.locator("text=Emergency Access").click();
    await page.getByLabel("Email Address").fill("user@test.com");
    await page.getByLabel("Local Password").fill("password");
    await page.getByRole("button", { name: /Sign In \(Emergency Access\)/i }).click();
    await expect(page.locator("text=Connection error")).toBeVisible();
  });

  test("'Back to Normal Login' returns from break-glass form", async ({ page }) => {
    await page.locator("text=Emergency Access").click();
    await expect(page.locator("text=Emergency Break Glass Access")).toBeVisible();
    await page.getByRole("button", { name: /Back to Normal Login/i }).click();
    await expect(page.locator("text=Emergency Break Glass Access")).not.toBeVisible();
    await expect(page.getByRole("button", { name: /Sign in with Azure AD/i })).toBeVisible();
  });

  test("break-glass form clears inputs when switching back", async ({ page }) => {
    await page.locator("text=Emergency Access").click();
    await page.getByLabel("Email Address").fill("test@test.com");
    await page.getByLabel("Local Password").fill("secret");
    await page.getByRole("button", { name: /Back to Normal Login/i }).click();
    await page.locator("text=Emergency Access").click();
    await expect(page.getByLabel("Email Address")).toHaveValue("");
    await expect(page.getByLabel("Local Password")).toHaveValue("");
  });

  test("shows loading state during break-glass submission", async ({ page }) => {
    await page.route("**/api/proxy/auth/break-glass/login", async (route) => {
      await new Promise((r) => setTimeout(r, 1000));
      return route.fulfill({ status: 401, json: { detail: "Invalid" } });
    });
    await page.locator("text=Emergency Access").click();
    await page.getByLabel("Email Address").fill("user@test.com");
    await page.getByLabel("Local Password").fill("password");
    await page.getByRole("button", { name: /Sign In \(Emergency Access\)/i }).click();
    await expect(page.locator("text=Signing In...")).toBeVisible();
  });

  test("footer text is present", async ({ page }) => {
    await expect(page.locator("text=security policies and terms of use")).toBeVisible();
  });
});
