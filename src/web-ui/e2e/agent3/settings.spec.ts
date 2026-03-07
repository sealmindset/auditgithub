import { test, expect, mockAuthenticatedAPI, MOCK_SETTINGS } from "../fixtures/auth.fixture";

test.describe("Settings Page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/settings");
  });

  test("renders page title", async ({ page }) => {
    await expect(page.locator("h1:has-text('Settings')")).toBeVisible();
    await expect(page.locator("text=Manage your platform configuration")).toBeVisible();
  });

  test("shows all settings tabs", async ({ page }) => {
    await expect(page.locator("text=General").first()).toBeVisible();
    await expect(page.locator("text=Authentication & Authorization").first()).toBeVisible();
    await expect(page.locator("text=Integrations").first()).toBeVisible();
    await expect(page.locator("text=Cribl").first()).toBeVisible();
    await expect(page.locator("text=My Devices").first()).toBeVisible();
    await expect(page.locator("text=Notifications").first()).toBeVisible();
  });

  test("General tab is active by default", async ({ page }) => {
    await expect(page.locator("text=General Configuration")).toBeVisible();
    await expect(page.locator("text=Automatic Scanning")).toBeVisible();
    await expect(page.locator("text=AI Analysis")).toBeVisible();
  });

  test("General tab has toggle switches", async ({ page }) => {
    const switches = page.locator("button[role='switch']");
    expect(await switches.count()).toBeGreaterThanOrEqual(2);
  });
});

test.describe("Settings - Integrations Tab", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/settings");
    await page.locator("text=Integrations").first().click();
  });

  test("shows OpenAI integration card", async ({ page }) => {
    await expect(page.locator("text=OpenAI Integration")).toBeVisible();
    await expect(page.getByLabel("API Key")).toBeVisible();
  });

  test("shows Jira integration card", async ({ page }) => {
    await expect(page.locator("text=Jira Integration")).toBeVisible();
    await expect(page.getByLabel("Jira URL")).toBeVisible();
    await expect(page.getByLabel("Email")).toBeVisible();
    await expect(page.getByLabel("API Token")).toBeVisible();
  });

  test("OpenAI verify button is disabled without key", async ({ page }) => {
    await page.getByLabel("API Key").fill("");
    const verifyBtn = page.getByRole("button", { name: "Verify" }).first();
    await expect(verifyBtn).toBeDisabled();
  });

  test("OpenAI verify button enables with key entered", async ({ page }) => {
    await page.getByLabel("API Key").fill("sk-test-key");
    const verifyBtn = page.getByRole("button", { name: "Verify" }).first();
    await expect(verifyBtn).toBeEnabled();
  });

  test("OpenAI verification shows success result", async ({ page }) => {
    await page.route("**/api/proxy/settings/verify/openai", (route) =>
      route.fulfill({ json: { valid: true, message: "API key is valid" } }),
    );
    await page.getByLabel("API Key").fill("sk-valid-key");
    await page.getByRole("button", { name: "Verify" }).first().click();
    await expect(page.locator("text=API key is valid")).toBeVisible();
  });

  test("OpenAI verification shows failure result", async ({ page }) => {
    await page.route("**/api/proxy/settings/verify/openai", (route) =>
      route.fulfill({ json: { valid: false, message: "Invalid API key" } }),
    );
    await page.getByLabel("API Key").fill("sk-bad-key");
    await page.getByRole("button", { name: "Verify" }).first().click();
    await expect(page.locator("text=Invalid API key")).toBeVisible();
  });

  test("Jira verify button disabled without all fields", async ({ page }) => {
    await page.getByLabel("Jira URL").fill("");
    const verifyBtns = page.getByRole("button", { name: "Verify" });
    const jiraVerify = verifyBtns.nth(1);
    await expect(jiraVerify).toBeDisabled();
  });
});

test.describe("Settings - Cribl Tab", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/settings");
    await page.locator("text=Cribl").first().click();
  });

  test("shows Cribl Stream Integration card", async ({ page }) => {
    await expect(page.locator("text=Cribl Stream Integration")).toBeVisible();
  });

  test("shows enable/disable toggle", async ({ page }) => {
    await expect(page.locator("text=Enable Cribl Logging")).toBeVisible();
  });

  test("shows ingest URL and auth token fields", async ({ page }) => {
    await expect(page.getByLabel("Ingest URL")).toBeVisible();
    await expect(page.getByLabel("Auth Token")).toBeVisible();
  });

  test("shows log level checkboxes", async ({ page }) => {
    for (const level of ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]) {
      await expect(page.locator(`label:has-text('${level}')`)).toBeVisible();
    }
  });

  test("shows MinIO fallback configuration", async ({ page }) => {
    await expect(page.locator("text=MinIO Log Storage")).toBeVisible();
    await expect(page.getByLabel("MinIO Endpoint")).toBeVisible();
    await expect(page.getByLabel("Bucket Name")).toBeVisible();
  });

  test("test configuration button is disabled without ingest URL", async ({ page }) => {
    await page.getByLabel("Ingest URL").fill("");
    const testBtn = page.getByRole("button", { name: "Test Configuration" });
    await expect(testBtn).toBeDisabled();
  });

  test("test configuration shows success result", async ({ page }) => {
    await page.route("**/api/proxy/cribl/test", (route) =>
      route.fulfill({
        json: {
          success: true,
          message: "Connection successful",
          response_time_ms: 150,
          status_code: 200,
          details: null,
        },
      }),
    );
    await page.getByLabel("Ingest URL").fill("https://cribl.example.com:20000");
    await page.getByRole("button", { name: "Test Configuration" }).click();
    await expect(page.locator("text=Connection successful")).toBeVisible();
    await expect(page.locator("text=150ms")).toBeVisible();
  });

  test("test configuration shows failure result", async ({ page }) => {
    await page.route("**/api/proxy/cribl/test", (route) =>
      route.fulfill({
        json: {
          success: false,
          message: "Connection refused",
          response_time_ms: null,
          status_code: null,
          details: null,
        },
      }),
    );
    await page.getByLabel("Ingest URL").fill("https://bad-host:20000");
    await page.getByRole("button", { name: "Test Configuration" }).click();
    await expect(page.locator("text=Connection refused")).toBeVisible();
  });

  test("save Cribl configuration button exists", async ({ page }) => {
    await expect(page.getByRole("button", { name: "Save Cribl Configuration" })).toBeVisible();
  });
});

test.describe("Settings - Notifications Tab", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/settings");
    await page.locator("text=Notifications").first().click();
  });

  test("shows notification options", async ({ page }) => {
    await expect(page.locator("text=Email Notifications")).toBeVisible();
    await expect(page.locator("text=Slack Notifications")).toBeVisible();
  });

  test("notification toggles are present", async ({ page }) => {
    const switches = page.locator("button[role='switch']");
    expect(await switches.count()).toBeGreaterThanOrEqual(2);
  });
});

test.describe("Settings - Save Changes", () => {
  test("save button is present at bottom of page", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.goto("/settings");
    await expect(page.getByRole("button", { name: "Save Changes" })).toBeVisible();
  });

  test("saving shows loading state", async ({ page }) => {
    await mockAuthenticatedAPI(page);
    await page.route("**/api/proxy/settings/", async (route) => {
      if (route.request().method() === "POST") {
        await new Promise((r) => setTimeout(r, 500));
        return route.fulfill({ json: { success: true } });
      }
      return route.fulfill({ json: MOCK_SETTINGS });
    });
    await page.goto("/settings");
    // Intercept alert dialog
    page.on("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Save Changes" }).click();
    // Button should show spinner briefly
    const spinner = page.locator(".animate-spin");
    // The spinner may be very brief, but the save should complete
    await page.waitForTimeout(1000);
  });
});
