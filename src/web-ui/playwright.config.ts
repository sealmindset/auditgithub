import { defineConfig, devices } from "@playwright/test";

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || "http://localhost:3000";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 3,
  reporter: [
    ["html", { open: "never" }],
    ["list"],
  ],
  use: {
    baseURL: BASE_URL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "on-first-retry",
  },

  projects: [
    // Agent 1: Authentication & Navigation
    {
      name: "auth-navigation",
      testMatch: /agent1\/.+\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"] },
    },
    // Agent 2: Dashboard & Analytics
    {
      name: "dashboard-analytics",
      testMatch: /agent2\/.+\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"] },
    },
    // Agent 3: Data Pages & Admin
    {
      name: "data-management",
      testMatch: /agent3\/.+\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  webServer: process.env.CI
    ? undefined
    : {
        command: "npm run dev",
        url: BASE_URL,
        reuseExistingServer: true,
        timeout: 30_000,
      },
});
