import { test, expect, type Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const ME_CERT = {
  id: 1,
  username: "alice",
  email: "alice@corp.test",
  groups: ["CERT"],
};

const INVESTIGATIONS_LIST = {
  count: 1,
  next: null,
  previous: null,
  results: [
    {
      id: 7,
      reporter_email: "bob@corp.test",
      status: "DONE",
      info: "Suspicious credential harvesting page",
      artifact: "http://phish.evil.com/login",
      created_at: "2026-04-01T10:00:00Z",
      tests_done: 3,
      type: "URL",
      result: "Suspicious",
      is_challengeable: false,
      is_challenged: false,
    },
  ],
};

const INVESTIGATION_DETAIL = {
  ...INVESTIGATIONS_LIST.results[0],
  analyzer_reports: [
    {
      id: 1,
      cortex_job_id: "cj-001",
      type: "url",
      status: "SUCCESS",
      analyzer_name: "PhishingURLAnalyzer",
      analyzer_id: "PhishingURLAnalyzer_1_0",
      level: "malicious",
      confidence: 0.95,
      score: 0.95,
      category: "Phishing",
      categories: ["Phishing"],
      report_summary: {},
      report_taxonomy: {},
      report_full: {},
      target: null,
    },
  ],
  case_infos: { score: 0.95, confidence: 0.95, classification: "Phishing" },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function setupMocks(page: Page, { meGroups = ["CERT"] } = {}) {
  await page.route("**/api/auth/me/", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ...ME_CERT, groups: meGroups }),
    })
  );

  await page.route("**/api/investigations/**", (route) => {
    const url = route.request().url();
    // Detail route: /investigations/7/
    if (/\/investigations\/\d+\/$/.test(url)) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(INVESTIGATION_DETAIL),
      });
    } else {
      // List route
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(INVESTIGATIONS_LIST),
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("Case detail render (Investigation)", () => {
  test("renders investigation list for CERT user", async ({ page }) => {
    await setupMocks(page);
    await page.goto("/investigation");

    await expect(
      page.getByText(/phish\.evil\.com|bob@corp/i).first()
    ).toBeVisible({ timeout: 10_000 });
  });

  test("shows Suspicious result chip in the list", async ({ page }) => {
    await setupMocks(page);
    await page.goto("/investigation");

    await expect(page.getByText(/suspicious/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test("clicking a row opens the detail drawer", async ({ page }) => {
    await setupMocks(page);
    await page.goto("/investigation");

    // Wait for the row to appear, then click it
    const artifact = page.getByText(/phish\.evil\.com/i).first();
    await expect(artifact).toBeVisible({ timeout: 10_000 });
    await artifact.click();

    // The drawer should show the analyzer name
    await expect(
      page.getByText(/PhishingURLAnalyzer/i)
    ).toBeVisible({ timeout: 5_000 });
  });

  test("detail drawer shows analyzer confidence", async ({ page }) => {
    await setupMocks(page);
    await page.goto("/investigation");

    await page.getByText(/phish\.evil\.com/i).first().click();

    // The 95% confidence or score should render somewhere in the drawer
    await expect(
      page.getByText(/0\.95|95%|95/i).first()
    ).toBeVisible({ timeout: 5_000 });
  });

  test("non-elevated user cannot see the investigations list", async ({ page }) => {
    // Authenticated as regular user (no CERT/CISO/Admin group)
    await setupMocks(page, { meGroups: [] });
    await page.goto("/investigation");

    // Should be redirected or show an access denied indicator;
    // the investigations table should never load
    await expect(
      page.getByText(/phish\.evil\.com/i)
    ).not.toBeVisible({ timeout: 5_000 });
  });
});
