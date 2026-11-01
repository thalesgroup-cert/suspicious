import { test, expect, type Page } from "@playwright/test";

// Self-contained: every API call is mocked, only the Vite dev server is needed.

const ROW = {
  id: 7,
  reporter_email: "bob@corp.test",
  status: "DONE",
  info: "Credential harvesting mail",
  artifact: "http://phish.evil.com/login",
  created_at: "2026-04-01T10:00:00Z",
  tests_done: 3,
  type: "URL",
  result: "Suspicious",
  is_challengeable: false,
  is_challenged: false,
};

const ASSESSMENT = {
  result: "Dangerous",
  sub_class: "CREDENTIAL_PHISHING",
  tier: "high",
  runner_up: null,
  model_version: "v1",
  analysed_at: "2026-04-01T10:00:00Z",
  reads: "body only",
  similar_cases: [],
  campaign: { ref: "261031-865a1", size: 9 },
  cross_check: { facts: [{ kind: "rule", text: "Decisive rule: deny-listed" }], disagrees: false },
};

async function setup(page: Page, aiAssessment: unknown) {
  await page.route("**/api/auth/me/", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ id: 1, username: "alice", email: "alice@corp.test", groups: ["CERT"] }),
    })
  );
  await page.route("**/api/investigations/**", (route) => {
    const detail = /\/investigations\/\d+\/$/.test(route.request().url());
    const body = detail
      ? {
          ...ROW,
          analyzer_reports: [],
          case_infos: {
            score: 8, confidence: 90, classification: "Dangerous",
            score_ai: 7, confidence_ai: 80, classification_ai: "Dangerous", category_ai: "phishing",
          },
          ai_assessment: aiAssessment,
        }
      : { count: 1, next: null, previous: null, results: [ROW] };
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

test("shows the AI model assessment section when ai_assessment is present", async ({ page }) => {
  await setup(page, ASSESSMENT);
  await page.goto("/investigation");
  await page.getByText("Credential harvesting mail").click();

  await expect(page.getByRole("heading", { name: "AI model assessment" })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText("High", { exact: true })).toBeVisible();
  await expect(page.getByText("Campaign 261031-865a1, 9 mails")).toBeVisible();
  await expect(page.getByText("AI classifier")).toHaveCount(0);
});

test("keeps the legacy AI classifier caption when ai_assessment is null", async ({ page }) => {
  await setup(page, null);
  await page.goto("/investigation");
  await page.getByText("Credential harvesting mail").click();

  await expect(page.getByText("AI classifier")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole("heading", { name: "AI model assessment" })).toHaveCount(0);
});
