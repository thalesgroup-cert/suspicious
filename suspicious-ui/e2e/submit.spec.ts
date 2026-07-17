import { test, expect, type Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const ME_RESPONSE = {
  id: 1,
  username: "alice",
  email: "alice@corp.test",
  groups: ["CERT"],
};

async function mockAuthenticatedUser(page: Page) {
  await page.route("**/api/auth/me/", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(ME_RESPONSE) })
  );
}

async function mockSubmitConfig(page: Page) {
  // Route for the submit config endpoint (returns suspicious email address)
  await page.route("**/api/submit/config/**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify("suspicious@corp.test"),
    })
  );
  // Also catch any generic settings/config endpoint
  await page.route("**/api/**/config**", (route) => {
    if (!route.request().url().includes("auth")) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify("suspicious@corp.test"),
      });
    } else {
      route.continue();
    }
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("Case submission flow", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthenticatedUser(page);
    await mockSubmitConfig(page);
  });

  test("submit page renders both submission modes", async ({ page }) => {
    await page.goto("/submit");

    // Both mode selectors should be visible
    await expect(page.getByText(/file|email/i).first()).toBeVisible();
    await expect(page.getByText(/url|artifact|indicator/i).first()).toBeVisible();
  });

  test("file mode shows a drop zone by default", async ({ page }) => {
    await page.goto("/submit");
    await expect(page.getByText(/drop|drag|upload|choose|select/i).first()).toBeVisible();
  });

  test("switching to artifact mode shows text input", async ({ page }) => {
    await page.goto("/submit");

    // Click the artifact / URL mode button
    await page.getByText(/url|artifact|indicator/i).first().click();

    // A text input should appear
    const input = page.getByRole("textbox").first();
    await expect(input).toBeVisible();
  });

  test("submit button disabled when artifact input is empty", async ({ page }) => {
    await page.goto("/submit");
    await page.getByText(/url|artifact|indicator/i).first().click();

    const submitBtn = page.getByRole("button", { name: /submit|analyze|send/i });
    await expect(submitBtn).toBeDisabled();
  });

  test("fills artifact form and submits a URL", async ({ page }) => {
    let submissionPayload: unknown = null;

    // Intercept the URL submission endpoint
    await page.route("**/api/submit/**", async (route) => {
      submissionPayload = JSON.parse(route.request().postData() ?? "{}");
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          status: "success",
          accepted: true,
          submission_type: "url",
          result_type: "case",
          case_id: 42,
          message: "Submission accepted.",
        }),
      });
    });
    // Also catch the investigations / ioc submit route
    await page.route("**/api/ioc**", async (route) => {
      submissionPayload = JSON.parse(route.request().postData() ?? "{}");
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          status: "success",
          accepted: true,
          submission_type: "url",
          result_type: "case",
          case_id: 42,
          message: "Submission accepted.",
        }),
      });
    });

    await page.goto("/submit");
    await page.getByText(/url|artifact|indicator/i).first().click();

    const input = page.getByRole("textbox").first();
    await expect(input).toBeVisible();
    await input.fill("http://evil.example.com/phishing");

    const submitBtn = page.getByRole("button", { name: /submit|analyze|send/i });
    await expect(submitBtn).not.toBeDisabled();
    await submitBtn.click();

    // Success: either a snackbar or navigation away from submit page
    await expect(
      page.getByText(/accepted|success|submitted/i)
    ).toBeVisible({ timeout: 5_000 });
  });
});
