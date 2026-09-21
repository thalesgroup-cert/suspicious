import { test, expect, type Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// IOC road: bulk indicator submission → one case, lands on Submissions
// ---------------------------------------------------------------------------

const ME_RESPONSE = {
  id: 1,
  username: "alice",
  email: "alice@corp.test",
  groups: ["CERT"],
};

async function mockBackend(page: Page) {
  await page.route("**/api/auth/me/", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(ME_RESPONSE),
    })
  );

  await page.route("**/api/submit/config/**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify("suspicious@corp.test"),
    })
  );

  // The IOC-road submit endpoint — assert on the payload it receives.
  await page.route("**/api/submit/indicators/**", async (route) => {
    const body = JSON.parse(route.request().postData() ?? "{}");
    expect(body.indicators).toContain("8.8.8.8");
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        status: "success",
        case_id: 7,
        observable_count: 3,
        accepted: true,
        skipped: [],
      }),
    });
  });

  // Submissions page lands with ?q=7&open=7 — keep it from erroring.
  await page.route("**/api/submissions/**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ count: 0, next: null, previous: null, results: [] }),
    })
  );
}

test("bulk indicator submission creates one case and navigates to submissions", async ({
  page,
}) => {
  await mockBackend(page);

  await page.goto("/submit");

  await page.getByRole("button", { name: /indicators/i }).click();

  const textarea = page.getByRole("textbox").first();
  await textarea.fill("8.8.8.8\n1.1.1.1\nhttp://example.test");

  // Live preview counts the three parsed indicators.
  await expect(page.getByText(/3 indicator/i)).toBeVisible();

  await page.getByRole("button", { name: /^submit$/i }).click();

  await expect(page).toHaveURL(/\/submissions/);
  await expect(page.getByText(/3 indicator\(s\), case #7/i)).toBeVisible({
    timeout: 5_000,
  });
});
