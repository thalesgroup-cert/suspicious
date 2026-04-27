import { test, expect, type Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async function mockUnauthenticated(page: Page) {
  await page.route("**/api/auth/me/", (route) =>
    route.fulfill({ status: 401, body: JSON.stringify({ detail: "Not authenticated." }) })
  );
}

async function mockAuthenticated(page: Page) {
  await page.route("**/api/auth/me/", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: 1,
        username: "alice",
        email: "alice@corp.test",
        groups: ["CERT"],
      }),
    })
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("Login flow", () => {
  test("unauthenticated visit to / redirects to /login", async ({ page }) => {
    await mockUnauthenticated(page);
    await page.goto("/");
    await expect(page).toHaveURL(/\/login/);
  });

  test("login page renders username and password fields", async ({ page }) => {
    await mockUnauthenticated(page);
    await page.goto("/login");

    await expect(page.getByLabel(/username/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
  });

  test("submit button is disabled when fields are empty", async ({ page }) => {
    await mockUnauthenticated(page);
    await page.goto("/login");

    const btn = page.getByRole("button", { name: /sign in|log in|login/i });
    await expect(btn).toBeDisabled();
  });

  test("successful login navigates to home", async ({ page }) => {
    let meCallCount = 0;
    await page.route("**/api/auth/me/", (route) => {
      meCallCount++;
      if (meCallCount === 1) {
        // First call: check current auth — not logged in
        route.fulfill({ status: 401, body: JSON.stringify({ detail: "Not authenticated." }) });
      } else {
        // Subsequent calls: after login succeeds
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            id: 1,
            username: "alice",
            email: "alice@corp.test",
            groups: ["CERT"],
          }),
        });
      }
    });

    await page.route("**/api/auth/login/", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ expiry: "2099-01-01T00:00:00Z" }),
      })
    );

    await page.goto("/login");
    await expect(page.getByLabel(/username/i)).toBeVisible();

    await page.fill('[aria-label*="sername" i], [name="username"], input[type="text"]:first-of-type', "alice");
    await page.fill('[aria-label*="assword" i], [name="password"], input[type="password"]', "secret");

    await page.getByRole("button", { name: /sign in|log in|login/i }).click();

    await expect(page).toHaveURL("/", { timeout: 10_000 });
  });

  test("invalid credentials shows error message", async ({ page }) => {
    await mockUnauthenticated(page);
    await page.route("**/api/auth/login/", (route) =>
      route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Invalid credentials." }),
      })
    );

    await page.goto("/login");
    await expect(page.getByLabel(/username/i)).toBeVisible();

    await page.fill('[aria-label*="sername" i], input[type="text"]:first-of-type', "alice");
    await page.fill('[aria-label*="assword" i], input[type="password"]', "wrong");
    await page.getByRole("button", { name: /sign in|log in|login/i }).click();

    await expect(page.getByText(/invalid credentials/i)).toBeVisible({ timeout: 5_000 });
  });

  test("authenticated user visiting /login is redirected to /", async ({ page }) => {
    await mockAuthenticated(page);
    await page.goto("/login");
    await expect(page).toHaveURL("/", { timeout: 5_000 });
  });
});
