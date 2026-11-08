import { test, expect, type Page } from "@playwright/test";

// Self-contained: every API call is mocked, only the Vite dev server is needed.
// Response shapes follow features/aiModel/api.ts and the api/ai_model_views serializers.

type Ver = { version_id: string; status: string; created_at: string; trigger: string };

const GATE_FAIL = {
  checks: {
    macro_f1: { passed: true, value: 0.93, threshold: 0.9 },
    campaign_heldout: { passed: false, value: 4, threshold: 1, detail: "too many Dangerous called Safe" },
  },
  candidate: null,
  baseline: null,
  campaign: { dangerous_called_safe: 4, baseline_dangerous_called_safe: 1, groups: 12, fallback: false },
  tier_cutoffs: { high: 0.9, medium: 0.6 },
};
const GATE_OK = {
  checks: { macro_f1: { passed: true, value: 0.94, threshold: 0.9 }, campaign_heldout: { passed: true, value: 0, threshold: 1 } },
  candidate: null,
  baseline: null,
  campaign: { dangerous_called_safe: 0, baseline_dangerous_called_safe: 1, groups: 12, fallback: false },
  tier_cutoffs: { high: 0.9, medium: 0.6 },
};

const summary = (v: Ver, extra: object = {}) => ({
  ...v,
  shadow_since: null,
  shadow_min_days: 7,
  recheck: null,
  ...extra,
});
const page_ = <T,>(results: T[]) => ({ count: results.length, next: null, previous: null, results });
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

type Mock = {
  active: Ver;
  previous: Ver | null;
  candidate: (Ver & { gate: unknown; eligible: boolean }) | null;
  shadow: Ver | null;
  conditions: string[];
  reviewed: boolean;
  jobState: "none" | "succeeded";
  promoteRefusal: string[] | null;
};

function status(m: Mock) {
  const job = {
    job_id: "j1", kind: "retrain", state: "succeeded", trigger: "manual", rows: 1200, excluded_rows: 30,
    started_at: "2026-11-01T10:00:00Z", finished_at: "2026-11-01T10:20:00Z", error: "",
  };
  return {
    active: summary(m.active),
    previous: m.previous ? summary(m.previous) : null,
    shadow: m.shadow ? summary(m.shadow, { shadow_since: "2026-10-20T10:00:00Z" }) : null,
    job_running: false,
    job_id: null,
    health: { ok: true, detail: "", checked_at: "2026-11-08T08:00:00Z" },
    breaker: { state: "closed", since: null },
    schedule: { enabled: true, interval_days: 30, next_run: "2026-12-01T00:00:00Z", backoff_until: null },
    counts: { candidate: m.candidate ? 1 : 0, shadow: m.shadow ? 1 : 0, active: 1, previous: m.previous ? 1 : 0, discarded: 0, failed: 0 },
    jobs: m.jobState === "succeeded" ? [job] : [],
    ledger: { by_source: { imap_folder: { Dangerous: 40, Safe: 60 } }, flagged: 2, trainable: 100 },
  };
}

function shadowBody(m: Mock) {
  if (!m.shadow) return { shadow: null };
  return {
    ...summary(m.shadow, { shadow_since: "2026-10-20T10:00:00Z" }),
    live_results: 300,
    agreement: { class: { agree: 280, total: 300 }, verdict: { agree: 290, total: 300 } },
    flips: {
      count: 1,
      results: [{ case_id: 55, flip: "critical", live_result: "Safe", would_be_result: "Dangerous", reviewable: true, reviewed: m.reviewed }],
    },
    campaign_effects: { count: 0, results: [] },
    alert_delta: { candidate_only: { count: 0, results: [] }, active_only: { count: 0, results: [] } },
    conditions: m.conditions,
  };
}

function versions(m: Mock) {
  const row = (v: Ver) => ({
    ...summary(v),
    stats: { scored: 100, dangerous: 40, checks: 0, created: 3, joined: 5, alerts: 2 },
    purity: { labelled: 10, dangerous: 9, purity: 0.9, warning: false },
    age_warning: false,
  });
  return page_([m.active, ...(m.previous ? [m.previous] : [])].map(row));
}

async function setup(page: Page, groups: string[], m: Mock) {
  // Anything not mocked below answers with an empty object so the rest of the Settings page stays quiet.
  // A regex anchored on the origin: the glob "**/api/**" would also catch Vite's own /src/api/*.ts modules.
  await page.route(/^https?:\/\/[^/]+\/api\//, (route) => route.fulfill(json({})));
  // A finished tour: the help tour overlay would otherwise sit over the page and swallow clicks.
  await page.route("**/api/profile/", (route) => route.fulfill(json({ tour_completed: true })));
  await page.route("**/api/auth/me/", (route) =>
    route.fulfill(json({ id: 1, username: "root", email: "root@corp.test", groups })),
  );
  await page.route("**/api/connectors/enabled/", (route) => route.fulfill(json({ enabled: ["ai_model"] })));
  await page.route("**/api/ai-model/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace(/^.*\/api\/ai-model\//, "");
    const post = req.method() === "POST";
    switch (path) {
      case "status/":
        return route.fulfill(json(status(m)));
      case "jobs/":
        return route.fulfill(json(page_(status(m).jobs)));
      case "candidates/":
        return route.fulfill(json(page_(m.candidate ? [{ ...m.candidate, rows: 1200, excluded_rows: 30 }] : [])));
      case "retrain/":
        if (post) {
          m.jobState = "succeeded";
          m.candidate = { version_id: "v2", status: "candidate", created_at: "2026-11-08T08:00:00Z", trigger: "manual", gate: GATE_FAIL, eligible: false };
          return route.fulfill(json({ job_id: "j1" }, 202));
        }
        break;
      case "shadow/start/":
        m.shadow = { ...m.candidate!, status: "shadow" };
        m.candidate = null;
        m.conditions = ["unreviewed_flips"];
        return route.fulfill(json(summary(m.shadow)));
      case "shadow/":
        return route.fulfill(json(shadowBody(m)));
      case "reviews/":
        if (post) {
          m.reviewed = true;
          m.conditions = [];
          return route.fulfill(json({ version_id: m.shadow!.version_id, kind: "flip", case_id: 55 }, 201));
        }
        return route.fulfill(json(page_([])));
      case "promote/":
        if (m.promoteRefusal) return route.fulfill(json({ detail: "Promotion refused.", codes: m.promoteRefusal }, 409));
        m.previous = { ...m.active, status: "previous" };
        m.active = { ...m.shadow!, status: "active" };
        m.shadow = null;
        return route.fulfill(json(summary(m.active)));
      case "versions/":
        return route.fulfill(json(versions(m)));
      case "rollback/": {
        const back = m.previous!;
        m.previous = { ...m.active, status: "previous" };
        m.active = { ...back, status: "active" };
        return route.fulfill(json(summary(m.active)));
      }
    }
    return route.fulfill(json({ detail: "not mocked" }, 404));
  });
}

const V1: Ver = { version_id: "v1", status: "active", created_at: "2026-09-01T00:00:00Z", trigger: "manual" };
const base = (over: Partial<Mock> = {}): Mock => ({
  active: V1, previous: null, candidate: null, shadow: null, conditions: [], reviewed: false, jobState: "none", promoteRefusal: null, ...over,
});
const SHADOW_V3: Ver = { version_id: "v3", status: "shadow", created_at: "2026-10-15T00:00:00Z", trigger: "manual" };

test("retrain produces a candidate whose failed gate check blocks the shadow", async ({ page }) => {
  await setup(page, ["Admin"], base());
  await page.goto("/settings/ai_model");

  await expect(page.getByText("Circuit breaker: closed")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText("Active version: v1")).toBeVisible();

  await page.getByRole("button", { name: "Retrain now" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Start retrain" }).click();
  await expect(page.getByText("Last job: succeeded, 1200 rows, 30 excluded")).toBeVisible();

  await page.getByRole("button", { name: "See candidate" }).click();
  await expect(page.getByText("Candidate v2")).toBeVisible();
  await expect(page.getByRole("row", { name: /campaign_heldout Failed/ })).toBeVisible();
  await expect(page.getByText("Not eligible: campaign_heldout")).toBeVisible();
  await expect(page.getByRole("button", { name: "Start shadow" })).toBeDisabled();
});

test("shadow, review, promote and roll back", async ({ page }) => {
  const m = base({
    candidate: { version_id: "v3", status: "candidate", created_at: "2026-10-15T00:00:00Z", trigger: "manual", gate: GATE_OK, eligible: true },
  });
  await setup(page, ["Admin"], m);
  await page.goto("/settings/ai_model");

  await page.getByRole("tab", { name: "Candidate" }).click();
  await page.getByRole("button", { name: "Start shadow" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Start shadow" }).click();

  await page.getByRole("tab", { name: "Shadow" }).click();
  await expect(page.getByText("Shadow v3")).toBeVisible();
  await expect(page.getByText("Not met: Some critical verdict flips are not reviewed yet.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Promote" })).toBeDisabled();

  await page.getByRole("button", { name: "Review case 55" }).click();
  await page.getByLabel("Review note").fill("Checked the headers, the candidate is right.");
  await page.getByRole("button", { name: "Save review" }).click();
  await expect(page.getByText("Done: All critical verdict flips are reviewed.")).toBeVisible();

  await page.getByRole("button", { name: "Promote" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Promote" }).click();
  await expect(page.getByText("No shadow is running.")).toBeVisible();

  await page.getByRole("tab", { name: "Versions" }).click();
  await expect(page.getByRole("row", { name: /^v3 active/ })).toBeVisible();
  await expect(page.getByRole("row", { name: /^v1 previous/ })).toBeVisible();

  await page.getByRole("button", { name: "Rollback to v1" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Roll back" }).click();
  await expect(page.getByText("Rolled back to v1.")).toBeVisible();
  await expect(page.getByRole("row", { name: /^v1 active/ })).toBeVisible();
});

test("a refused promotion shows the 409 codes in words", async ({ page }) => {
  await setup(page, ["Admin"], base({ shadow: SHADOW_V3, promoteRefusal: ["too_few_results", "recheck_stale"] }));
  await page.goto("/settings/ai_model");

  await page.getByRole("tab", { name: "Shadow" }).click();
  await page.getByRole("button", { name: "Promote" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Promote" }).click();
  await expect(
    page.getByRole("status").getByText("Too few live results have been compared so far. The last gate recheck is out of date; run it again."),
  ).toBeVisible();
});

test("a CERT-only user has no AI model section", async ({ page }) => {
  await setup(page, ["CERT"], base());
  await page.goto("/settings/ai_model");

  await expect(page).not.toHaveURL(/ai_model/);
  await expect(page.getByText("Model lifecycle")).toHaveCount(0);
  await expect(page.getByText("AI model", { exact: true })).toHaveCount(0);
});
