/**
 * Product walkthrough → demo/out/suspicious-demo.webm (+ .vtt / .srt).
 *
 * Runs against the Vite dev server with every `/api/**` call mocked (see
 * fixtures.ts), so it is deterministic and needs no backend. Captions are
 * burned into the recording by the Director.
 *
 * `say(text)` holds the caption while nothing else happens;
 * `say(text, 0)` shows it and keeps going, narrating the actions that follow.
 */
import { test, expect } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { Director, toSrt, toVtt } from "./director";
import { installMocks, newState } from "./fixtures";

const OUT = "demo/out";
const SHOTS = !!process.env.DEMO_SHOTS;

test("Suspicious product walkthrough", async ({ page }) => {
  const state = newState();
  await installMocks(page, state);
  const d = new Director(page);
  await d.prepare();
  mkdirSync(`${OUT}/shots`, { recursive: true });

  const snap = async (name: string) => {
    if (SHOTS) await page.screenshot({ path: `${OUT}/shots/${name}.png` });
  };
  const nav = (name: string) => page.getByRole("link", { name, exact: true });
  const heading = (name: string) => page.getByRole("heading", { name, exact: true });

  // ── 1. Sign in ───────────────────────────────────────────────────────────
  await page.goto("/login");
  await d.pause(700);
  await d.say("Suspicious: AI-powered phishing and threat analysis, built by Thales Group CERT.", 3400);
  await d.say("Employees sign in with SSO, or with a local account.", 0);
  await d.click(page.getByRole("button", { name: /username and password/i }));
  await d.type(page.locator("#login-username"), "elena.voss@meridian.example", 35);
  await d.type(page.locator("#login-password"), "MeridianDev!2026", 35);
  await snap("01-login");
  await d.click(page.getByRole("button", { name: /^sign in$/i }));
  await expect(page.getByText(/welcome, elena/i)).toBeVisible();

  // ── 2. Home ──────────────────────────────────────────────────────────────
  await d.say("Home shows this month's verdicts across the whole organisation…", 3000);
  await snap("02-home");
  await d.glide(page.getByText("Threat distribution"));
  await d.say("…and your latest submissions, one click from the full report.", 0);
  await d.scroll(360);
  await d.pause(1800);
  await snap("02b-home-recent");
  await d.scroll(-360);

  // ── 3. Submit ────────────────────────────────────────────────────────────
  await d.click(nav("Submit"));
  await expect(heading("Submit")).toBeVisible();
  await d.say("Anyone can report something suspicious in seconds: a file, an email, or pasted indicators.", 0);
  await d.click(page.getByRole("button", { name: /^file/i }));
  await snap("03-submit-file");
  await d.pause(1500);
  await d.click(page.getByRole("button", { name: /^indicators/i }));
  await d.say("Types are detected automatically, defanged links included.", 0);
  await d.type(
    page.getByRole("textbox", { name: "Indicators" }),
    "hxxps://meridian-payroll-update[.]example/sso\n203.0.113.77\n9f2b4c7a51e0d3c8a6b7f1e2d4c5a8b9",
    18,
  );
  await expect(page.locator("#indicators-summary")).toContainText(/3 found/i);
  await d.pause(1200);
  await d.type(page.getByRole("textbox", { name: /context/i }), "Link in an HR payroll email. Looked odd.", 30);
  await snap("03b-submit-filled");
  await d.say("Related indicators are correlated into a single case.", 2600);
  await d.click(page.getByRole("button", { name: /^submit$/i }));
  await expect(page).toHaveURL(/\/submissions/);

  // ── 4. My submissions ────────────────────────────────────────────────────
  await d.say("The new case opens at once. Analyzers run in parallel: YARA, ML, sandbox and reputation.", 4000);
  await snap("04-case-overview");
  await d.click(page.getByRole("tab", { name: /^analysis/i }));
  await d.say("Each analyzer reports its own verdict, confidence and evidence.", 3200);
  await snap("04b-case-analysis");
  await d.click(page.getByRole("button", { name: /^close$/i }));
  await d.say("Reporters follow every submission, and its final verdict, in one place.", 3400);
  await snap("04c-submissions");

  // ── 5. Investigation (CERT) ──────────────────────────────────────────────
  await d.click(nav("Investigation"));
  await expect(heading("Investigation")).toBeVisible();
  await d.say("CERT analysts get a full investigation workspace…", 2400);
  await snap("05-investigation");
  await d.click(page.getByText("Action required: payroll update for October").first());
  await d.say("…with an explained verdict: which sources agreed, and why.", 3600);
  await snap("05b-investigation-drawer");
  await d.click(page.getByRole("button", { name: /show source breakdown/i }));
  await snap("05c-investigation-sources");
  await d.pause(1800);
  await d.scroll(260);
  await d.pause(1200);
  await d.click(page.getByRole("button", { name: /^close$/i }));
  await d.pause(300);

  // ── 6. Dashboard ─────────────────────────────────────────────────────────
  await d.click(nav("Dashboard"));
  await expect(heading("Dashboard")).toBeVisible();
  await d.say("The dashboard tracks volumes, outcomes and top reporters, month over month.", 3600);
  await d.hush(); // caption-free frame: used as the video poster
  await d.pause(700);
  d.mark("poster");
  await snap("06-dashboard");
  await d.scroll(480);
  await d.pause(1500);
  await snap("06b-dashboard-scrolled");

  // ── 7. Campaigns ─────────────────────────────────────────────────────────
  await d.click(nav("Campaigns"));
  await expect(heading("Campaigns")).toBeVisible();
  await d.say("Campaign detection clusters similar messages with ML embeddings…", 3400);
  await snap("07-campaigns");
  await d.say("…so a coordinated wave is spotted before it spreads.", 0);
  await d.scroll(520);
  await d.pause(2200);
  await snap("07b-campaigns-scrolled");
  await d.scroll(520);
  await d.pause(1600);

  // ── 8. Outro ─────────────────────────────────────────────────────────────
  await d.click(nav("Home"));
  await d.say("Open source, self-hosted, and deployed with Docker Compose.", 3000);
  await d.say("github.com/thalesgroup-cert/suspicious", 3600, 600);
  await d.pause(400);

  const cues = d.finish();
  writeFileSync(`${OUT}/suspicious-demo.vtt`, toVtt(cues));
  writeFileSync(`${OUT}/suspicious-demo.srt`, toSrt(cues));
  writeFileSync(`${OUT}/suspicious-demo.marks.json`, JSON.stringify(d.marks));
});
