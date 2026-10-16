/**
 * Short, caption-free clips of each page → demo/out/gifs/<name>.webm.
 * `demo/build-gifs.sh` turns them into the GIFs used in the README and docs.
 *
 * Same harness as the walkthrough (mocked API, visible cursor) but no
 * subtitles: each clip just shows how the page works.
 */
import { test, expect, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { Director } from "./director";
import { installMocks, newState, type DemoState } from "./fixtures";

const OUT = "demo/out/gifs";
const SHOTS = !!process.env.DEMO_SHOTS;

type Run = (ctx: { page: Page; d: Director; shot: (n: string) => Promise<void> }) => Promise<void>;

/** Record one clip. `start`/`end` marks trim the boot and tear-down out of the GIF. */
function clip(name: string, over: Partial<DemoState>, run: Run) {
  test(`clip: ${name}`, async ({ page }) => {
    await installMocks(page, newState({ authenticated: true, ...over }));
    const d = new Director(page);
    await d.prepare();
    mkdirSync(OUT, { recursive: true });
    const shot = async (n: string) => {
      if (SHOTS) await page.screenshot({ path: `${OUT}/${name}-${n}.png` });
    };
    await run({ page, d, shot });
    d.mark("end");
    writeFileSync(`${OUT}/${name}.json`, JSON.stringify(d.marks));
    await page.close();
    await page.video()!.saveAs(`${OUT}/${name}.webm`);
  });
}

const nav = (page: Page, name: string) => page.getByRole("link", { name, exact: true });
const heading = (page: Page, name: string) => page.getByRole("heading", { name, exact: true });

clip("login", { authenticated: false }, async ({ page, d, shot }) => {
  await page.goto("/login");
  await expect(page.getByRole("button", { name: /username and password/i })).toBeVisible();
  await d.pause(900);
  d.mark("start");
  await d.pause(1200);
  await d.click(page.getByRole("button", { name: /username and password/i }));
  await d.type(page.locator("#login-username"), "elena.voss@meridian.example", 40);
  await d.type(page.locator("#login-password"), "MeridianDev!2026", 40);
  await shot("filled");
  await d.click(page.getByRole("button", { name: /^sign in$/i }));
  await expect(page.getByText(/welcome, elena/i)).toBeVisible();
  await d.pause(1800);
});

clip("home", {}, async ({ page, d, shot }) => {
  await page.goto("/");
  await expect(page.getByText(/welcome, elena/i)).toBeVisible();
  await d.pause(1500);
  d.mark("start");
  await d.glide(page.getByText("Threat distribution"));
  await d.pause(900);
  await d.glide(page.getByText("Dangerous", { exact: true }).first());
  await d.pause(1200);
  await d.scroll(380);
  await d.pause(1800);
  await shot("recent");
  await d.glide(page.getByRole("button", { name: /see more/i }));
  await d.pause(1500);
  await d.scroll(-380);
  await d.pause(1200);
});

clip("submit", {}, async ({ page, d, shot }) => {
  await page.goto("/submit");
  await expect(heading(page, "Submit")).toBeVisible();
  await d.pause(1500);
  d.mark("start");
  await d.click(page.getByRole("button", { name: /^file/i }));
  await d.pause(1500);
  await shot("file");
  await d.click(page.getByRole("button", { name: /^indicators/i }));
  await d.type(
    page.getByRole("textbox", { name: "Indicators" }),
    "hxxps://meridian-payroll-update[.]example/sso\n203.0.113.77\n9f2b4c7a51e0d3c8a6b7f1e2d4c5a8b9",
    16,
  );
  await expect(page.locator("#indicators-summary")).toContainText(/3 found/i);
  await d.pause(1800);
  await shot("preview");
  await d.type(page.getByRole("textbox", { name: /context/i }), "Link in an HR payroll email. Looked odd.", 28);
  await d.click(page.getByRole("button", { name: /^submit$/i }));
  await expect(page).toHaveURL(/\/submissions/);
  await d.pause(2200);
  await shot("case");
  await d.click(page.getByRole("tab", { name: /^analysis/i }));
  await d.pause(2200);
});

clip("submissions", {}, async ({ page, d, shot }) => {
  await page.goto("/submissions");
  await expect(heading(page, "Submissions")).toBeVisible();
  await d.pause(1800);
  d.mark("start");
  await d.type(page.getByRole("textbox", { name: /search/i }), "payroll", 70);
  await d.pause(1500);
  await shot("search");
  await d.click(page.getByText("Action required: payroll update for October").first());
  await d.pause(1800);
  await shot("drawer");
  await d.click(page.getByRole("tab", { name: /^analysis/i }));
  await d.pause(2000);
  await d.click(page.getByRole("tab", { name: /^overview/i }));
  await d.pause(1200);
  await d.click(page.getByRole("button", { name: /^close$/i }));
  await d.pause(1000);
});

clip("investigation", {}, async ({ page, d, shot }) => {
  await page.goto("/investigation");
  await expect(heading(page, "Investigation")).toBeVisible();
  await d.pause(1800);
  d.mark("start");
  await d.click(page.getByText("Action required: payroll update for October").first());
  await d.pause(1800);
  await shot("drawer");
  await d.click(page.getByRole("button", { name: /show source breakdown/i }));
  await d.pause(1600);
  await d.scroll(300);
  await d.pause(1500);
  await shot("sources");
  await d.click(page.getByRole("tab", { name: /^analysis/i }));
  await d.pause(2200);
  await d.click(page.getByRole("button", { name: /^close$/i }));
  await d.pause(900);
});

clip("dashboard", {}, async ({ page, d, shot }) => {
  await page.goto("/dashboard");
  await expect(heading(page, "Dashboard")).toBeVisible();
  await d.pause(2200);
  d.mark("start");
  await d.glide(page.getByRole("region", { name: "Dangerous" }));
  await d.pause(1500);
  await d.scroll(520);
  await d.pause(2200);
  await shot("scrolled");
  await d.scroll(520);
  await d.pause(1800);
  await d.scroll(-1040, 80);
  await d.pause(1000);
});

clip("campaigns", {}, async ({ page, d, shot }) => {
  await page.goto("/campaigns");
  await expect(heading(page, "Campaigns")).toBeVisible();
  await d.pause(2200);
  d.mark("start");
  await d.scroll(480);
  await d.pause(2000);
  await shot("map");
  await d.scroll(520);
  await d.pause(2200);
  await shot("table");
  await d.scroll(-1000, 80);
  await d.pause(900);
});

clip("profile", {}, async ({ page, d, shot }) => {
  await page.goto("/profile");
  await expect(page.getByText("My profile")).toBeVisible();
  await d.pause(1800);
  d.mark("start");
  await d.click(page.getByRole("button", { name: /appearance/i }).first());
  await d.pause(2000);
  await shot("appearance");
  await d.click(page.getByRole("button", { name: /customize colors/i }).first());
  await d.pause(2000);
  await shot("colors");
  await d.click(page.getByRole("button", { name: /avatar/i }).first());
  await d.pause(2000);
  await d.click(page.getByRole("button", { name: /preferences/i }).first());
  await d.pause(1200);
});

clip("settings", {}, async ({ page, d, shot }) => {
  await page.goto("/settings");
  await expect(heading(page, "Settings")).toBeVisible();
  await d.pause(1800);
  d.mark("start");
  await d.type(page.getByPlaceholder(/paste domains/i), "partners.meridian.example", 45);
  await d.click(page.getByRole("button", { name: /^add$/i }));
  await d.pause(2000);
  await shot("added");
  await d.click(page.getByRole("button", { name: /domains denylist/i }));
  await d.pause(2000);
  await d.click(page.getByRole("button", { name: /scoring/i }));
  await d.pause(2400);
  await shot("scoring");
});
