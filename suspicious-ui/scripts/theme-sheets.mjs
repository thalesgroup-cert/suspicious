import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";

const out = path.resolve(process.argv[2] ?? "theme-shots");
const url = process.env.UI_URL ?? "http://localhost:9021";
const THEMES = ["midnight","graphite","slate","light","paper","renee","high_contrast","sunrise","valentine","cyber","the_one","metal","winter","spring","summer","autumn","future"];
const PAGES = ["", "submissions", "dashboard"];
const name = (p) => p || "home";

fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch(
  process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {},
);
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();

await page.goto(`${url}/login`);
await page.getByRole("button", { name: /username and pass/i }).click();
await page.locator("input").first().fill(process.env.UI_USER ?? "elena.voss@meridian.example");
await page.locator("input[type=password]").fill(process.env.UI_PASS ?? "MeridianDev!2026");
await page.keyboard.press("Enter");
await page.waitForURL((u) => !u.pathname.startsWith("/login"));

for (const t of THEMES) {
  for (const p of PAGES) {
    await page.goto(`${url}/${p}`);
    await page.waitForLoadState("networkidle");
    // The server-saved theme overwrites localStorage after load, so switch through the store's own event.
    await page.evaluate((theme) => window.dispatchEvent(new CustomEvent("suspicious:theme-hydrate", { detail: { theme, autoSeasonal: false } })), t);
    await page.waitForTimeout(700);
    await page.screenshot({ path: path.join(out, `${t}-${name(p)}.png`) });
  }
}

// Captions sit under each image so they never cover the page.
const groups = [THEMES.slice(0, 6), THEMES.slice(6, 12), THEMES.slice(12)];
const sheetPage = await browser.newPage({ viewport: { width: 1938, height: 800 } });
for (const p of PAGES) {
  for (const [i, g] of groups.entries()) {
    const html = `<body style="margin:0;background:#777;display:grid;grid-template-columns:repeat(3,640px);gap:6px;font:bold 14px sans-serif">${g
      .map((t) => `<figure style="margin:0"><img width="640" src="file://${path.join(out, `${t}-${name(p)}.png`)}"><figcaption style="background:#000;color:#fff;padding:2px 6px">${t}</figcaption></figure>`)
      .join("")}</body>`;
    const f = path.join(out, "sheet.html");
    fs.writeFileSync(f, html);
    await sheetPage.goto(`file://${f}`);
    await sheetPage.screenshot({ path: path.join(out, `sheet-${name(p)}-${i + 1}.png`), fullPage: true });
  }
}
fs.rmSync(path.join(out, "sheet.html"));
await browser.close();
console.log(`wrote ${THEMES.length * PAGES.length} captures and ${PAGES.length * groups.length} sheets to ${out}`);
