import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { page } from "vitest/browser";
import { renderWithProviders } from "@/test/utils";
import { themes } from "@/styles/themes";
import { composite, contrastRatio, flatten } from "@/shared/lib/contrast";
import { stubMatchMedia } from "@/test/matchMedia";
import { fixtureMeSuperuser, fixtureAnalyzers, fixtureFeederStatus } from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));
vi.mock("@/features/settings/api", () => ({
  listItems: vi.fn(),
  addItems: vi.fn(),
  removeItem: vi.fn(),
  addFromFile: vi.fn(),
  getFeederStatus: vi.fn(),
  setFeederStatus: vi.fn(),
  getFeederHealth: vi.fn(),
  listAnalyzers: vi.fn(),
  updateAnalyzerWeight: vi.fn(),
}));

// vi.mock is hoisted above plain consts, so the connector fixtures are hoisted with it.
const connectors = vi.hoisted(() => {
  const base = {
    version: "1.0.0",
    description: "Pushes finalised cases.",
    author: "Thales CERT",
    docs_url: "",
    category: "Threat intel",
    events: ["case_finalised"],
    schedules: [{ name: "sync", interval_seconds: 3600 }],
    enabled: true,
    enabled_by_default: false,
    status: "connected" as const,
    last_health_ok: true as boolean | null,
    last_health_detail: "",
    last_health_at: "2026-10-19T08:00:00Z" as string | null,
  };
  return [
    {
      ...base,
      name: "misp",
      config_schema: [
        { key: "url", type: "url", required: true, default: null, help: "Base URL" },
        { key: "api_key", type: "secret", required: true, default: null, help: "" },
        { key: "verify_tls", type: "bool", required: false, default: true, help: "" },
        { key: "timeout", type: "int", required: false, default: 30, help: "" },
      ],
    },
    { ...base, name: "thehive", status: "partial" as const, last_health_ok: false, last_health_detail: "401 Unauthorized", config_schema: [] },
    { ...base, name: "ai_narration", enabled: false, status: "disabled" as const, last_health_ok: null, last_health_at: null, config_schema: [{ key: "model", type: "str", required: false, default: "m", help: "" }] },
  ];
});
vi.mock("@/features/settings/components/connectors", () => ({
  listConnectors: vi.fn().mockResolvedValue({ connectors, load_errors: {} }),
  setConnectorEnabled: vi.fn(),
  getConnectorConfig: vi.fn().mockResolvedValue({ url: "https://misp.example", api_key: "", verify_tls: true, timeout: 30, model: "m" }),
  putConnectorConfig: vi.fn(),
  testConnector: vi.fn(),
  listDeliveries: vi.fn().mockResolvedValue([
    { id: 1, event: "case_finalised", case_id: 7, status: "success", error: "", duration_ms: 120, attempt: 1, created_at: "2026-10-19T08:00:00Z" },
    { id: 2, event: "case_finalised", case_id: 8, status: "failed", error: "boom", duration_ms: 90, attempt: 2, created_at: "2026-10-19T08:05:00Z" },
  ]),
}));

import { getMe } from "@/api/auth";
import { listItems, removeItem, getFeederStatus, setFeederStatus, getFeederHealth, listAnalyzers, updateAnalyzerWeight } from "@/features/settings/api";
import SettingsPage from "../SettingsPage";

const T = { timeout: 8000 };
const ROUTE = "settings/:section?";

const LISTS = [
  { id: "1", value: "alpha.example", created_at: "2026-01-01T00:00:00Z" },
  { id: "2", value: "bravo.example", created_at: "2026-01-02T00:00:00Z" },
  { id: "3", value: "charlie.example", created_at: "2026-01-03T00:00:00Z" },
];
const CISO = [
  { id: 1, username: "adaeze.okafor", email: "adaeze.okafor@meridian.example", function: "CISO", gbu: "Group", country: "NG", region: "EMEA", scope: "Group" },
  { id: 2, username: "jordan.kim", email: "", function: "", gbu: "", country: "", region: "", scope: "" },
];

// [path, h2 title]. Connectors are walked tab by tab below.
const SECTIONS: [string, string][] = [
  ["domains_allow", "Domains allowlist"],
  ["domains_deny", "Domains denylist"],
  ["campaign_domains_allow", "Campaign domains"],
  ["emails_files_allow", "Files allowlist"],
  ["filetypes_allow", "Filetypes allowlist"],
  ["ciso_users", "CISO users"],
  ["email_feeder", "Email feeder"],
  ["scoring", "Analyzer scoring"],
  ["connectors", "Connectors"],
  ["connectors?connector=misp&tab=overview", "Connectors"],
  ["connectors?connector=misp&tab=configuration", "Connectors"],
  ["connectors?connector=misp&tab=deliveries", "Connectors"],
];

const CONTROL_ROLES = ["button", "link", "checkbox", "switch", "radio", "textbox", "combobox", "spinbutton", "slider", "tab", "searchbox", "menuitem"] as const;

async function open(path: string) {
  const view = renderWithProviders(<SettingsPage />, { initialPath: `/settings/${path}`, routePath: ROUTE });
  await screen.findByRole("heading", { level: 1, name: "Settings" }, T);
  await waitFor(() => {
    expect(screen.queryAllByRole("progressbar")).toHaveLength(0);
    expect(screen.queryByText("Loading")).not.toBeInTheDocument();
  }, T);
  return view;
}

const nameOf = (el: Element) =>
  el.getAttribute("aria-label") ??
  document.getElementById(el.getAttribute("aria-labelledby") ?? "")?.textContent ??
  el.querySelector(":scope > caption")?.textContent ??
  null;

describe("SettingsPage: structure for assistive technology", () => {
  beforeEach(async () => {
    await page.viewport(1280, 900);
    stubMatchMedia();
    vi.mocked(getMe).mockResolvedValue(fixtureMeSuperuser);
    vi.mocked(listItems).mockImplementation((async (section: string) => (section === "ciso_users" ? CISO : LISTS)) as never);
    vi.mocked(getFeederStatus).mockResolvedValue(fixtureFeederStatus);
    vi.mocked(setFeederStatus).mockResolvedValue({ enabled: false });
    vi.mocked(removeItem).mockResolvedValue({});
    vi.mocked(getFeederHealth).mockResolvedValue({ online: true, last_successful_poll: 1_760_000_000, emails_processed_total: 12, errors_total: 0, stale_seconds: 5, stale: false, checked_at: 1_760_000_100, error: null, feeder_status: "ok" });
    vi.mocked(listAnalyzers).mockResolvedValue(fixtureAnalyzers);
    vi.mocked(updateAnalyzerWeight).mockResolvedValue({});
  });
  afterEach(() => vi.unstubAllGlobals());

  describe.each(SECTIONS)("section %s", (path, title) => {
    it("has one h1, exactly one h2 (the section's), and no heading level skipped; an open drawer is its own region with one h2", async () => {
      await open(path);
      // hidden: an open drawer is modal, so the page behind it is aria-hidden and would otherwise vanish from the query.
      const all = screen.getAllByRole("heading", { hidden: true });
      const info = (h: HTMLElement) => ({ level: Number(h.tagName[1]), name: h.textContent });
      const headings = all.filter((h) => !h.closest("[role=dialog]")).map(info);
      expect(headings.filter((h) => h.level === 1)).toEqual([{ level: 1, name: "Settings" }]);
      expect(headings[0].level).toBe(1);
      expect(headings.filter((h) => h.level === 2)).toEqual([{ level: 2, name: title }]);
      headings.slice(1).forEach((h, i) => expect(h.level - headings[i].level, `${headings[i].name} -> ${h.name}`).toBeLessThanOrEqual(1));
      const inDialog = all.filter((h) => h.closest("[role=dialog]")).map(info);
      expect(inDialog).toEqual(path.includes("connector=") ? [{ level: 2, name: "misp" }] : []);
    });

    it("names every region, landmark, table and tab panel once", async () => {
      await open(path);
      const landmarks = [...screen.queryAllByRole("region"), ...screen.queryAllByRole("navigation"), ...screen.queryAllByRole("table"), ...screen.queryAllByRole("tabpanel"), ...screen.queryAllByRole("tablist")];
      const names = landmarks.map((el) => nameOf(el) ?? `(unnamed ${el.tagName})`);
      expect(names.filter((n) => n.startsWith("(unnamed")), "unnamed").toEqual([]);
      for (const n of new Set(names)) {
        // A tab panel may share its tab's name; nothing else may repeat.
        const same = landmarks.filter((el) => nameOf(el) === n);
        expect(new Set(same.map((el) => el.getAttribute("role") ?? el.tagName)).size, `"${n}" is used by more than one landmark kind or twice`).toBe(same.length);
      }
    });

    it("gives every interactive control an accessible name", async () => {
      await open(path);
      const unnamed: string[] = [];
      for (const role of CONTROL_ROLES) {
        for (const el of screen.queryAllByRole(role)) {
          try {
            expect(el).toHaveAccessibleName();
          } catch {
            unnamed.push(`${role}: ${el.outerHTML.slice(0, 140)}`);
          }
        }
      }
      expect(unnamed).toEqual([]);
    });
  });

  it("tabs from the Refresh button through the status strip and the section nav into the panel, each zone once and in order", async () => {
    const user = userEvent.setup();
    await open("domains_allow");
    const zoneOf = (el: Element) =>
      el.closest("nav") ? "nav" : el.closest("[data-testid='status-strip'], a[href*='/settings/']") && !el.closest("nav") ? "strip" : el.closest("section, [role='region']") || el.closest(".MuiCardContent-root") ? "panel" : "header";
    (await screen.findByRole("button", { name: "Refresh" })).focus();
    const zones: string[] = ["header"];
    for (let i = 0; i < 30; i++) {
      await user.tab();
      zones.push(zoneOf(document.activeElement as Element));
    }
    const collapsed = zones.filter((z, i) => z !== zones[i - 1]);
    // Same order as on screen: header actions, status strip, section nav, panel.
    expect(collapsed.slice(0, 4)).toEqual(["header", "strip", "nav", "panel"]);
    expect(collapsed.indexOf("nav")).toBe(collapsed.lastIndexOf("nav"));
  });

  it("names the section picker on a phone", async () => {
    await page.viewport(390, 800);
    stubMatchMedia({ phone: true });
    await open("scoring");
    expect(screen.queryByRole("navigation", { name: "Settings sections" })).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Settings section" })).toBeInTheDocument();
  });

  describe("confirm dialogs hand focus back", () => {
    async function selectTwo(user: ReturnType<typeof userEvent.setup>) {
      await open("campaign_domains_allow");
      await user.click(await screen.findByRole("checkbox", { name: "Select alpha.example" }));
      await user.click(screen.getByRole("checkbox", { name: "Select bravo.example" }));
    }

    it("bulk delete: Cancel and Escape return focus to the Delete button", async () => {
      const user = userEvent.setup();
      await selectTwo(user);
      for (const close of ["cancel", "escape"]) {
        const opener = screen.getByRole("button", { name: "Delete 2" });
        await user.click(opener);
        const dialog = await screen.findByRole("dialog");
        expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
        if (close === "cancel") await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
        else await user.keyboard("{Escape}");
        await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument(), T);
        expect(opener, close).toHaveFocus();
      }
    });

    it("bulk delete: after Delete the opener is gone, so focus goes to the list's search field and stays there once the dialog has faded", async () => {
      const user = userEvent.setup();
      await selectTwo(user);
      await user.click(screen.getByRole("button", { name: "Delete 2" }));
      await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete" }));
      await waitFor(() => expect(removeItem).toHaveBeenCalledTimes(2), T);
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument(), T);
      await new Promise((r) => setTimeout(r, 400));
      expect(screen.getByRole("textbox", { name: "Search Campaign domains" })).toHaveFocus();
    });

    it("feeder off: Cancel returns focus to the switch, and so does confirming", async () => {
      const user = userEvent.setup();
      await open("email_feeder");
      const sw = screen.getByRole("switch", { name: "Email feeder" });
      await user.click(sw);
      await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument(), T);
      expect(sw).toHaveFocus();
      vi.mocked(getFeederStatus).mockResolvedValue({ enabled: false });
      await user.click(sw);
      await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Turn off" }));
      await waitFor(() => expect(setFeederStatus).toHaveBeenCalledWith(false), T);
      await waitFor(() => expect(sw).toHaveFocus(), T);
    });

    it("leaving a section with unsaved scoring edits: Cancel returns focus to the nav link that was used", async () => {
      const user = userEvent.setup();
      await open("scoring");
      const input = (await screen.findAllByRole("spinbutton"))[0];
      await user.clear(input);
      await user.type(input, "5");
      const link = within(screen.getByRole("navigation", { name: "Settings sections" })).getByRole("link", { name: /^Domains allowlist/ });
      await user.click(link);
      const dialog = await screen.findByRole("dialog");
      expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
      await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument(), T);
      expect(link).toHaveFocus();
    });

    it("closing the connector drawer with a draft: Cancel returns focus to the Close button that was used", async () => {
      const user = userEvent.setup();
      await open("connectors?connector=misp&tab=configuration");
      await user.type((await screen.findAllByRole("textbox"))[0], "x");
      const close = screen.getByRole("button", { name: "Close misp" });
      await user.click(close);
      const dialog = await screen.findByRole("dialog", { name: "Discard unsaved changes to misp?" });
      await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByRole("dialog", { name: /Discard/ })).not.toBeInTheDocument(), T);
      expect(close).toHaveFocus();
    });
  });

  it.each(["{Enter}", " "])("opens the file chooser once from the keyboard on Import file (key %j)", async (key) => {
    const user = userEvent.setup();
    await open("campaign_domains_allow");
    const input = document.querySelector("input[type=file]") as HTMLInputElement;
    const click = vi.spyOn(input, "click");
    const trigger = screen.getByRole("button", { name: "Import file" });
    trigger.focus();
    expect(trigger).toHaveFocus();
    await user.keyboard(key);
    // The input sits inside the button: its programmatic click must not bubble back and fire the button again.
    expect(click).toHaveBeenCalledTimes(1);
  });

  it("names the add field of a list", async () => {
    await open("campaign_domains_allow");
    expect(screen.getByRole("textbox", { name: /add/i })).toBeInTheDocument();
  });

  describe("on a phone the connector drawer fills the screen, so focus follows it", () => {
    async function phone() {
      await page.viewport(390, 800);
      stubMatchMedia({ phone: true });
      await open("connectors");
    }

    it("opening a connector moves focus into the drawer", async () => {
      const user = userEvent.setup();
      await phone();
      await user.click(screen.getByRole("button", { name: "Configure misp" }));
      const dialog = await screen.findByRole("dialog", { name: "misp" });
      await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true), T);
      expect(dialog.getBoundingClientRect().width).toBe(390);
    });

    it("closing the drawer moves focus back to the Configure button that opened it", async () => {
      const user = userEvent.setup();
      await phone();
      const button = screen.getByRole("button", { name: "Configure misp" });
      await user.click(button);
      await user.click(await screen.findByRole("button", { name: "Close misp" }));
      await waitFor(() => expect(button).toHaveFocus(), T);
    });

    it("a long unbroken health detail wraps inside the drawer instead of running off it", async () => {
      const misp = connectors[0];
      const before = { ...misp };
      Object.assign(misp, { last_health_ok: false, last_health_detail: "HTTPSConnectionPool(host=" + "x".repeat(160) + ")" });
      try {
        await page.viewport(390, 800);
        stubMatchMedia({ phone: true });
        await open("connectors?connector=misp");
        const caption = await screen.findByText(/^Last checked/);
        expect(caption.scrollWidth).toBeLessThanOrEqual(caption.clientWidth);
      } finally {
        Object.assign(misp, before);
      }
    });

    it("a deep link to a connector puts focus inside the drawer (a modal dialog takes focus), and closing puts it on that connector's Configure button", async () => {
      const user = userEvent.setup();
      await page.viewport(390, 800);
      stubMatchMedia({ phone: true });
      await open("connectors?connector=misp");
      const dialog = await screen.findByRole("dialog", { name: "misp" });
      await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true), T);
      await user.keyboard("{Escape}");
      await waitFor(() => expect(screen.getByRole("button", { name: "Configure misp" })).toHaveFocus(), T);
    });
  });

  describe("deliveries table", () => {
    it("at desktop width keeps the Error column readable; it was 79px when five columns shared a pane of about 520px", async () => {
      await open("connectors?connector=misp&tab=deliveries");
      const cell = (await screen.findByRole("cell", { name: "boom" })) as HTMLElement;
      expect(cell.getBoundingClientRect().width).toBeGreaterThanOrEqual(100);
    });

    it("on a phone folds Case and Time into the Event cell so Status and Error are reachable without sideways scrolling", async () => {
      await page.viewport(390, 800);
      stubMatchMedia({ phone: true });
      await open("connectors?connector=misp&tab=deliveries");
      const region = await screen.findByRole("region", { name: "Deliveries table" });
      const headers = within(region).getAllByRole("columnheader").map((h) => h.textContent);
      expect(headers).toEqual(["Event", "Status", "Error"]);
      const eventCell = within(region).getAllByRole("cell")[0];
      expect(within(eventCell).getByRole("link", { name: /^Case #/ })).toBeVisible();
      expect(region.scrollWidth).toBeLessThanOrEqual(region.clientWidth);
      expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(window.innerWidth);
      expect(((await screen.findByRole("cell", { name: "boom" })) as HTMLElement).getBoundingClientRect().width).toBeGreaterThanOrEqual(90);
    });
  });

  // The Refresh button sits straight on the shell, whose glow is up to 7% primary over the page colour.
  it.each(Object.keys(themes) as (keyof typeof themes)[])("keeps Refresh readable on the shell in the %s theme", async (theme) => {
    localStorage.setItem("suspicious.theme", theme);
    try {
      const { palette } = themes[theme];
      await open("domains_allow");
      const shell = composite(flatten(palette.primary.main, palette.background.default), 0.07, palette.background.default);
      const color = getComputedStyle(screen.getByRole("button", { name: "Refresh" })).color;
      expect(contrastRatio(color, shell)).toBeGreaterThanOrEqual(4.5);
    } finally {
      localStorage.removeItem("suspicious.theme");
    }
  });

  it("turns every CSS transition off under prefers-reduced-motion", async () => {
    // Real Chromium evaluates the media rule; emulate it by reading the rule that applies to every element.
    await open("email_feeder");
    const rules = [...document.styleSheets].flatMap((s) =>
      [...s.cssRules].filter((r): r is CSSMediaRule => r instanceof CSSMediaRule && r.conditionText.includes("prefers-reduced-motion: reduce")).flatMap((m) => [...m.cssRules]),
    );
    const kill = rules.find((r): r is CSSStyleRule => r instanceof CSSStyleRule && r.selectorText.startsWith("*") && r.style.getPropertyPriority("transition-duration") === "important");
    expect(kill, "a reduced-motion rule over *").toBeDefined();
    const animated = [...document.querySelectorAll<HTMLElement>("main *, [class*=MuiCardContent] *")].filter((el) => el.style.transitionDuration && el.style.getPropertyPriority("transition-duration") !== "important");
    expect(animated, "inline transitions that would beat the rule").toEqual([]);
  });
});
