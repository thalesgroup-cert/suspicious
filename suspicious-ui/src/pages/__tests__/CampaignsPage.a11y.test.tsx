import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ThemeProvider, createTheme } from "@mui/material/styles";
import { contrastRatio } from "@/shared/lib/contrast";
import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";
import { fixtureMe, fixtureCampaignSummary, fixtureMailVolume, fixtureNeighbours, fixturePca } from "@/test/fixtures";
import { detectWebGL } from "@/features/campaigns/mapSupport";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));
vi.mock("@/features/campaigns/api", () => ({
  getCampaignSummary: vi.fn(),
  getMailVolume: vi.fn(),
  getNeighbours: vi.fn(),
  getPca: vi.fn(),
}));
// The real 3D map component (its wrapper, key, controls) around a stub canvas: this file is about what a keyboard and a screen reader meet.
vi.mock("@/features/campaigns/mapSupport", async (original) => ({
  ...(await original<typeof import("@/features/campaigns/mapSupport")>()),
  detectWebGL: vi.fn(),
}));
vi.mock("@react-three/fiber", async (original) => ({
  ...(await original<typeof import("@react-three/fiber")>()),
  Canvas: () => <div data-testid="gl-canvas" />,
}));

import { getMe } from "@/api/auth";
import { getCampaignSummary, getMailVolume, getNeighbours, getPca } from "@/features/campaigns/api";
import CampaignsPage from "../CampaignsPage";

const T = { timeout: 8000 };

async function renderPage() {
  const view = renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
  await screen.findByRole("group", { name: "3D embedding map" }, T);
  await screen.findByRole("region", { name: "Review lists" }, T);
  return view;
}

describe("CampaignsPage: structure for assistive technology", () => {
  beforeEach(() => {
    stubMatchMedia();
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(getCampaignSummary).mockReset().mockResolvedValue(fixtureCampaignSummary);
    vi.mocked(getMailVolume).mockReset().mockResolvedValue(fixtureMailVolume);
    vi.mocked(getNeighbours).mockReset().mockResolvedValue(fixtureNeighbours);
    vi.mocked(getPca).mockReset().mockResolvedValue(fixturePca);
    vi.mocked(detectWebGL).mockReturnValue(true);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("has one h1, an h2 for every panel, and no heading level skipped", async () => {
    await renderPage();
    const headings = screen.getAllByRole("heading").map((h) => ({ level: Number(h.tagName[1]), name: h.textContent }));
    expect(headings.filter((h) => h.level === 1)).toEqual([{ level: 1, name: "Campaigns" }]);
    expect(headings[0].level).toBe(1);
    const h2 = headings.filter((h) => h.level === 2).map((h) => h.name);
    expect(h2).toEqual(
      expect.arrayContaining(["Messages", "Dangerous share", "Active campaigns", "Largest campaign", "Peak day", "Embedding map", "Messages to review", "Messages per day", "Classification mix", "Campaigns in this period"])
    );
    // Going down never jumps more than one level (h2 to h4), whatever the panel shows.
    headings.slice(1).forEach((h, i) => expect(h.level - headings[i].level).toBeLessThanOrEqual(1));
    // The KPI number is a styled paragraph, not a second h1.
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
  });

  it("names every region once", async () => {
    await renderPage();
    const names = screen.getAllByRole("region").map((r) => r.getAttribute("aria-label") ?? document.getElementById(r.getAttribute("aria-labelledby")!)?.textContent);
    expect(names.every(Boolean)).toBe(true);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toEqual(expect.arrayContaining(["Embedding map", "Messages to review", "Review lists"]));
  });

  it("gives every table a name, in both the table views and the default one", async () => {
    const user = userEvent.setup();
    await renderPage();
    for (const toggle of screen.getAllByRole("button", { name: "Table view" })) await user.click(toggle);
    const tables = screen.getAllByRole("table");
    expect(tables.length).toBeGreaterThanOrEqual(3);
    for (const t of tables) expect(t, t.outerHTML.slice(0, 80)).toHaveAccessibleName();
    expect(screen.getByRole("table", { name: /Sampled messages with their position/ })).toBeInTheDocument();
  });

  it("tabs from the skip link to the map group to the review lists, each before the next", async () => {
    const user = userEvent.setup();
    await renderPage();
    const visited: string[] = [];
    // Start at the Period select and walk forward; stop once the review rows have been reached.
    screen.getByRole("combobox", { name: "Period" }).focus();
    for (let i = 0; i < 60; i++) {
      await user.tab();
      const el = document.activeElement as HTMLElement;
      visited.push(el.getAttribute("aria-label") ?? el.textContent?.trim() ?? el.tagName);
      if (/^Reset your password/.test(visited[visited.length - 1])) break;
    }
    const at = (name: string | RegExp) => visited.findIndex((v) => (typeof name === "string" ? v === name : name.test(v)));
    expect(at("Skip map")).toBeGreaterThan(-1);
    expect(at("3D embedding map")).toBe(at("Skip map") + 1);
    expect(at("Review lists")).toBeGreaterThan(at("3D embedding map"));
    expect(at(/^Reset your password/)).toBe(at("Review lists") + 1);
  });

  it("has a Retry in the panel that failed, for each query, and the panel recovers", async () => {
    const user = userEvent.setup();
    const cases = [
      [getCampaignSummary, "the indicators"],
      [getMailVolume, "the message volume"],
      [getPca, "the embedding map"],
      [getNeighbours, "the review lists"],
    ] as const;
    for (const [fn, what] of cases) {
      vi.mocked(fn as never as typeof getPca).mockRejectedValueOnce(new Error("boom"));
      const { unmount } = renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      const alert = (await screen.findAllByText(`Could not load ${what}.`, {}, T))[0].closest('[role="alert"]') as HTMLElement;
      // The summary feeds three panels: each shows its own Retry.
      await user.click(within(alert).getByRole("button", { name: "Retry" }));
      await waitFor(() => expect(screen.queryByText(`Could not load ${what}.`)).not.toBeInTheDocument(), T);
      unmount();
    }
  });

  it("keeps links and text buttons readable when the theme's accent is too light for text", async () => {
    // Amber on white is about 1.9:1; sunrise, summer and metal have the same problem with their own accents.
    const light = createTheme({ palette: { primary: { main: "#ffb74d" }, background: { paper: "#ffffff", default: "#ffffff" } } });
    renderWithProviders(
      <ThemeProvider theme={light}>
        <CampaignsPage />
      </ThemeProvider>,
      { initialPath: "/campaigns" }
    );
    await screen.findByRole("group", { name: "3D embedding map" }, T);
    const targets = [
      ...screen.getAllByRole("button", { name: /^(Show in map|Table view|Reset view)$/ }),
      ...screen.getAllByRole("link", { name: /^(Case |Open latest case|Skip map)/ }),
    ];
    expect(targets.length).toBeGreaterThan(4);
    for (const el of targets) {
      const ratio = contrastRatio(getComputedStyle(el).color, "#ffffff");
      expect(ratio, el.textContent ?? "").toBeGreaterThanOrEqual(4.5);
    }
  });
});
