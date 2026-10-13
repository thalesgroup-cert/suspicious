import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { fixtureMe, fixtureDashboardSummary } from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/features/dashboard/api", () => ({
  getDashboardSummary: vi.fn(),
  getDashboardScopes: vi.fn(),
}));

import { getMe } from "@/api/auth";
import { getDashboardScopes, getDashboardSummary } from "@/features/dashboard/api";
import DashboardPage from "../DashboardPage";

const plainUser = { ...fixtureMe, groups: [] as string[] };

const AU_SCOPES = {
  default: "OWN_COUNTRY",
  options: [
    { key: "OWN_COUNTRY", label: "My country (AU)" },
    { key: "ALL", label: "Overall" },
  ],
};

const OVERALL_ONLY = { default: "ALL", options: [{ key: "ALL", label: "Overall" }] };

// Echo the requested scope back the way the backend labels it.
const LABELS: Record<string, string> = {
  OWN_COUNTRY: "My country (AU)",
  ALL: "Overall",
  "COUNTRY:NZ": "NZ",
};
function summaryFor({ scope }: { scope?: string }) {
  const key = scope ?? "ALL";
  return Promise.resolve({ ...fixtureDashboardSummary, scope: { key, label: LABELS[key] ?? key } });
}

function lastSummaryCall() {
  const calls = vi.mocked(getDashboardSummary).mock.calls;
  return calls[calls.length - 1]?.[0];
}

async function openSelect(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(await screen.findByRole("combobox", { name }, { timeout: 5000 }));
  return screen.findByRole("listbox");
}

// Tests run in a real browser whose default viewport is narrow: pin the breakpoint explicitly.
const stubViewport = (phone: boolean) =>
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: phone && query.includes("max-width"),
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    onchange: null,
    dispatchEvent: () => false,
  }));

describe("DashboardPage - Test Suite", () => {
  beforeEach(() => {
    stubViewport(false);
    localStorage.clear();
    vi.mocked(getMe).mockResolvedValue(plainUser);
    vi.mocked(getDashboardScopes).mockResolvedValue(AU_SCOPES);
    vi.mocked(getDashboardSummary).mockReset().mockImplementation(summaryFor);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  describe("Page Navigation and Access", () => {
    it("renders the dashboard title", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByRole("heading", { name: "Dashboard" }, { timeout: 5000 })).toBeInTheDocument();
    });

    it("fetches the dashboard summary for the default scope on mount", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await waitFor(() => expect(getDashboardSummary).toHaveBeenCalled());
      expect(lastSummaryCall()).toMatchObject({ scope: "OWN_COUNTRY" });
    });

    it("resolves the authenticated user before rendering KPIs", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await waitFor(() => expect(getMe).toHaveBeenCalled());
    });
  });

  describe("Header", () => {
    it("shows scope, month and year in the header without opening a popover", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByRole("combobox", { name: "Scope" }, { timeout: 5000 })).toHaveTextContent(
        "My country (Australia)"
      );
      expect(screen.getByRole("combobox", { name: "Month" })).toBeVisible();
      expect(screen.getByRole("combobox", { name: "Year" })).toBeVisible();
      expect(screen.queryByRole("button", { name: /time & scope/i })).not.toBeInTheDocument();
    });

    it("reads the period and the scope name in the subtitle", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByText("October 2026 · Australia", {}, { timeout: 5000 })).toBeInTheDocument();
    });

    it("lists only the scopes the backend offers", async () => {
      const user = userEvent.setup();
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      const list = await openSelect(user, "Scope");
      expect(within(list).getAllByRole("option").map((o) => o.textContent)).toEqual([
        "My country (Australia)",
        "Overall",
      ]);
    });

    it("refetches the summary with the chosen scope", async () => {
      const user = userEvent.setup();
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      const list = await openSelect(user, "Scope");
      await user.click(within(list).getByRole("option", { name: "Overall" }));
      await waitFor(() => expect(lastSummaryCall()).toMatchObject({ scope: "ALL" }));
      expect(await screen.findByText("October 2026 · Overall")).toBeInTheDocument();
    });

    it("explains why when Overall is the only scope", async () => {
      vi.mocked(getDashboardScopes).mockResolvedValue(OVERALL_ONLY);
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByText("Only Overall is available: your profile has no country that can be used as a scope.", {}, { timeout: 5000 })).toBeInTheDocument();
      expect(screen.getByRole("combobox", { name: "Scope" })).toHaveTextContent("Overall");
    });

    it("does not show the explanation when the user's country is available", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await screen.findByText("October 2026 · Australia", {}, { timeout: 5000 });
      expect(screen.queryByText("Only Overall is available: your profile has no country that can be used as a scope.")).not.toBeInTheDocument();
    });

    it("does not show the explanation to a CERT user with several scopes but no own country", async () => {
      vi.mocked(getMe).mockResolvedValue(fixtureMe);
      vi.mocked(getDashboardScopes).mockResolvedValue({
        default: "ALL",
        options: [
          { key: "ALL", label: "Overall" },
          { key: "COUNTRY:NZ", label: "NZ" },
          { key: "REGION:APAC", label: "APAC" },
        ],
      });
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await screen.findByText("October 2026 · Overall", {}, { timeout: 5000 });
      expect(screen.queryByText(/only overall is available/i)).not.toBeInTheDocument();
    });

    it("says so when the scopes cannot be loaded and shows Overall", async () => {
      vi.mocked(getDashboardScopes).mockRejectedValue({ isAxiosError: true, response: { status: 500 } });
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(
        await screen.findByText("Scopes could not be loaded; showing Overall.", {}, { timeout: 5000 })
      ).toBeInTheDocument();
      expect(lastSummaryCall()).toMatchObject({ scope: "ALL" });
      expect(screen.queryByText(/only overall is available/i)).not.toBeInTheDocument();
    });

    it("keeps the grid mounted while a new scope loads", async () => {
      const user = userEvent.setup();
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      const grid = await screen.findByTestId("dashboard-grid", {}, { timeout: 5000 });
      let release!: () => void;
      vi.mocked(getDashboardSummary).mockImplementation(
        (p) => new Promise((r) => { release = () => r(summaryFor(p)); })
      );
      const list = await openSelect(user, "Scope");
      await user.click(within(list).getByRole("option", { name: "Overall" }));
      await waitFor(() => expect(lastSummaryCall()).toMatchObject({ scope: "ALL" }));
      expect(screen.getByTestId("dashboard-grid")).toBe(grid);
      await act(async () => release());
      expect(await screen.findByText("October 2026 · Overall")).toBeInTheDocument();
      expect(screen.getByTestId("dashboard-grid")).toBe(grid);
    });

    it("shows a loading cue while a new scope loads, then the new scope", async () => {
      const user = userEvent.setup();
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await screen.findByText("October 2026 · Australia", {}, { timeout: 5000 });
      expect(await screen.findByTestId("dashboard-grid")).toHaveAttribute("aria-busy", "false");
      let release!: () => void;
      vi.mocked(getDashboardSummary).mockImplementation(
        (p) => new Promise((r) => { release = () => r(summaryFor(p)); })
      );
      const list = await openSelect(user, "Scope");
      await user.click(within(list).getByRole("option", { name: "Overall" }));
      expect(await screen.findByRole("progressbar", { name: "Loading Overall" })).toBeInTheDocument();
      expect(screen.getByTestId("dashboard-grid")).toHaveAttribute("aria-busy", "true");
      expect(screen.getByText("October 2026 · Australia")).toBeInTheDocument();
      await act(async () => release());
      expect(await screen.findByText("October 2026 · Overall")).toBeInTheDocument();
      expect(screen.queryByRole("progressbar", { name: /^Loading/ })).not.toBeInTheDocument();
      expect(screen.getByTestId("dashboard-grid")).toHaveAttribute("aria-busy", "false");
    });

    it("lets a plain user change the month and year", async () => {
      const user = userEvent.setup();
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      let list = await openSelect(user, "Month");
      await user.click(within(list).getByRole("option", { name: "March" }));
      await waitFor(() => expect(lastSummaryCall()).toMatchObject({ month: 3 }));
      list = await openSelect(user, "Year");
      const year = within(list).getAllByRole("option")[0];
      await user.click(year);
      await waitFor(() => expect(lastSummaryCall()).toMatchObject({ month: 3, year: Number(year.textContent) }));
    });

    it("falls back to the default scope with a message when the chosen scope is refused", async () => {
      vi.mocked(getDashboardScopes).mockResolvedValue({
        ...AU_SCOPES,
        options: [...AU_SCOPES.options, { key: "COUNTRY:NZ", label: "NZ" }],
      });
      vi.mocked(getDashboardSummary).mockImplementation((p) =>
        p.scope === "COUNTRY:NZ" ? Promise.reject({ isAxiosError: true, response: { status: 403 } }) : summaryFor(p)
      );
      const user = userEvent.setup();
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      const list = await openSelect(user, "Scope");
      await user.click(within(list).getByRole("option", { name: "New Zealand" }));
      expect(await screen.findByText(/new zealand is not available/i, {}, { timeout: 5000 })).toBeInTheDocument();
      await waitFor(() => expect(lastSummaryCall()).toMatchObject({ scope: "OWN_COUNTRY" }));
      expect(screen.getByRole("combobox", { name: "Scope" })).toHaveTextContent("My country (Australia)");
      expect(screen.getByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    });
  });

  describe("Errors", () => {
    it("shows the error with Retry, not a fallback, for a 400 on a chosen scope", async () => {
      vi.mocked(getDashboardSummary).mockImplementation((p) =>
        p.scope === "ALL" ? Promise.reject({ isAxiosError: true, response: { status: 400 } }) : summaryFor(p)
      );
      const user = userEvent.setup();
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      const list = await openSelect(user, "Scope");
      await user.click(within(list).getByRole("option", { name: "Overall" }));
      expect(await screen.findByRole("button", { name: "Retry" }, { timeout: 5000 })).toBeInTheDocument();
      expect(screen.queryByText(/is not available to you/i)).not.toBeInTheDocument();
      expect(lastSummaryCall()).toMatchObject({ scope: "ALL" });
    });

    it("lands on the error with Retry when the default scope itself is refused (no loop)", async () => {
      vi.mocked(getDashboardSummary).mockRejectedValue({ isAxiosError: true, response: { status: 403 } });
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByRole("button", { name: "Retry" }, { timeout: 5000 })).toBeInTheDocument();
      const calls = vi.mocked(getDashboardSummary).mock.calls.length;
      await new Promise((r) => setTimeout(r, 300));
      expect(vi.mocked(getDashboardSummary).mock.calls.length).toBe(calls);
      expect(calls).toBe(1);
      expect(screen.queryByText(/is not available to you/i)).not.toBeInTheDocument();
    });

    it("offers a real Retry button that refetches", async () => {
      vi.mocked(getDashboardSummary).mockRejectedValue({ isAxiosError: true, response: { status: 500 } });
      const user = userEvent.setup();
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      const retry = await screen.findByRole("button", { name: "Retry" }, { timeout: 5000 });
      expect(retry.tagName).toBe("BUTTON");
      const before = vi.mocked(getDashboardSummary).mock.calls.length;
      vi.mocked(getDashboardSummary).mockImplementation(summaryFor);
      await user.click(retry);
      await waitFor(() => expect(vi.mocked(getDashboardSummary).mock.calls.length).toBeGreaterThan(before));
      expect(await screen.findByText("October 2026 · Australia")).toBeInTheDocument();
      // The header stays usable while the body shows the error.
      expect(screen.getByRole("combobox", { name: "Scope" })).toBeInTheDocument();
    });
  });

  describe("Display", () => {
    it("shows the Overview section once data resolves", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByText(/overview/i, {}, { timeout: 5000 })).toBeInTheDocument();
    });

    it("says no data, with no arrow, when the previous month has no reports", async () => {
      vi.mocked(getDashboardSummary).mockImplementation((p) =>
        summaryFor(p).then((d) => ({ ...d, previous: { ...d.previous, reports: 0 } }))
      );
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      const reports = await screen.findByRole("region", { name: "Reports" }, { timeout: 5000 });
      expect(within(reports).getByText("vs September: no data")).toBeInTheDocument();
      expect(document.querySelector('[data-testid^="Trending"]')).toBeNull();
    });

    it("shows only the empty state, naming scope and period, when nothing was reported", async () => {
      vi.mocked(getDashboardSummary).mockImplementation((p) =>
        summaryFor(p).then((d) => ({
          ...d,
          reports: 0,
          in_progress: 0,
          outcomes: { safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0, failure: 0 },
          by_type: { MAIL: 0, FILE: 0, URL: 0, IP: 0, HASH: 0, IOC: 0, UNKNOWN: 0 },
          reporters: 0,
          trend: [],
          top_reporters: [],
        }))
      );
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByText("No reports in this period", {}, { timeout: 5000 })).toBeInTheDocument();
      expect(screen.getByText("Nothing was reported in Australia in October 2026.")).toBeInTheDocument();
      expect(screen.queryAllByRole("region")).toEqual([]);
      expect(screen.queryByTestId("dashboard-grid")).not.toBeInTheDocument();
    });

    it("shows the panels, not the empty state, when cases exist but none has finished", async () => {
      vi.mocked(getDashboardSummary).mockImplementation((p) =>
        summaryFor(p).then((d) => ({
          ...d,
          reports: 2,
          in_progress: 2,
          outcomes: { safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0, failure: 0 },
          by_type: { MAIL: 2, FILE: 0, URL: 0, IP: 0, HASH: 0, IOC: 0, UNKNOWN: 0 },
        }))
      );
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      const outcomes = await screen.findByRole("region", { name: "Outcomes" }, { timeout: 5000 });
      expect(within(outcomes).getByText("No finished cases yet")).toBeInTheDocument();
      expect(within(outcomes).getByText("In progress: 2")).toBeInTheDocument();
      expect(screen.queryByText("No reports in this period")).not.toBeInTheDocument();
      expect(within(screen.getByRole("region", { name: "What was reported" })).getByText("Share of 2 reports")).toBeInTheDocument();
    });

    it("hides the reporters panel, and every reporter name, when top_reporters is null", async () => {
      vi.mocked(getDashboardSummary).mockResolvedValue({ ...fixtureDashboardSummary, top_reporters: null });
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await screen.findByRole("region", { name: "Outcomes" }, { timeout: 5000 });
      await waitFor(() => expect(document.querySelectorAll(".react-grid-item").length).toBe(3));
      expect(screen.queryByRole("region", { name: "Top reporters" })).not.toBeInTheDocument();
      expect(screen.queryByText(/top reporters/i)).not.toBeInTheDocument();
      expect(screen.queryByText("phishing-corp")).not.toBeInTheDocument();
    });

    it("shows the top reporters to an elevated user", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      const panel = await screen.findByRole("region", { name: "Top reporters" }, { timeout: 5000 });
      expect(within(panel).getAllByRole("listitem").map((r) => r.textContent)).toEqual([
        "phishing-corp17",
        "spoof-it9",
      ]);
    });

    it("renders every panel as a region named by its h2", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await screen.findByRole("region", { name: "Outcomes" }, { timeout: 5000 });
      const names = screen.getAllByRole("region").map((r) => {
        const heading = document.getElementById(r.getAttribute("aria-labelledby")!)!;
        expect(heading.tagName).toBe("H2");
        return heading.textContent;
      });
      expect(names).toEqual(["Reports", "Dangerous", "Reporters", "Outcomes", "What was reported", "Top reporters"]);
    });

    it("still renders every panel from an older saved layout that lacks the new panels", async () => {
      localStorage.setItem(
        "dashboard:layouts:1",
        JSON.stringify({
          lg: [
            { i: "kpi-trends", x: 0, y: 0, w: 12, h: 6 },
            { i: "top-prefixes", x: 0, y: 6, w: 8, h: 14 },
            { i: "threat-distribution", x: 8, y: 6, w: 4, h: 14 },
          ],
        })
      );
      vi.mocked(getMe).mockResolvedValue({ ...plainUser, id: 1 });
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await screen.findByRole("region", { name: "Outcomes" }, { timeout: 5000 });
      await waitFor(() => expect(document.querySelectorAll(".react-grid-item").length).toBe(4));
      expect(screen.getByRole("region", { name: "What was reported" })).toBeInTheDocument();
    });
  });

  describe("Phone", () => {
    it("stacks the panels in one column with no grid, handles or saved layouts", async () => {
      stubViewport(true);
      const getItem = vi.spyOn(Storage.prototype, "getItem");
      const setItem = vi.spyOn(Storage.prototype, "setItem");
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await screen.findByRole("region", { name: "Outcomes" }, { timeout: 5000 });
      const stack = screen.getByTestId("dashboard-stack");
      const order = screen.getAllByRole("region").map((r) => document.getElementById(r.getAttribute("aria-labelledby")!)!.textContent);
      expect(order).toEqual(["Reports", "Dangerous", "Reporters", "Outcomes", "What was reported", "Top reporters"]);
      expect(stack).toBeInTheDocument();
      expect(screen.queryByTestId("dashboard-grid")).not.toBeInTheDocument();
      expect(document.querySelector(".react-grid-item")).toBeNull();
      expect(document.querySelector(".react-resizable-handle")).toBeNull();
      expect(document.querySelector(".dashboard-panel-drag-handle")).toBeNull();
      expect(screen.queryByRole("button", { name: "Reset layout" })).not.toBeInTheDocument();
      const layoutKey = ([k]: unknown[]) => String(k).startsWith("dashboard:layouts");
      expect(getItem.mock.calls.filter(layoutKey)).toEqual([]);
      expect(setItem.mock.calls.filter(layoutKey)).toEqual([]);
    });
  });

  describe("Stable first paint (D1)", () => {
    it("never writes saved layouts on mount or on a theme change, and never loops", async () => {
      const setItem = vi.spyOn(Storage.prototype, "setItem");
      const consoleError = vi.spyOn(console, "error");
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await waitFor(() => expect(document.querySelectorAll(".react-grid-item").length).toBe(4), { timeout: 5000 });
      await act(async () => {
        window.dispatchEvent(
          new CustomEvent("suspicious:theme-hydrate", { detail: { theme: "paper", autoSeasonal: false } })
        );
        await new Promise((r) => setTimeout(r, 600));
      });
      await act(async () => {
        window.dispatchEvent(
          new CustomEvent("suspicious:theme-hydrate", { detail: { theme: "midnight", autoSeasonal: false } })
        );
        await new Promise((r) => setTimeout(r, 600));
      });
      const layoutWrites = setItem.mock.calls.filter(([k]) => String(k).startsWith("dashboard:layouts"));
      expect(layoutWrites).toEqual([]);
      expect(
        consoleError.mock.calls.filter((args) => /Maximum update depth|#185/.test(String(args[0])))
      ).toEqual([]);
    });
  });
});
