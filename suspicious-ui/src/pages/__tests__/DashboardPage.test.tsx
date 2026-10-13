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

describe("DashboardPage - Test Suite", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.mocked(getMe).mockResolvedValue(plainUser);
    vi.mocked(getDashboardScopes).mockResolvedValue(AU_SCOPES);
    vi.mocked(getDashboardSummary).mockReset().mockImplementation(summaryFor);
  });

  afterEach(() => vi.restoreAllMocks());

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

    it("explains that no country is set when only Overall is available", async () => {
      vi.mocked(getDashboardScopes).mockResolvedValue(OVERALL_ONLY);
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByText("No country is set on your profile.", {}, { timeout: 5000 })).toBeInTheDocument();
      expect(screen.getByRole("combobox", { name: "Scope" })).toHaveTextContent("Overall");
    });

    it("does not show the explanation when the user's country is available", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await screen.findByText("October 2026 · Australia", {}, { timeout: 5000 });
      expect(screen.queryByText("No country is set on your profile.")).not.toBeInTheDocument();
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

    it("renders the new payload with top_reporters null and empty legacy arrays", async () => {
      vi.mocked(getDashboardSummary).mockResolvedValue({
        ...fixtureDashboardSummary,
        top_reporters: null,
        top_prefixes: [],
        danger_counts: { failure: 0, safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0, malicious: 0 },
      });
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByText(/overview/i, {}, { timeout: 5000 })).toBeInTheDocument();
      expect(document.querySelectorAll(".react-grid-item").length).toBe(3);
    });
  });

  describe("Stable first paint (D1)", () => {
    it("never writes saved layouts on mount or on a theme change, and never loops", async () => {
      const setItem = vi.spyOn(Storage.prototype, "setItem");
      const consoleError = vi.spyOn(console, "error");
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await waitFor(() => expect(document.querySelectorAll(".react-grid-item").length).toBe(3), { timeout: 5000 });
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
