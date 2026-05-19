import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { fixtureMe, fixtureDashboardSummary } from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/features/dashboard/api", () => ({
  getDashboardSummary: vi.fn(),
}));


import { getMe } from "@/api/auth";
import { getDashboardSummary } from "@/features/dashboard/api";
import DashboardPage from "../DashboardPage";

describe("DashboardPage - Test Suite", () => {
  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(getDashboardSummary).mockResolvedValue(fixtureDashboardSummary);
  });

  describe("Page Navigation and Access", () => {
    it("renders the dashboard title", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByText(/dashboard/i, {}, { timeout: 5000 })).toBeInTheDocument();
    });

    it("fetches the dashboard summary on mount", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await waitFor(() => expect(getDashboardSummary).toHaveBeenCalled());
    });

    it("resolves the authenticated user before rendering KPIs", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      await waitFor(() => expect(getMe).toHaveBeenCalled());
    });
  });

  describe("Display", () => {
    it("shows the Overview section once data resolves", async () => {
      renderWithProviders(<DashboardPage />, { initialPath: "/dashboard" });
      expect(await screen.findByText(/overview/i, {}, { timeout: 5000 })).toBeInTheDocument();
    });

  });

  describe("Management", () => {
    it("re-renders for an empty danger-counts payload without crashing", async () => {
      vi.mocked(getDashboardSummary).mockResolvedValue({
        ...fixtureDashboardSummary,
        danger_counts: {
          failure: 0,
          safe: 0,
          inconclusive: 0,
          suspicious: 0,
          dangerous: 0,
          malicious: 0,
        },
        top_prefixes: [],
      });
      const { container } = renderWithProviders(<DashboardPage />, {
        initialPath: "/dashboard",
      });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
      await waitFor(() => expect(getDashboardSummary).toHaveBeenCalled());
    });
  });
});
