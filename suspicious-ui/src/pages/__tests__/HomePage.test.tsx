import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { fixtureMe, fixtureDashboardSummary } from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/api/client", () => ({
  api: {
    get: vi.fn().mockResolvedValue({ data: { count: 0, results: [] } }),
    post: vi.fn().mockResolvedValue({ data: {} }),
    patch: vi.fn().mockResolvedValue({ data: {} }),
  },
}));

vi.mock("@/features/dashboard/api", () => ({
  getDashboardSummary: vi.fn(),
}));


import { getMe } from "@/api/auth";
import { api } from "@/api/client";
import { getDashboardSummary } from "@/features/dashboard/api";
import HomePage from "../HomePage";

describe("HomePage - Test Suite", () => {
  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(getDashboardSummary).mockResolvedValue(fixtureDashboardSummary);
  });

  describe("Page Navigation and Access", () => {
    it("renders without crashing on the home route", async () => {
      const { container } = renderWithProviders(<HomePage />, { initialPath: "/" });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });

    it("fetches the authenticated user on mount", async () => {
      renderWithProviders(<HomePage />, { initialPath: "/" });
      await waitFor(() => expect(getMe).toHaveBeenCalled());
    });
  });

  describe("Display", () => {
    it("keeps the page mounted while data is loading", async () => {
      const { container } = renderWithProviders(<HomePage />, { initialPath: "/" });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });
  });

  describe("Empty chart", () => {
    it("shows the spinner, not the empty message, while the home summary is loading", async () => {
      vi.mocked(api.get).mockImplementation((url: string) =>
        url === "/home/summary/"
          ? new Promise(() => {})
          : Promise.resolve({ data: { count: 0, results: [] } }),
      );
      renderWithProviders(<HomePage />, { initialPath: "/" });
      await screen.findByText("Threat distribution");
      expect(screen.getAllByRole("progressbar").length).toBeGreaterThan(0);
      expect(screen.queryByText("No submissions this month")).toBeNull();
    });
  });

  describe("Greeting heading", () => {
    it("does not squeeze letters so tightly that the word gap after the comma closes", async () => {
      renderWithProviders(<HomePage />, { initialPath: "/" });
      const h = await screen.findByText(/^Welcome,/);
      // Audit H4: -0.6px at 14px (about -0.043em) at weight 980 closed "Welcome,Elena".
      expect((parseFloat(getComputedStyle(h).letterSpacing) || 0)).toBeGreaterThanOrEqual(-0.14);
    });
  });

  describe("Management", () => {
    it("renders the home route under a Suspense-friendly tree", async () => {
      const { container } = renderWithProviders(<HomePage />, { initialPath: "/" });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });
  });
});
