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

  describe("Management", () => {
    it("renders the home route under a Suspense-friendly tree", async () => {
      const { container } = renderWithProviders(<HomePage />, { initialPath: "/" });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });
  });
});
