import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import {
  fixtureMe,
  fixtureClassificationCounts,
  fixturePca,
  fixtureMailVolume,
} from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/features/campaigns/api", () => ({
  getClassificationCounts: vi.fn(),
  getPca: vi.fn(),
  getMailVolume: vi.fn(),
}));


import { getMe } from "@/api/auth";
import {
  getClassificationCounts,
  getPca,
  getMailVolume,
} from "@/features/campaigns/api";
import CampaignsPage from "../CampaignsPage";

describe("CampaignsPage - Test Suite", () => {
  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(getClassificationCounts).mockResolvedValue(fixtureClassificationCounts);
    vi.mocked(getPca).mockResolvedValue(fixturePca);
    vi.mocked(getMailVolume).mockResolvedValue(fixtureMailVolume);
  });

  describe("Page Navigation and Access", () => {
    it("renders the Campaign Dashboard heading", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(
        await screen.findByText(/campaign dashboard/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });

    it("issues the three campaign queries on mount", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      await waitFor(() => {
        expect(getClassificationCounts).toHaveBeenCalled();
        expect(getPca).toHaveBeenCalled();
        expect(getMailVolume).toHaveBeenCalled();
      });
    });
  });

  describe("Display", () => {
    it("shows the Classification repartition panel", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(
        await screen.findByText(/classification repartition/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });

    it("shows the Embeddings map (PCA) panel", async () => {
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(
        await screen.findByText(/embeddings map/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });

  });

  describe("Management", () => {
    it("re-renders when classification counts are empty", async () => {
      vi.mocked(getClassificationCounts).mockResolvedValue({
        SAFE: 0,
        UNWANTED: 0,
        DANGEROUS: 0,
      });
      renderWithProviders(<CampaignsPage />, { initialPath: "/campaigns" });
      expect(
        await screen.findByText(/campaign dashboard/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });
  });
});
