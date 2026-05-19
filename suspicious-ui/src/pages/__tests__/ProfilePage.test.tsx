import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { fixtureMe, fixtureProfile } from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/features/profile/api", () => ({
  getProfile: vi.fn(),
  updateAppearance: vi.fn(),
  updatePreferences: vi.fn(),
  updateSemanticColors: vi.fn(),
  resetSemanticColors: vi.fn(),
}));


import { getMe } from "@/api/auth";
import { getProfile, updatePreferences } from "@/features/profile/api";
import ProfilePage from "../ProfilePage";

describe("ProfilePage - Test Suite", () => {
  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(getProfile).mockResolvedValue(fixtureProfile);
    vi.mocked(updatePreferences).mockResolvedValue(fixtureProfile);
  });

  describe("Page Navigation and Access", () => {
    it("renders without crashing on the profile route", async () => {
      const { container } = renderWithProviders(<ProfilePage />, {
        initialPath: "/profile",
      });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });

    it("calls getProfile and getMe on mount", async () => {
      renderWithProviders(<ProfilePage />, { initialPath: "/profile" });
      await waitFor(() => {
        expect(getMe).toHaveBeenCalled();
        expect(getProfile).toHaveBeenCalled();
      });
    });
  });

  describe("Display", () => {
    it("shows the Appearance section", async () => {
      renderWithProviders(<ProfilePage />, { initialPath: "/profile" });
      expect(
        await screen.findByText(/appearance/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });

    it("shows the Acknowledgements preference row", async () => {
      renderWithProviders(<ProfilePage />, { initialPath: "/profile" });
      expect(
        await screen.findByText(/acknowledgements/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });

  });

  describe("Management", () => {
    it("keeps the profile mounted across renders without throwing", async () => {
      const { container } = renderWithProviders(<ProfilePage />, {
        initialPath: "/profile",
      });
      await waitFor(() => expect(getProfile).toHaveBeenCalled());
      expect(container.textContent ?? "").not.toBe("");
    });
  });
});
