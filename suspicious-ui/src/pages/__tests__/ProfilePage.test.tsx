import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient } from "@tanstack/react-query";
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

  describe("State across navigation", () => {
    it("keeps preference toggles checked after unmount/remount with warm query cache", async () => {
      localStorage.clear();
      // Realistic client: cache survives unmount (gcTime > 0), like the app default.
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: { retry: false, gcTime: 5 * 60_000, staleTime: 0 },
          mutations: { retry: false },
        },
      });

      const { rerender } = renderWithProviders(<ProfilePage key="first" />, {
        initialPath: "/profile",
        queryClient,
      });

      // Initial mount: toggles hydrate from the fetched profile (both true).
      await waitFor(() => {
        const toggles = screen.getAllByRole("switch");
        expect(toggles).toHaveLength(2);
        toggles.forEach((t) => expect(t).toBeChecked());
      });

      // Simulate navigating to another page and back: remount with warm cache.
      rerender(<ProfilePage key="second" />);

      await waitFor(() => {
        const toggles = screen.getAllByRole("switch");
        expect(toggles).toHaveLength(2);
        toggles.forEach((t) => expect(t).toBeChecked());
      });
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

  describe("Avatar section", () => {
    it("clears pinned options when switching to a different style", async () => {
      const user = userEvent.setup();
      renderWithProviders(<ProfilePage />, { initialPath: "/profile" });

      // Nav to Avatar (fixtureProfile has no avatar set, so no style is
      // selected yet — the style grid is visible but the "Customize"
      // carousel only appears once a style is picked).
      await user.click(await screen.findByText("Avatar"));
      await user.click(await screen.findByAltText("Avataaars"));

      // Pin the "Eyes" category away from its "Auto" default.
      const eyesNext = await screen.findByLabelText("Eyes next option");
      await user.click(eyesNext);
      await waitFor(() => {
        expect(screen.getByLabelText("Eyes use random")).toBeEnabled();
      });

      // Switch to a different style — the stale "eyes" option must not
      // survive (it's not even a valid key for every style, and colliding
      // key names must not carry a phantom pinned value across styles).
      await user.click(await screen.findByAltText("Bottts"));

      // Switching back to avataaars proves the option map was actually
      // reset (not just hidden because bottts lacks an "eyes" category).
      await user.click(await screen.findByAltText("Avataaars"));
      await screen.findByLabelText("Eyes next option");
      await waitFor(() => {
        expect(screen.getByLabelText("Eyes use random")).toBeDisabled();
      });
    });
  });
});
