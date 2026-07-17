import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import {
  fixtureMeSuperuser,
  fixtureSettingsList,
  fixtureFeederStatus,
  fixtureAnalyzers,
} from "@/test/fixtures";

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


import { getMe } from "@/api/auth";
import {
  listItems,
  getFeederStatus,
  getFeederHealth,
  listAnalyzers,
} from "@/features/settings/api";
import SettingsPage from "../SettingsPage";
void getFeederStatus;

describe("SettingsPage - Test Suite", () => {
  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue(fixtureMeSuperuser);
    vi.mocked(listItems).mockResolvedValue(fixtureSettingsList as never);
    vi.mocked(getFeederStatus).mockResolvedValue(fixtureFeederStatus);
    vi.mocked(getFeederHealth).mockResolvedValue({ ok: true, status: "ok" } as never);
    vi.mocked(listAnalyzers).mockResolvedValue(fixtureAnalyzers);
  });

  describe("Page Navigation and Access", () => {
    it("renders without crashing on the settings route", async () => {
      const { container } = renderWithProviders(<SettingsPage />, {
        initialPath: "/settings",
      });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });

    it("calls getMe on mount", async () => {
      renderWithProviders(<SettingsPage />, { initialPath: "/settings" });
      await waitFor(() => expect(getMe).toHaveBeenCalled());
    });
  });

  describe("Display", () => {
    it("shows the Email feeder section for an admin user", async () => {
      renderWithProviders(<SettingsPage />, { initialPath: "/settings" });
      expect(
        await screen.findByText(/email feeder/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });

    it("shows the Admin console card", async () => {
      renderWithProviders(<SettingsPage />, { initialPath: "/settings" });
      expect(
        await screen.findByText(/admin console/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });
  });

  describe("Management", () => {
    it("keeps the settings DOM mounted after first paint", async () => {
      const { container } = renderWithProviders(<SettingsPage />, {
        initialPath: "/settings",
      });
      await waitFor(() => expect(container.textContent ?? "").not.toBe(""));
    });
  });
});
