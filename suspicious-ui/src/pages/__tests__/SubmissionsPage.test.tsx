import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { fixtureMe, fixtureSubmissionsList } from "@/test/fixtures";

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/features/submissions/api", () => ({
  listSubmissions: vi.fn(),
  getSubmissionDetails: vi.fn(),
  challengeSubmission: vi.fn(),
  analyzeUrl: vi.fn().mockResolvedValue({ status: "queued", url_id: 0 }),
  buildSortOrdering: vi.fn(
    (field: string, dir: string) => `${dir === "asc" ? "" : "-"}${field}`
  ),
}));


import { getMe } from "@/api/auth";
import { listSubmissions } from "@/features/submissions/api";
import SubmissionsPage from "../SubmissionsPage";

describe("SubmissionsPage - Test Suite", () => {
  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(listSubmissions).mockResolvedValue(fixtureSubmissionsList as never);
  });

  describe("Page Navigation and Access", () => {
    it("renders without crashing on the submissions route", async () => {
      const { container } = renderWithProviders(<SubmissionsPage />, {
        initialPath: "/submissions",
      });
      await waitFor(() => expect(container.firstChild).toBeTruthy());
    });

    it("queries the submissions list on mount", async () => {
      renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
      await waitFor(() => expect(listSubmissions).toHaveBeenCalled());
    });
  });

  describe("Display", () => {
    it("shows rows when submissions are returned", async () => {
      renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
      expect(
        await screen.findByText(/phish@example\.com/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });

    it("shows the second submission row from the fixture", async () => {
      renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
      expect(
        await screen.findByText(/benign\.example\.org/i, {}, { timeout: 5000 })
      ).toBeInTheDocument();
    });
  });

  describe("Management", () => {
    it("re-issues the submissions query when re-mounted", async () => {
      vi.mocked(listSubmissions).mockClear();
      renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
      await waitFor(() => expect(listSubmissions).toHaveBeenCalled());
    });
  });
});
