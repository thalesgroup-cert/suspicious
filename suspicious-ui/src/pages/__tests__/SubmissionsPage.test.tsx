import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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
import { listSubmissions, challengeSubmission } from "@/features/submissions/api";
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

  describe("Challenge dialog", () => {
    it("requires a proposed verdict and submits it with the reason", async () => {
      const user = userEvent.setup();
      vi.mocked(listSubmissions).mockResolvedValue({
        ...fixtureSubmissionsList,
        results: [
          { ...fixtureSubmissionsList.results[0], is_challengeable: true },
          fixtureSubmissionsList.results[1],
        ],
      } as never);
      vi.mocked(challengeSubmission).mockResolvedValue({ detail: "ok" });

      renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });

      const challengeButton = await screen.findByRole("button", { name: /challenge/i });
      await user.click(challengeButton);

      const confirmButton = await screen.findByRole("button", { name: /confirm/i });
      expect(confirmButton).toBeDisabled();

      const dangerousToggle = await screen.findByRole("button", { name: /dangerous/i });
      await user.click(dangerousToggle);

      expect(confirmButton).not.toBeDisabled();
      await user.click(confirmButton);

      await waitFor(() =>
        expect(challengeSubmission).toHaveBeenCalledWith(
          101,
          { proposed_result: "Dangerous", reason: "" },
        )
      );
    });
  });
});
