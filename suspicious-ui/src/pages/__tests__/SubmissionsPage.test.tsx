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

vi.mock("@/features/comments/api", () => ({
  getCaseComments: vi.fn().mockResolvedValue([]),
  addCaseComment: vi.fn().mockResolvedValue({
    id: 1, author_email: "me@example.com", body: "checking on this", is_internal: false, created_at: "2026-07-09T10:00:00Z",
  }),
}));


import { getMe } from "@/api/auth";
import { listSubmissions, challengeSubmission } from "@/features/submissions/api";
import { addCaseComment, getCaseComments } from "@/features/comments/api";
import SubmissionsPage from "../SubmissionsPage";

// Tests run in a real browser whose default viewport is narrow: pin the breakpoint explicitly.
const stub = (phone: boolean) =>
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: phone && query.includes("max-width"),
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    onchange: null,
    dispatchEvent: () => false,
  }));


describe("SubmissionsPage - Test Suite", () => {
  beforeEach(() => {
    stub(false);
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
    it("renders the page title as an h1 at page-title size", async () => {
      renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
      const h = await screen.findByRole("heading", { level: 1, name: "Submissions" });
      expect(parseFloat(getComputedStyle(h).fontSize)).toBeGreaterThanOrEqual(20);
    });

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

  describe("Comments", () => {
    it("adds a comment from the submissions drawer", async () => {
      const user = userEvent.setup();
      renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });

      await screen.findByText(/phish@example\.com/i, {}, { timeout: 5000 });
      await user.click(screen.getByText(/phish@example\.com/i));

      const textarea = await screen.findByPlaceholderText("Add a comment…");
      await user.type(textarea, "checking on this");
      await user.click(screen.getByRole("button", { name: "Add" }));

      await waitFor(() =>
        expect(addCaseComment).toHaveBeenCalledWith(101, "checking on this")
      );
    });
  });
});

describe("SubmissionsPage - detail drawer header", () => {
  it("is sticky so Close stays reachable while the content scrolls", async () => {
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(listSubmissions).mockResolvedValue(fixtureSubmissionsList as never);
    const id = (fixtureSubmissionsList as { results: { id: number }[] }).results[0].id;
    renderWithProviders(<SubmissionsPage />, { initialPath: `/submissions?open=${id}` });
    const header = await screen.findByTestId("sheet-header");
    expect(getComputedStyle(header).position).toBe("sticky");
  });
});

describe("SubmissionsPage - phone layout", () => {
  const HASH = "a".repeat(64);
  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(listSubmissions).mockResolvedValue({
      ...fixtureSubmissionsList,
      results: [{ ...fixtureSubmissionsList.results[0], artifact: HASH }, fixtureSubmissionsList.results[1]],
    } as never);
  });
  it("renders a stacked list with ID link and verdict, no table, on a phone", async () => {
    stub(true);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    const link = await screen.findByRole("link", { name: "101" });
    expect(link).toHaveAttribute("href", "/submissions?open=101");
    expect(screen.getAllByRole("listitem").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/dangerous/i)).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
    const art = screen.getByTitle(HASH);
    expect(getComputedStyle(art).textOverflow).toBe("ellipsis");
    expect(getComputedStyle(art).whiteSpace).toBe("nowrap");
  });

  it("tapping an ID opens the drawer without filtering; reopens after close", async () => {
    stub(true);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    const link = await screen.findByRole("link", { name: "101" });
    await userEvent.click(link);
    await screen.findByTestId("sheet-header");
    expect(screen.getByPlaceholderText(/id, status, artifact/i)).toHaveValue("");
    await userEvent.click(screen.getAllByRole("button", { name: /close/i })[0]);
    await waitFor(() => expect(screen.queryByTestId("sheet-header")).toBeNull());
    expect(screen.getByPlaceholderText(/id, status, artifact/i)).toHaveValue("");
    expect(screen.getByRole("link", { name: "102" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("link", { name: "101" }));
    expect(await screen.findByTestId("sheet-header")).toBeInTheDocument();
  });

  it("keeps the table on desktop", async () => {
    stub(false);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    expect(await screen.findByRole("table")).toBeInTheDocument();
  });
});
