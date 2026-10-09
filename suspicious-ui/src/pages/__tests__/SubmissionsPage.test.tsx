import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
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
import { listSubmissions, challengeSubmission, getSubmissionDetails } from "@/features/submissions/api";
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
  beforeEach(() => stub(false));
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

describe("SubmissionsPage - filters, pager, header", () => {
  const many = (n: number) => ({
    ...fixtureSubmissionsList,
    count: n,
    results: Array.from({ length: n }, (_, i) => ({
      ...fixtureSubmissionsList.results[0],
      id: 1000 + i,
      artifact: `row-${i}@example.com`,
      is_challengeable: false,
    })),
  });
  beforeEach(() => {
    stub(false);
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(listSubmissions).mockResolvedValue(many(99) as never);
  });
  const open = async () => {
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    return screen.findByRole("button", { name: /^filters/i });
  };

  it("collapses everything but search behind a Filters button", async () => {
    const btn = await open();
    expect(screen.getByPlaceholderText(/id, status, artifact/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("Status")).toBeNull();
    await userEvent.click(btn);
    for (const l of ["Status", "Type", "Result", "From", "To", "Sort"]) {
      expect(await screen.findByLabelText(l)).toBeInTheDocument();
    }
  });

  it("counts active filters on the button; Reset appears and clears", async () => {
    const btn = await open();
    expect(screen.queryByRole("button", { name: /reset/i })).toBeNull();
    await userEvent.click(btn);
    await userEvent.click(await screen.findByLabelText("Type"));
    await userEvent.click(await screen.findByRole("option", { name: "MAIL" }));
    expect(screen.getByRole("button", { name: /^filters/i })).toHaveTextContent(/^Filters1$/);
    await userEvent.click(await screen.findByRole("button", { name: /reset/i }));
    await waitFor(() => expect(screen.queryByRole("button", { name: /reset/i })).toBeNull());
    expect(screen.getByRole("button", { name: /^filters/i })).toHaveTextContent(/^Filters$/);
  });

  it("pager sits below the table with 10/25/50 and x-y of N", async () => {
    await open();
    const table = await screen.findByRole("table");
    expect(screen.getByText("1–10 of 99")).toBeInTheDocument();
    const pager = screen.getByText("1–10 of 99").closest(".MuiTablePagination-root")!;
    expect(table.compareDocumentPosition(pager) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(table.contains(pager)).toBe(false);
    await userEvent.click(within(pager as HTMLElement).getByRole("combobox"));
    expect((await screen.findAllByRole("option")).map((o) => o.textContent)).toEqual(["10", "25", "50"]);
  });

  it("changing rows per page shows 25 rows on page 1", async () => {
    await open();
    await screen.findByRole("table");
    await userEvent.click(screen.getByRole("button", { name: /next page/i }));
    expect(await screen.findByText("11–20 of 99")).toBeInTheDocument();
    const pager = screen.getByText("11–20 of 99").closest(".MuiTablePagination-root") as HTMLElement;
    await userEvent.click(within(pager).getByRole("combobox"));
    await userEvent.click(await screen.findByRole("option", { name: "25" }));
    expect(await screen.findByText("1–25 of 99")).toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(26);
  });

  it("a filter change returns to page 1", async () => {
    const btn = await open();
    await screen.findByRole("table");
    await userEvent.click(screen.getByRole("button", { name: /next page/i }));
    expect(await screen.findByText("11–20 of 99")).toBeInTheDocument();
    await userEvent.click(btn);
    await userEvent.click(await screen.findByLabelText("Type"));
    await userEvent.click(await screen.findByRole("option", { name: "MAIL" }));
    expect(await screen.findByText(/^1–10 of/)).toBeInTheDocument();
  });

  it("header chip says total, then match when searching; no avatar", async () => {
    await open();
    expect(await screen.findByText("99 total")).toBeInTheDocument();
    expect(document.querySelector(".MuiAvatar-root")).toBeNull();
    await userEvent.type(screen.getByPlaceholderText(/id, status, artifact/i), "row-1");
    expect(await screen.findByText(/^\d+ match$/)).toBeInTheDocument();
    expect(screen.queryByText(/^Search:/)).toBeNull();
  });
});

describe("SubmissionsPage - calmer rows", () => {
  const rowsWith = (over: object[]) => ({
    ...fixtureSubmissionsList,
    results: fixtureSubmissionsList.results.map((r, i) => ({ ...r, ...(over[i] ?? {}) })),
  });
  beforeEach(() => {
    stub(false);
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
  });

  it("omits the Challenge column when no row on the page is eligible", async () => {
    vi.mocked(listSubmissions).mockResolvedValue(fixtureSubmissionsList as never);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    await screen.findByRole("table");
    expect(screen.queryByRole("columnheader", { name: "Challenge" })).toBeNull();
    expect(screen.queryByText("Not available")).toBeNull();
  });

  it("shows the Challenge column and button when a row is eligible", async () => {
    vi.mocked(listSubmissions).mockResolvedValue(rowsWith([{ is_challengeable: true }]) as never);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    await screen.findByRole("table");
    expect(screen.getByRole("columnheader", { name: "Challenge" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Challenge" })).toHaveLength(1);
    expect(screen.queryByText("Not available")).toBeNull();
  });

  it("phone list offers Challenge for the eligible row only", async () => {
    stub(true);
    vi.mocked(listSubmissions).mockResolvedValue(rowsWith([{ is_challengeable: true }]) as never);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    await screen.findByRole("link", { name: "101" });
    const items = screen.getAllByRole("listitem");
    expect(within(items[0]).getByRole("button", { name: "Challenge" })).toBeInTheDocument();
    expect(within(items[1]).queryByRole("button", { name: "Challenge" })).toBeNull();
    await userEvent.click(within(items[0]).getByRole("button", { name: "Challenge" }));
    expect(await screen.findByRole("button", { name: /confirm/i })).toBeInTheDocument();
  });

  it("artifact is one ellipsised line with the full value in title", async () => {
    const HASH = "b".repeat(64);
    vi.mocked(listSubmissions).mockResolvedValue(rowsWith([{ artifact: HASH }]) as never);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    const el = await screen.findByTitle(HASH);
    expect(getComputedStyle(el).textOverflow).toBe("ellipsis");
    expect(getComputedStyle(el).whiteSpace).toBe("nowrap");
    expect(getComputedStyle(el).minWidth).toBe("0px");
    expect(screen.getAllByRole("button", { name: "Copy artifact" })[0]).toBeInTheDocument();
  });

  it("mutes DONE while the SAFE verdict keeps its colour", async () => {
    vi.mocked(listSubmissions).mockResolvedValue(rowsWith([{ result: "SAFE" }]) as never);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    await screen.findByRole("table");
    const done = screen.getByText("DONE").closest(".MuiChip-root")!;
    const safe = screen.getByText(/^safe$/i).closest(".MuiChip-root")!;
    expect(getComputedStyle(done).color).not.toBe(getComputedStyle(safe).color);
    expect(getComputedStyle(done).backgroundColor).toBe("rgba(0, 0, 0, 0)");
  });

  it("filter toggle controls the collapse by id", async () => {
    vi.mocked(listSubmissions).mockResolvedValue(fixtureSubmissionsList as never);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    const btn = await screen.findByRole("button", { name: /^filters/i });
    await userEvent.click(btn);
    const id = btn.getAttribute("aria-controls")!;
    expect(id).toBeTruthy();
    expect(document.getElementById(id)).toContainElement(await screen.findByLabelText("Status"));
  });

  it("filtered empty state offers Clear filters, which resets", async () => {
    vi.mocked(listSubmissions).mockResolvedValue(fixtureSubmissionsList as never);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    await screen.findByRole("table");
    vi.mocked(listSubmissions).mockImplementation(async (p) =>
      (p?.search ? { ...fixtureSubmissionsList, count: 0, results: [] } : fixtureSubmissionsList) as never);
    await userEvent.type(screen.getByPlaceholderText(/id, status, artifact/i), "zzzz");
    expect(await screen.findByText("No submissions match")).toBeInTheDocument();
    expect(screen.getByText("Try a different search or clear the filters.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByRole("table")).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/id, status, artifact/i)).toHaveValue("");
  });

  it("empty account shows No submissions yet with a Submit action", async () => {
    vi.mocked(listSubmissions).mockResolvedValue({ ...fixtureSubmissionsList, count: 0, results: [] } as never);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions" });
    expect(await screen.findByText("No submissions yet")).toBeInTheDocument();
    expect(screen.getByText("Submit a file, URL or indicators to see them here.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Submit" })).toBeInTheDocument();
  });
});

describe("SubmissionsPage - honest detail drawer", () => {
  const row = (tests_done: number) => ({ ...fixtureSubmissionsList.results[0], tests_done });
  const report = (id: number) => ({
    id, cortex_job_id: null, type: "x", status: "Success", analyzer_name: `an${id}`, analyzer_id: `an${id}`,
    level: null, confidence: null, score: null, category: null, categories: [],
    report_summary: null, report_taxonomy: null, report_full: null,
    target: { kind: "mail", id: null, value: null }, created_at: "2026-05-17T10:00:00Z",
  });
  const open = async (tests_done: number, reports: unknown[]) => {
    stub(false);
    vi.mocked(getMe).mockResolvedValue(fixtureMe);
    vi.mocked(listSubmissions).mockResolvedValue({ ...fixtureSubmissionsList, results: [row(tests_done)] } as never);
    vi.mocked(getSubmissionDetails).mockResolvedValue({
      ...row(tests_done), analyzer_reports: reports,
      case_infos: {
        score: 0, confidence: 0, classification: "SAFE",
        score_ai: 0, confidence_ai: 0, classification_ai: "SUSPICIOUS", category_ai: "Uncategorized",
      },
    } as never);
    renderWithProviders(<SubmissionsPage />, { initialPath: "/submissions?open=101" });
    await screen.findByText("AI classifier");
  };

  it("labels sources, says no analyzers ran, shows the id once, drops the empty report block", async () => {
    await open(0, []);
    expect(screen.getByText("Verdict")).toBeInTheDocument();
    expect(screen.getByText("No analyzers ran for this submission.")).toBeInTheDocument();
    expect(screen.getAllByText("#101")).toHaveLength(1);
    expect(screen.queryByText(/^Analysis ·/)).not.toBeInTheDocument();
    expect(parseFloat(getComputedStyle(screen.getByText("conf 0%")).fontSize)).toBeGreaterThanOrEqual(12);
  });

  it("with analyses there is no 'no analyzers' line and reports are counted", async () => {
    await open(3, [report(1), report(2)]);
    expect(screen.queryByText(/No analyzers ran/)).not.toBeInTheDocument();
    expect(screen.getByText("Analysis · 2 reports")).toBeInTheDocument();
  });

  it("keeps the 0-reports block when tests ran", async () => {
    await open(3, []);
    expect(screen.queryByText(/No analyzers ran/)).not.toBeInTheDocument();
    expect(screen.getByText("Analysis · 0 reports")).toBeInTheDocument();
  });
});
