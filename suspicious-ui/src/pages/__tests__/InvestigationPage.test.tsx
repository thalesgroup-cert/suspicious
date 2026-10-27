import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { useLocation, useNavigate, useNavigationType } from "react-router";
import userEvent from "@testing-library/user-event";
import { renderWithProviders, mockMe } from "@/test/utils";

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock("@/api/auth", () => ({
  getMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  hydrateColorsAfterSso: vi.fn(),
  hydrateAppearanceFromMe: vi.fn(),
}));

vi.mock("@/features/investigation/api", () => ({
  getAllInvestigations: vi.fn(),
  getInvestigationDetails: vi.fn(),
  editGlobalCase: vi.fn(),
  redoAnalysis: vi.fn(),
  bulkSetVerdict: vi.fn(),
  bulkRedoAnalysis: vi.fn(),
  buildSortOrdering: vi.fn((field: string, dir: string) => `${dir === "asc" ? "" : "-"}${field}`),
}));

vi.mock("@/features/comments/api", () => ({
  getCaseComments: vi.fn(),
  addCaseComment: vi.fn(),
}));

vi.mock("@/features/submissions/api", () => ({
  pushSubmissionToTheHive: vi.fn(),
  challengeSubmission: vi.fn(),
}));

vi.mock("@/features/settings/components/connectors", () => ({
  getEnabledConnectors: vi.fn().mockResolvedValue([]),
}));

vi.mock("@/features/home/api", () => ({
  getHomeSummary: vi.fn().mockResolvedValue({ suggested_scopes: {} }),
  setCisoScope: vi.fn().mockResolvedValue({ scope: "EMEA" }),
}));

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const mockRow = {
  id: 7,
  reporter_email: "reporter@corp.test",
  status: "DONE",
  info: "Suspicious email with credential harvesting link",
  artifact: "http://phish.evil.com/login",
  created_at: "2026-04-01T10:00:00Z",
  tests_done: 3,
  type: "URL",
  result: "Suspicious",
  is_challengeable: false,
  is_challenged: false,
};

const mockListResponse = {
  count: 1,
  next: null,
  previous: null,
  results: [mockRow],
};

const mockDetailsChallenged = {
  ...mockRow,
  challenge_proposed_result: "Dangerous",
  challenge_reason: "phish",
  analyzer_reports: [],
  case_infos: {},
};

const mockDetails = {
  ...mockRow,
  analyzer_reports: [
    {
      id: 1,
      cortex_job_id: "cj-001",
      type: "url",
      status: "SUCCESS",
      analyzer_name: "PhishingURLAnalyzer",
      analyzer_id: "PhishingURLAnalyzer_1_0",
      level: "malicious",
      confidence: 0.95,
      score: 0.95,
      category: "Phishing",
      categories: ["Phishing"],
      report_summary: {},
      report_taxonomy: {},
      report_full: {},
      target: null,
    },
  ],
  case_infos: {
    score: 0.95,
    confidence: 0.95,
    classification: "Phishing",
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

import { getMe } from "@/api/auth";
import {
  getAllInvestigations,
  getInvestigationDetails,
  redoAnalysis,
  bulkSetVerdict,
  bulkRedoAnalysis,
} from "@/features/investigation/api";
import InvestigationPage from "@/pages/InvestigationPage";
import { editGlobalCase } from "@/features/investigation/api";
import { getCaseComments, addCaseComment } from "@/features/comments/api";
import { pushSubmissionToTheHive, challengeSubmission } from "@/features/submissions/api";
import { getEnabledConnectors } from "@/features/settings/components/connectors";

const mockPush = vi.mocked(pushSubmissionToTheHive);
const mockChallenge = vi.mocked(challengeSubmission);
const mockEnabledConnectors = vi.mocked(getEnabledConnectors);
const mockGetMe = vi.mocked(getMe);
const mockGetAll = vi.mocked(getAllInvestigations);
const mockGetDetails = vi.mocked(getInvestigationDetails);
const mockGetComments = vi.mocked(getCaseComments);
const mockAddComment = vi.mocked(addCaseComment);
const mockRedoAnalysis = vi.mocked(redoAnalysis);
const mockEdit = vi.mocked(editGlobalCase);
const mockBulkVerdict = vi.mocked(bulkSetVerdict);
const mockBulkRedo = vi.mocked(bulkRedoAnalysis);

async function openRow(user: ReturnType<typeof userEvent.setup>) {
  await user.click((await screen.findByText(mockRow.info)).closest("tr")!);
  await waitFor(() => expect(mockGetDetails).toHaveBeenCalledWith(7));
}

/** The raw payload (which names every analyzer) lives in the Raw tab. */
async function showRaw(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("tab", { name: "Raw" }));
}

async function openMore(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "More actions" }));
}

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

function Probe() {
  const nav = useNavigate();
  const loc = useLocation();
  const type = useNavigationType();
  return (
    <div>
      <span data-testid="loc">{loc.pathname + loc.search}</span>
      <span data-testid="navtype">{type}</span>
      <button onClick={() => nav("/investigation")}>probe-back</button>
    </div>
  );
}
const withProbe = () => <><InvestigationPage /><Probe /></>;

function renderInvestigation() {
  return renderWithProviders(<InvestigationPage />, { initialPath: "/investigation" });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("InvestigationPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stub(false);
    mockEnabledConnectors.mockResolvedValue([]);
    mockGetMe.mockResolvedValue({ ...mockMe, groups: ["CERT"] } as never);
    mockGetAll.mockResolvedValue(mockListResponse as never);
    mockGetDetails.mockResolvedValue(mockDetails as never);
    mockGetComments.mockResolvedValue([
      { id: 1, author_email: "reporter@corp.test", body: "please check", is_internal: false, created_at: "2026-07-09T10:00:00Z" },
    ]);
    mockAddComment.mockResolvedValue({
      id: 2, author_email: "analyst@corp.test", body: "looks clean", is_internal: true, created_at: "2026-07-09T11:00:00Z",
    });
  });

  describe("bulk edit", () => {
    it("selecting a row shows the bar, and a row click still opens the drawer only from the row", async () => {
      const user = userEvent.setup();
      renderInvestigation();
      await user.click(await screen.findByRole("checkbox", { name: "Select case 7" }));
      expect(await screen.findByText("1 selected")).toBeInTheDocument();
      expect(mockGetDetails).not.toHaveBeenCalled();
      await user.click(screen.getByRole("button", { name: "Clear" }));
      expect(screen.queryByText("1 selected")).not.toBeInTheDocument();
    });

    it("the header checkbox selects every case on the page", async () => {
      const user = userEvent.setup();
      renderInvestigation();
      await user.click(await screen.findByRole("checkbox", { name: "Select all cases on this page" }));
      expect(await screen.findByText("1 selected")).toBeInTheDocument();
    });

    it("Set verdict sends the selected ids and reports a skipped case", async () => {
      mockBulkVerdict.mockResolvedValue([{ case_id: 7, outcome: "failed", detail: "Investigation not found." }]);
      const user = userEvent.setup();
      renderInvestigation();
      await user.click(await screen.findByRole("checkbox", { name: "Select case 7" }));
      await user.click(await screen.findByRole("button", { name: "Set verdict…" }));
      await user.click(await screen.findByRole("button", { name: "Apply to 1 case" }));
      await waitFor(() => expect(mockBulkVerdict).toHaveBeenCalledWith([7], 9, 90, "DANGEROUS"));
      expect(await screen.findByText(/Case 7: Investigation not found\./)).toBeInTheDocument();
    });

    it("an out-of-range score blocks Apply", async () => {
      const user = userEvent.setup();
      renderInvestigation();
      await user.click(await screen.findByRole("checkbox", { name: "Select case 7" }));
      await user.click(await screen.findByRole("button", { name: "Set verdict…" }));
      const score = await screen.findByLabelText("Score (0-10)");
      await user.clear(score);
      await user.type(score, "11");
      expect(screen.getByRole("button", { name: "Apply to 1 case" })).toBeDisabled();
      expect(mockBulkVerdict).not.toHaveBeenCalled();
    });

    it("Redo analysis sends the selected ids", async () => {
      mockBulkRedo.mockResolvedValue([{ case_id: 7, outcome: "queued" }]);
      const user = userEvent.setup();
      renderInvestigation();
      await user.click(await screen.findByRole("checkbox", { name: "Select case 7" }));
      await user.click(await screen.findByRole("button", { name: "Redo analysis" }));
      await waitFor(() => expect(mockBulkRedo).toHaveBeenCalledWith([7]));
      expect(await screen.findByText(/1 queued for analysis/)).toBeInTheDocument();
    });

    it("changing the search clears the selection", async () => {
      const user = userEvent.setup();
      renderInvestigation();
      await user.click(await screen.findByRole("checkbox", { name: "Select case 7" }));
      expect(await screen.findByText("1 selected")).toBeInTheDocument();
      await user.type(screen.getByPlaceholderText(/id, user mail, status/i), "phish");
      await waitFor(() => expect(screen.queryByText("1 selected")).not.toBeInTheDocument());
    });

    it("a CISO gets no checkboxes and no bar", async () => {
      mockGetMe.mockResolvedValue({ ...mockMe, groups: ["CISO"], ciso_scope: "EMEA" } as never);
      renderInvestigation();
      await screen.findByText(mockRow.info);
      expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    });
  });

  it("renders the investigations table", async () => {
    renderInvestigation();

    await waitFor(() => {
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument();
    });
  });

  it("shows correct result chip for a suspicious case", async () => {
    renderInvestigation();

    await waitFor(() => {
      expect(screen.getByText("SUSPICIOUS")).toBeInTheDocument();
    });
  });

  it("opens the detail drawer when a row is clicked", async () => {
    const user = userEvent.setup();
    renderInvestigation();

    await waitFor(() => {
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument();
    });

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                 screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);

    await waitFor(() => {
      expect(mockGetDetails).toHaveBeenCalledWith(7);
    });
  });

  it("shows detail content once drawer data loads", async () => {
    const user = userEvent.setup();
    renderInvestigation();

    await waitFor(() =>
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument()
    );

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);
    await showRaw(user);

    await waitFor(() => {
      expect(screen.getByText(/PhishingURLAnalyzer/i)).toBeInTheDocument();
    });
  });

  it("shows the reporter's proposed verdict and reason for a challenged case", async () => {
    const user = userEvent.setup();
    mockGetDetails.mockResolvedValue(mockDetailsChallenged as never);
    renderInvestigation();

    await waitFor(() =>
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument()
    );

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);

    await waitFor(() => {
      expect(screen.getByText(/reporter's challenge/i)).toBeInTheDocument();
      expect(screen.getByText("Dangerous")).toBeInTheDocument();
      expect(screen.getByText(/reason: phish/i)).toBeInTheDocument();
    });
  });

  it("does not show stale details from the previous case while the next one loads", async () => {
    const user = userEvent.setup();
    const rowB = { ...mockRow, id: 8, info: "Other suspicious case", artifact: "http://other.evil.com/x" };
    mockGetAll.mockResolvedValue({
      count: 2, next: null, previous: null, results: [mockRow, rowB],
    } as never);

    let resolveSecond!: (value: unknown) => void;
    const secondDetailsPromise = new Promise((resolve) => { resolveSecond = resolve; });
    mockGetDetails.mockImplementation(((id: number) =>
      id === 7 ? Promise.resolve(mockDetails) : secondDetailsPromise) as never);

    renderInvestigation();

    await waitFor(() => expect(screen.getByText(mockRow.info)).toBeInTheDocument());
    await user.click(screen.getByText(mockRow.info).closest("tr")!);
    await showRaw(user);
    await waitFor(() => expect(screen.getByText(/PhishingURLAnalyzer/i)).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "Next case" }));
    expect(await screen.findByRole("heading", { level: 2, name: "#8" })).toBeInTheDocument();
    // The tab resets to Overview on a case change: go back to Raw, where #7's payload must not show under #8.
    await showRaw(user);
    expect(screen.queryByText(/PhishingURLAnalyzer/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit verdict" })).toBeDisabled();

    resolveSecond({ ...mockDetails, id: 8, analyzer_reports: [] });
    await waitFor(() => expect(screen.getByRole("button", { name: "Edit verdict" })).toBeEnabled());
    expect(screen.queryByText(/PhishingURLAnalyzer/i)).not.toBeInTheDocument();
  });

  it("while the next case loads, Edit verdict and Redo are off; then Edit seeds and saves that case's own values", async () => {
    const user = userEvent.setup();
    const rowB = { ...mockRow, id: 8, info: "Other suspicious case" };
    mockGetAll.mockResolvedValue({ count: 2, next: null, previous: null, results: [mockRow, rowB] } as never);
    let resolveSecond!: (value: unknown) => void;
    const second = new Promise((resolve) => { resolveSecond = resolve; });
    mockGetDetails.mockImplementation(((id: number) => (id === 7 ? Promise.resolve(mockDetails) : second)) as never);
    mockEdit.mockResolvedValue({} as never);

    renderInvestigation();
    await openRow(user);
    await waitFor(() => expect(screen.getByRole("button", { name: "Edit verdict" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Next case" }));
    expect(await screen.findByRole("heading", { level: 2, name: "#8" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit verdict" })).toBeDisabled();
    expect(screen.getByRole("tab", { name: "Analysis" })).toBeInTheDocument();
    await openMore(user);
    expect(screen.getByRole("menuitem", { name: /redo analysis/i })).toHaveAttribute("aria-disabled", "true");
    await user.keyboard("{Escape}");

    resolveSecond({ ...mockDetails, id: 8, case_infos: { score: 4, confidence: 40, classification: "Spam" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Edit verdict" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Edit verdict" }));
    expect(screen.getByLabelText("Score (0-10)")).toHaveValue(4);
    expect(screen.getByLabelText("Confidence (0-100)")).toHaveValue(40);
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mockEdit).toHaveBeenCalledWith(8, 4, 40, "SPAM"));
  });

  it("a screenshot error on one case does not carry over to the next", async () => {
    const user = userEvent.setup();
    const rowB = { ...mockRow, id: 8, info: "Other suspicious case" };
    // A valid 1x1 PNG for B; A's path does not exist, so its image errors.
    const png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
    mockGetAll.mockResolvedValue({ count: 2, next: null, previous: null, results: [mockRow, rowB] } as never);
    mockGetDetails.mockImplementation(((id: number) => Promise.resolve(
      id === 7 ? { ...mockDetails, screenshot_url: "/missing-shot.png" } : { ...mockDetails, id: 8, screenshot_url: png },
    )) as never);
    renderInvestigation();
    // Visit B first so its details are cached: the step back to B has no loading phase that would remount the panel.
    await user.click((await screen.findByText(rowB.info)).closest("tr")!);
    await screen.findByRole("img", { name: "Page screenshot" });
    await user.click(screen.getByRole("button", { name: "Previous case" }));
    expect(await screen.findByText("No screenshot available")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next case" }));
    expect(await screen.findByRole("heading", { level: 2, name: "#8" })).toBeInTheDocument();
    expect(screen.queryByText("No screenshot available")).toBeNull();
  });

  it("closing and reopening the same case lands on Overview", async () => {
    const user = userEvent.setup();
    renderInvestigation();
    await openRow(user);
    await showRaw(user);
    await user.click(screen.getAllByRole("button", { name: /close/i })[0]);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await openRow(user);
    expect(await screen.findByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  });

  it("shows a deny-list banner with reason for a deny-listed case", async () => {
    const user = userEvent.setup();
    mockGetDetails.mockResolvedValue({
      ...mockDetails,
      is_denylisted: true,
      is_allowlisted: false,
      list_reason: "Domain deny-listed: evil.example",
    } as never);
    renderInvestigation();

    await waitFor(() =>
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument()
    );

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        /this case matched the deny list\.\s*domain deny-listed: evil\.example/i
      );
    });
  });

  it("shows an allow-list banner for an allow-listed case", async () => {
    const user = userEvent.setup();
    mockGetDetails.mockResolvedValue({
      ...mockDetails,
      is_denylisted: false,
      is_allowlisted: true,
      list_reason: "Domain 'safe.example' is allow-listed.",
    } as never);
    renderInvestigation();

    await waitFor(() =>
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument()
    );

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/this case matched the allow list/i);
    });
  });

  it("does not show a challenge panel when the case has no proposed verdict", async () => {
    const user = userEvent.setup();
    renderInvestigation();

    await waitFor(() =>
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument()
    );

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);

    await waitFor(() => {
      expect(screen.getByText("Phishing")).toBeInTheDocument(); // the loaded classification
    });

    expect(screen.queryByText(/reporter's challenge/i)).not.toBeInTheDocument();
  });

  it("shows the reporter's note in the context panel when present", async () => {
    const user = userEvent.setup();
    mockGetDetails.mockResolvedValue({
      ...mockDetails,
      reporter_note: "forwarded phishing",
      reporter_context: "please check this url",
    } as never);
    renderInvestigation();

    await waitFor(() =>
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument()
    );

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);

    await waitFor(() => {
      expect(screen.getByText(/reporter's context/i)).toBeInTheDocument();
      expect(screen.getByText("forwarded phishing")).toBeInTheDocument();
    });
  });

  it("shows the reporter's context when there is no note", async () => {
    const user = userEvent.setup();
    mockGetDetails.mockResolvedValue({
      ...mockDetails,
      reporter_context: "please check this url",
    } as never);
    renderInvestigation();

    await waitFor(() =>
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument()
    );

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);

    await waitFor(() => {
      expect(screen.getByText("please check this url")).toBeInTheDocument();
    });
  });

  it("does not show a reporter's context panel when neither field is present", async () => {
    const user = userEvent.setup();
    renderInvestigation();

    await waitFor(() =>
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument()
    );

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);

    await waitFor(() => {
      expect(screen.getByText("Phishing")).toBeInTheDocument(); // the loaded classification
    });

    expect(screen.queryByText(/reporter's context/i)).not.toBeInTheDocument();
  });

  it("redirects non-elevated users away from the page", async () => {
    mockGetMe.mockResolvedValue({ ...mockMe, groups: [] } as never);

    renderInvestigation();

    await waitFor(() => {
      expect(mockGetAll).not.toHaveBeenCalled();
    });
  });

  it("prompts a scopeless CISO to set a scope instead of listing cases", async () => {
    mockGetMe.mockResolvedValue({ ...mockMe, groups: ["CISO"], ciso_scope: "" } as never);

    renderInvestigation();

    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: /select your management scope/i })
      ).toBeInTheDocument();
    });
    expect(mockGetAll).not.toHaveBeenCalled();
  });

  it("lists cases for a CISO who already has a scope", async () => {
    mockGetMe.mockResolvedValue({ ...mockMe, groups: ["CISO"], ciso_scope: "EMEA" } as never);

    renderInvestigation();

    await waitFor(() => expect(mockGetAll).toHaveBeenCalled());
  });

  it("tells a scoped CISO when nothing was submitted in their scope", async () => {
    mockGetMe.mockResolvedValue({ ...mockMe, groups: ["CISO"], ciso_scope: "RO" } as never);
    mockGetAll.mockResolvedValue({ results: [], count: 0 } as never);

    renderInvestigation();

    expect(
      await screen.findByText(/no submissions have been sent within your scope \(RO\)/i)
    ).toBeInTheDocument();
  });

  it("shows the comment thread and posts an analyst note", async () => {
    const user = userEvent.setup();
    renderInvestigation();

    await waitFor(() =>
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument()
    );

    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);
    await user.click(await screen.findByRole("tab", { name: "Discussion (1)" }));

    await waitFor(() => {
      expect(screen.getByText("please check")).toBeInTheDocument();
    });

    const textarea = screen.getByPlaceholderText("Add a comment…");
    await user.type(textarea, "looks clean");
    await user.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() =>
      expect(mockAddComment).toHaveBeenCalledWith(7, "looks clean")
    );
  });

  describe("Report + push to TheHive", () => {
    async function openDrawer(user: ReturnType<typeof userEvent.setup>) {
      renderInvestigation();
      await waitFor(() =>
        expect(screen.getByText(/phish\.evil\.com|reporter@corp/i)).toBeInTheDocument(),
      );
      const row =
        screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
        screen.getByText(/phish\.evil\.com|reporter@corp/i);
      await user.click(row);
      await waitFor(() => expect(mockGetDetails).toHaveBeenCalledWith(7));
    }

    it("opens the HTML report in a new tab", async () => {
      const user = userEvent.setup();
      const openSpy = vi.spyOn(window, "open").mockImplementation(() => null);
      await openDrawer(user);

      await openMore(user);
      await user.click(screen.getByRole("menuitem", { name: "Full report" }));
      expect(openSpy).toHaveBeenCalledWith("/api/cases/7/report/", "_blank");
      openSpy.mockRestore();
    });

    it("downloads the Markdown report", async () => {
      const user = userEvent.setup();
      const openSpy = vi.spyOn(window, "open").mockImplementation(() => null);
      await openDrawer(user);

      await openMore(user);
      await user.click(screen.getByRole("menuitem", { name: "Markdown report" }));
      expect(openSpy).toHaveBeenCalledWith("/api/cases/7/report.md", "_blank");
      openSpy.mockRestore();
    });

    it("hides the TheHive button when the connector is not enabled", async () => {
      const user = userEvent.setup();
      mockEnabledConnectors.mockResolvedValue([]);
      await openDrawer(user);
      expect(
        screen.queryByRole("button", { name: /push to thehive/i }),
      ).not.toBeInTheDocument();
    });

    it("pushes to TheHive and reports the result", async () => {
      const user = userEvent.setup();
      mockEnabledConnectors.mockResolvedValue(["thehive"]);
      mockPush.mockResolvedValue({
        status: "created",
        alert_id: "~1",
        alert_url: "https://hive/alerts/~1/details",
      });
      await openDrawer(user);

      const btn = await screen.findByRole("button", { name: /push to thehive/i });
      await user.click(btn);

      await waitFor(() => expect(mockPush).toHaveBeenCalledWith(7));
      expect(await screen.findByText("Created an alert in TheHive for #7.")).toBeInTheDocument();
    });

    it("reports a failed push with the server's message, or a generic one", async () => {
      const user = userEvent.setup();
      mockEnabledConnectors.mockResolvedValue(["thehive"]);
      mockPush.mockRejectedValueOnce({ response: { data: { detail: "TheHive is unreachable." } } });
      mockPush.mockRejectedValueOnce(new Error("boom"));
      await openDrawer(user);

      const btn = await screen.findByRole("button", { name: /push to thehive/i });
      await waitFor(() => expect(btn).toBeEnabled());
      await user.click(btn);
      expect(await screen.findByText("TheHive is unreachable.")).toBeInTheDocument();
      await waitFor(() => expect(btn).toBeEnabled());
      await user.click(btn);
      expect(await screen.findByText("Push to TheHive failed.")).toBeInTheDocument();
    });
  });

  describe("Redo analysis", () => {
    it("is disabled while the case is not terminal", async () => {
      const user = userEvent.setup();
      mockGetDetails.mockResolvedValue({ ...mockDetails, status: "IN_PROGRESS" } as never);
      renderInvestigation();

      await waitFor(() =>
        expect(screen.getByText(/phish\.evil\.com|reporter@corp/i)).toBeInTheDocument()
      );
      const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                  screen.getByText(/phish\.evil\.com|reporter@corp/i);
      await user.click(row);

      await waitFor(() => expect(screen.getByText("Phishing")).toBeInTheDocument());
      await openMore(user);
      expect(screen.getByRole("menuitem", { name: /redo analysis/i })).toHaveAttribute("aria-disabled", "true");
    });

    it("opens a confirmation dialog before calling the API", async () => {
      const user = userEvent.setup();
      renderInvestigation(); // mockDetails.status is "DONE" (terminal) by default

      await waitFor(() =>
        expect(screen.getByText(/phish\.evil\.com|reporter@corp/i)).toBeInTheDocument()
      );
      const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                  screen.getByText(/phish\.evil\.com|reporter@corp/i);
      await user.click(row);

      await waitFor(() => expect(screen.getByText("Phishing")).toBeInTheDocument());
      await openMore(user);
      await user.click(screen.getByRole("menuitem", { name: "Redo analysis" }));

      await waitFor(() => {
        expect(screen.getByText("Redo analysis?")).toBeInTheDocument();
      });
      expect(mockRedoAnalysis).not.toHaveBeenCalled();
    });

    it("calls redoAnalysis and refetches details on confirm", async () => {
      const user = userEvent.setup();
      mockRedoAnalysis.mockResolvedValue({ status: "queued", dispatched: 1 });
      renderInvestigation();

      await waitFor(() =>
        expect(screen.getByText(/phish\.evil\.com|reporter@corp/i)).toBeInTheDocument()
      );
      const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                  screen.getByText(/phish\.evil\.com|reporter@corp/i);
      await user.click(row);

      await waitFor(() => expect(screen.getByText("Phishing")).toBeInTheDocument());
      await openMore(user);
      await user.click(screen.getByRole("menuitem", { name: "Redo analysis" }));
      await waitFor(() => expect(screen.getByText("Redo analysis?")).toBeInTheDocument());

      const dialog = screen.getByRole("dialog");
      await user.click(within(dialog).getByRole("button", { name: /redo analysis/i }));

      await waitFor(() => {
        expect(mockRedoAnalysis).toHaveBeenCalledWith(7);
      });
      await waitFor(() => {
        expect(mockGetDetails).toHaveBeenCalledTimes(2); // initial load + post-redo refetch
      });
    });

    it("shows the server's error message on a 409", async () => {
      const user = userEvent.setup();
      mockRedoAnalysis.mockRejectedValue({
        response: { status: 409, data: { detail: "Case is still being analyzed." } },
      });
      renderInvestigation();

      await waitFor(() =>
        expect(screen.getByText(/phish\.evil\.com|reporter@corp/i)).toBeInTheDocument()
      );
      const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                  screen.getByText(/phish\.evil\.com|reporter@corp/i);
      await user.click(row);

      await waitFor(() => expect(screen.getByText("Phishing")).toBeInTheDocument());
      await openMore(user);
      await user.click(screen.getByRole("menuitem", { name: "Redo analysis" }));
      await waitFor(() => expect(screen.getByText("Redo analysis?")).toBeInTheDocument());

      const dialog = screen.getByRole("dialog");
      await user.click(within(dialog).getByRole("button", { name: /redo analysis/i }));

      await waitFor(() => {
        expect(screen.getByText("Case is still being analyzed.")).toBeInTheDocument();
      });
    });
  });
  describe("Redo analysis dialog", () => {
    it("Cancel closes it without calling the API", async () => {
      const user = userEvent.setup();
      renderInvestigation();
      await openRow(user);
      await waitFor(() => expect(screen.getByText("Phishing")).toBeInTheDocument());
      await openMore(user);
      await user.click(screen.getByRole("menuitem", { name: "Redo analysis" }));
      const dialog = await screen.findByRole("dialog", { name: "Redo analysis?" });
      await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
      await waitFor(() => expect(screen.queryByText("Redo analysis?")).not.toBeInTheDocument());
      expect(mockRedoAnalysis).not.toHaveBeenCalled();
    });
  });

  describe("Verdict override", () => {
    async function startEdit(user: ReturnType<typeof userEvent.setup>) {
      renderInvestigation();
      await openRow(user);
      await waitFor(() => expect(screen.getByText("Phishing")).toBeInTheDocument());
      await user.click(screen.getByRole("button", { name: "Edit verdict" }));
    }

    it("Edit verdict opens the override form on Overview with the current values, focused", async () => {
      const user = userEvent.setup();
      renderInvestigation();
      await openRow(user);
      await user.click(await screen.findByRole("tab", { name: "Raw" }));
      await waitFor(() => expect(screen.getByRole("button", { name: "Edit verdict" })).toBeEnabled());
      await user.click(screen.getByRole("button", { name: "Edit verdict" }));
      expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
      expect(screen.getByRole("heading", { name: "Verdict override" })).toBeInTheDocument();
      const score = screen.getByLabelText("Score (0-10)");
      expect(score).toHaveValue(0.95);
      expect(screen.getByLabelText("Confidence (0-100)")).toHaveValue(0.95);
      await waitFor(() => expect(score).toHaveFocus());
    });

    it("Save sends the same payload as before and leaves edit mode", async () => {
      const user = userEvent.setup();
      mockEdit.mockResolvedValue({} as never);
      await startEdit(user);
      const score = screen.getByLabelText("Score (0-10)");
      await user.clear(score);
      await user.type(score, "8");
      const conf = screen.getByLabelText("Confidence (0-100)");
      await user.clear(conf);
      await user.type(conf, "90");
      await user.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(mockEdit).toHaveBeenCalledWith(7, 8, 90, "PHISHING"));
      await waitFor(() => expect(screen.queryByRole("heading", { name: "Verdict override" })).not.toBeInTheDocument());
    });

    it("out-of-range score or confidence keeps Save disabled", async () => {
      const user = userEvent.setup();
      await startEdit(user);
      const score = screen.getByLabelText("Score (0-10)");
      await user.clear(score);
      await user.type(score, "11");
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
      expect(screen.getByText("Score must be between 0 and 10.")).toBeInTheDocument();
      await user.clear(score);
      await user.type(score, "5");
      const conf = screen.getByLabelText("Confidence (0-100)");
      await user.clear(conf);
      await user.type(conf, "101");
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
      expect(screen.getByText("Confidence must be between 0 and 100.")).toBeInTheDocument();
      expect(mockEdit).not.toHaveBeenCalled();
    });

    it("Edit verdict while already editing puts focus back on Score", async () => {
      const user = userEvent.setup();
      await startEdit(user);
      await user.click(screen.getByLabelText("Confidence (0-100)"));
      expect(screen.getByLabelText("Score (0-10)")).not.toHaveFocus();
      await user.click(screen.getByRole("button", { name: "Edit verdict" }));
      await waitFor(() => expect(screen.getByLabelText("Score (0-10)")).toHaveFocus());
    });

    it("Cancel leaves edit mode and restores the saved values", async () => {
      const user = userEvent.setup();
      await startEdit(user);
      const score = screen.getByLabelText("Score (0-10)");
      await user.clear(score);
      await user.type(score, "3");
      await user.click(screen.getByRole("button", { name: "Cancel" }));
      expect(screen.queryByRole("heading", { name: "Verdict override" })).not.toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: "Edit verdict" }));
      expect(screen.getByLabelText("Score (0-10)")).toHaveValue(0.95);
    });
  });

  it("previous/next move between the rows of the current page", async () => {
    const user = userEvent.setup();
    const rowB = { ...mockRow, id: 8, info: "Other suspicious case" };
    mockGetAll.mockResolvedValue({ count: 2, next: null, previous: null, results: [mockRow, rowB] } as never);
    renderInvestigation();
    await openRow(user);
    expect(screen.getByRole("button", { name: "Previous case" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Next case" }));
    await waitFor(() => expect(mockGetDetails).toHaveBeenCalledWith(8));
    expect(screen.getByRole("heading", { level: 2, name: "#8" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next case" })).toBeDisabled();
  });

  it("a deep-linked case that is not on the page has no previous/next", async () => {
    mockGetDetails.mockResolvedValue({ ...mockDetails, id: 99 } as never);
    renderWithProviders(<InvestigationPage />, { initialPath: "/investigation?open=99" });
    expect(await screen.findByRole("heading", { level: 2, name: "#99" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous case" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next case" })).toBeDisabled();
  });

  describe("list: filters, pager, header", () => {
    // Server-side paging: the mock answers the page asked for, with the server total.
    const pageOf = (count: number) => async (p: { page: number; pageSize: number; search?: string }) => {
      const n = Math.max(0, Math.min(p.pageSize, count - p.page * p.pageSize));
      return {
        count, next: null, previous: null,
        results: Array.from({ length: n }, (_, i) => ({
          ...mockRow, id: 1000 + p.page * p.pageSize + i, info: `case-${p.page * p.pageSize + i}`,
        })),
      };
    };
    beforeEach(() => { mockGetAll.mockImplementation(pageOf(340) as never); });
    const filtersBtn = () => screen.findByRole("button", { name: /^filters/i });
    const search = () => screen.getByPlaceholderText(/id, user mail/i);

    it("collapses everything but search behind a Filters button that controls the collapse", async () => {
      renderInvestigation();
      const btn = await filtersBtn();
      expect(search()).toBeInTheDocument();
      expect(btn).toHaveAttribute("aria-expanded", "false");
      expect(screen.queryByLabelText("Status")).toBeNull();
      await userEvent.click(btn);
      expect(btn).toHaveAttribute("aria-expanded", "true");
      for (const l of ["Status", "Type", "Result", "From", "To", "Sort"]) {
        expect(await screen.findByLabelText(l)).toBeInTheDocument();
      }
      expect(document.getElementById(btn.getAttribute("aria-controls")!)).toContainElement(screen.getByLabelText("Status"));
    });

    it("counts active filters on the button; Reset appears and clears everything", async () => {
      renderInvestigation();
      const btn = await filtersBtn();
      expect(screen.queryByRole("button", { name: /reset/i })).toBeNull();
      await userEvent.click(btn);
      await userEvent.click(await screen.findByLabelText("Status"));
      await userEvent.click(await screen.findByRole("option", { name: "DONE" }));
      expect(screen.getByRole("button", { name: /^filters/i })).toHaveTextContent(/^Filters1$/);
      await userEvent.type(search(), "abc");
      await userEvent.click(await screen.findByRole("button", { name: /reset/i }));
      await waitFor(() => expect(screen.queryByRole("button", { name: /reset/i })).toBeNull());
      expect(screen.getByRole("button", { name: /^filters/i })).toHaveTextContent(/^Filters$/);
      expect(search()).toHaveValue("");
    });

    it("header chip reads the server total, then match when searching; no avatar", async () => {
      mockGetAll.mockImplementation((async (p: { page: number; pageSize: number; search?: string }) =>
        pageOf(p.search ? 12 : 340)(p)) as never);
      renderInvestigation();
      expect(await screen.findByText("340 total")).toBeInTheDocument();
      expect(document.querySelector(".MuiAvatar-root")).toBeNull();
      await userEvent.type(search(), "row");
      expect(await screen.findByText("12 match")).toBeInTheDocument();
      expect(screen.queryByText(/^Search:/)).toBeNull();
    });

    it("while a new search loads, the chip shows no number instead of the old count as match", async () => {
      mockGetAll.mockImplementation(((p: { page: number; pageSize: number; search?: string }) =>
        p.search ? new Promise(() => {}) : pageOf(340)(p)) as never);
      renderInvestigation();
      expect(await screen.findByText("340 total")).toBeInTheDocument();
      await userEvent.type(search(), "row");
      expect(await screen.findByText("…")).toBeInTheDocument();
      expect(screen.queryByText(/match/)).toBeNull();
    });

    it("a filter also says match; changing only the sort keeps total", async () => {
      renderInvestigation();
      await userEvent.click(await filtersBtn());
      await userEvent.click(await screen.findByLabelText("Sort"));
      await userEvent.click(await screen.findByRole("option", { name: "ID (high → low)" }));
      expect(await screen.findByText("340 total")).toBeInTheDocument();
      expect(screen.queryByText(/match/)).toBeNull();
      await userEvent.click(screen.getByLabelText("Type"));
      await userEvent.click(await screen.findByRole("option", { name: "MAIL" }));
      expect(await screen.findByText("340 match")).toBeInTheDocument();
    });

    it("pager sits below the table with 10/25/50 and x-y of N", async () => {
      renderInvestigation();
      const table = await screen.findByRole("table");
      const label = await screen.findByText("1–10 of 340");
      const pager = label.closest(".MuiTablePagination-root") as HTMLElement;
      expect(table.compareDocumentPosition(pager) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      expect(table.contains(pager)).toBe(false);
      expect(screen.queryByRole("button", { name: /^prev$/i })).toBeNull();
      await userEvent.click(within(pager).getByRole("combobox"));
      expect((await screen.findAllByRole("option")).map((o) => o.textContent)).toEqual(["10", "25", "50"]);
    });

    it("next page asks the server for page 2; a filter change returns to page 1", async () => {
      renderInvestigation();
      await screen.findByText("1–10 of 340");
      await userEvent.click(screen.getByRole("button", { name: /next page/i }));
      expect(await screen.findByText("11–20 of 340")).toBeInTheDocument();
      expect(mockGetAll).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1, pageSize: 10 }));
      await userEvent.click(await filtersBtn());
      await userEvent.click(await screen.findByLabelText("Type"));
      await userEvent.click(await screen.findByRole("option", { name: "MAIL" }));
      expect(await screen.findByText("1–10 of 340")).toBeInTheDocument();
      expect(mockGetAll).toHaveBeenLastCalledWith(expect.objectContaining({ page: 0, type: "MAIL" }));
    });

    it("changing rows per page shows 25 rows from page 1", async () => {
      renderInvestigation();
      await screen.findByText("1–10 of 340");
      await userEvent.click(screen.getByRole("button", { name: /next page/i }));
      const pager = (await screen.findByText("11–20 of 340")).closest(".MuiTablePagination-root") as HTMLElement;
      await userEvent.click(within(pager).getByRole("combobox"));
      await userEvent.click(await screen.findByRole("option", { name: "25" }));
      expect(await screen.findByText("1–25 of 340")).toBeInTheDocument();
      expect(mockGetAll).toHaveBeenLastCalledWith(expect.objectContaining({ page: 0, pageSize: 25 }));
      expect(screen.getAllByRole("row")).toHaveLength(26);
    });

    it("no cases at all: No cases yet, no action, no pager", async () => {
      mockGetAll.mockImplementation(pageOf(0) as never);
      renderInvestigation();
      expect(await screen.findByText("No cases yet")).toBeInTheDocument();
      expect(screen.getByText("Submitted cases appear here.")).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
      expect(document.querySelector(".MuiTablePagination-root")).toBeNull();
    });

    it("a search with no match offers Clear filters, which resets", async () => {
      mockGetAll.mockImplementation((async (p: { page: number; pageSize: number; search?: string }) =>
        pageOf(p.search ? 0 : 340)(p)) as never);
      renderInvestigation();
      await screen.findByRole("table");
      await userEvent.type(search(), "zzzz");
      expect(await screen.findByText("No cases match")).toBeInTheDocument();
      expect(screen.getByText("Try a different search or clear the filters.")).toBeInTheDocument();
      expect(document.querySelector(".MuiTablePagination-root")).toBeNull();
      await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));
      expect(await screen.findByRole("table")).toBeInTheDocument();
      expect(search()).toHaveValue("");
    });
  });

  describe("list: rows", () => {
    it("desktop: a lighter outlined ID chip with copy, DONE muted while the verdict keeps its colour", async () => {
      renderInvestigation();
      await screen.findByRole("table");
      const id = screen.getByRole("button", { name: "7" });
      expect(id.className).toMatch(/MuiButton-outlined/);
      expect(screen.getByRole("button", { name: "Copy ID" })).toBeInTheDocument();
      const done = screen.getByText("DONE").closest(".MuiChip-root")!;
      const verdict = screen.getByText("SUSPICIOUS").closest(".MuiChip-root")!;
      expect(getComputedStyle(done).backgroundColor).toBe("rgba(0, 0, 0, 0)");
      expect(getComputedStyle(done).color).not.toBe(getComputedStyle(verdict).color);
    });

    it("artifact is one ellipsised line with the full value in title; mail keeps its copy", async () => {
      const LONG = "x".repeat(200);
      mockGetAll.mockResolvedValue({ ...mockListResponse, results: [{ ...mockRow, info: LONG }] } as never);
      renderInvestigation();
      const el = await screen.findByTitle(LONG);
      expect(getComputedStyle(el).textOverflow).toBe("ellipsis");
      expect(getComputedStyle(el).whiteSpace).toBe("nowrap");
      expect(getComputedStyle(el).minWidth).toBe("0px");
      expect(screen.getByText("reporter@corp.test")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Copy email" })).toBeInTheDocument();
    });

    it("phone: a stacked list with the ID link, verdict and reporter mail; no table", async () => {
      stub(true);
      renderInvestigation();
      const link = await screen.findByRole("link", { name: "7" });
      expect(link).toHaveAttribute("href", "/investigation?open=7");
      const item = screen.getAllByRole("listitem")[0];
      expect(within(item).getByText("SUSPICIOUS")).toBeInTheDocument();
      expect(within(item).getByText("reporter@corp.test")).toBeInTheDocument();
      expect(screen.queryByRole("table")).toBeNull();
    });

    it("Enter on a row's copy button copies; the drawer stays closed", async () => {
      const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
      const user = userEvent.setup();
      renderInvestigation();
      await screen.findByRole("table");
      screen.getByRole("button", { name: "Copy ID" }).focus();
      await user.keyboard("{Enter}");
      await waitFor(() => expect(write).toHaveBeenCalledWith("7"));
      expect(screen.queryByRole("dialog")).toBeNull();
      write.mockRestore();
    });

    it("keyboard: Enter on a row opens the dialog named by its h2 with focus inside; Close returns focus to the row", async () => {
      const user = userEvent.setup();
      renderInvestigation();
      const row = (await screen.findByText(mockRow.info)).closest("tr")!;
      row.focus();
      await user.keyboard("{Enter}");
      const dialog = await screen.findByRole("dialog", { name: "#7" });
      await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
      await user.click(within(dialog).getByRole("button", { name: "Close" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      expect(document.activeElement).toBe(row);
    });
  });

  describe("list: drawer and URL", () => {
    const three = { count: 3, next: null, previous: null, results: [7, 8, 9].map((id) => ({ ...mockRow, id, info: `case-${id}` })) };
    const close = () => userEvent.click(screen.getAllByRole("button", { name: /close/i })[0]);
    const drawerHeading = (id: number) => screen.queryByRole("heading", { level: 2, name: `#${id}` });

    it("phone link replaces history; closing drops ?open= so the same link reopens", async () => {
      stub(true);
      renderWithProviders(withProbe(), { initialPath: "/investigation" });
      await userEvent.click(await screen.findByRole("link", { name: "7" }));
      expect(await screen.findByRole("heading", { level: 2, name: "#7" })).toBeInTheDocument();
      expect(screen.getByTestId("navtype")).toHaveTextContent("REPLACE");
      await close();
      await waitFor(() => expect(drawerHeading(7)).toBeNull());
      expect(screen.getByTestId("loc")).toHaveTextContent(/^\/investigation$/);
      await userEvent.click(screen.getByRole("link", { name: "7" }));
      expect(await screen.findByRole("heading", { level: 2, name: "#7" })).toBeInTheDocument();
    });

    it("the URL losing ?open= (Back) closes the drawer", async () => {
      renderWithProviders(withProbe(), { initialPath: "/investigation?open=7" });
      expect(await screen.findByRole("heading", { level: 2, name: "#7" })).toBeInTheDocument();
      screen.getByText("probe-back").click(); // behind the modal, so not reachable by role
      await waitFor(() => expect(drawerHeading(7)).toBeNull());
    });

    it("desktop row click opens and closes without touching the URL", async () => {
      renderWithProviders(withProbe(), { initialPath: "/investigation" });
      await openRow(userEvent.setup());
      expect(await screen.findByRole("heading", { level: 2, name: "#7" })).toBeInTheDocument();
      expect(screen.getByTestId("loc")).toHaveTextContent(/^\/investigation$/);
      await close();
      await waitFor(() => expect(drawerHeading(7)).toBeNull());
      expect(screen.getByTestId("loc")).toHaveTextContent(/^\/investigation$/);
    });

    it("the middle row has both neighbours; Next replaces ?open=, and closing then drops it", async () => {
      mockGetAll.mockResolvedValue(three as never);
      mockGetDetails.mockReturnValue(new Promise(() => {}));
      renderWithProviders(withProbe(), { initialPath: "/investigation?open=8" });
      expect(await screen.findByRole("heading", { level: 2, name: "#8" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Previous case" })).toBeEnabled();
      expect(screen.getByRole("button", { name: "Next case" })).toBeEnabled();
      await userEvent.click(screen.getByRole("button", { name: "Next case" }));
      await waitFor(() => expect(screen.getByTestId("loc")).toHaveTextContent("/investigation?open=9"));
      expect(screen.getByTestId("navtype")).toHaveTextContent("REPLACE");
      expect(await screen.findByRole("heading", { level: 2, name: "#9" })).toBeInTheDocument();
      await close();
      await waitFor(() => expect(drawerHeading(9)).toBeNull());
      expect(screen.getByTestId("loc")).toHaveTextContent(/^\/investigation$/);
    });
  });

  describe("CISO: challenge for a user in scope, no case edits", () => {
    const challengeable = { ...mockRow, is_challengeable: true, is_challenged: false };

    function asRole(groups: string[], row: Record<string, unknown> = challengeable) {
      mockGetMe.mockResolvedValue({ ...mockMe, groups, ciso_scope: "EMEA" } as never);
      mockGetAll.mockResolvedValue({ ...mockListResponse, results: [row] } as never);
      mockGetDetails.mockResolvedValue({ ...mockDetails, ...row } as never);
    }

    async function open() {
      const user = userEvent.setup();
      renderInvestigation();
      await openRow(user);
      await waitFor(() => expect(screen.getByText("Phishing")).toBeInTheDocument());
      return user;
    }

    it("a CISO can challenge but is not offered Edit verdict", async () => {
      asRole(["CISO"]);
      await open();
      expect(screen.getByRole("button", { name: "Challenge verdict" })).toBeEnabled();
      expect(screen.queryByRole("button", { name: "Edit verdict" })).toBeNull();
    });

    it("CERT edits but is not offered Challenge verdict (the API only lets the reporter or a CISO)", async () => {
      asRole(["CERT"]);
      await open();
      expect(screen.getByRole("button", { name: "Edit verdict" })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Challenge verdict" })).toBeNull();
    });

    it("a user who is both CISO and CERT gets both", async () => {
      asRole(["CISO", "CERT"]);
      await open();
      expect(screen.getByRole("button", { name: "Edit verdict" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Challenge verdict" })).toBeInTheDocument();
    });

    it("no Challenge verdict once the case is challenged, or when it cannot be", async () => {
      for (const row of [
        { ...challengeable, is_challenged: true },
        { ...challengeable, is_challengeable: false },
      ]) {
        asRole(["CISO"], row);
        const { unmount } = renderInvestigation();
        const user = userEvent.setup();
        await openRow(user);
        await waitFor(() => expect(screen.getByText("Phishing")).toBeInTheDocument());
        expect(screen.queryByRole("button", { name: "Challenge verdict" })).toBeNull();
        unmount();
        vi.clearAllMocks();
      }
    });

    it("sends the challenge for that case and refreshes it", async () => {
      asRole(["CISO"]);
      mockChallenge.mockResolvedValue({ detail: "Challenge submitted." } as never);
      const user = await open();
      const detailsCalls = mockGetDetails.mock.calls.length;

      await user.click(screen.getByRole("button", { name: "Challenge verdict" }));
      expect(screen.getByRole("dialog", { name: /challenge/i })).toHaveTextContent("#7");
      await user.click(screen.getByRole("button", { name: "Dangerous" }));
      await user.type(screen.getByLabelText(/why is the verdict wrong/i), "reported by a user in my scope");
      await user.click(screen.getByRole("button", { name: "Confirm" }));

      await waitFor(() => expect(mockChallenge).toHaveBeenCalledWith(7, {
        proposed_result: "Dangerous", reason: "reported by a user in my scope",
      }));
      await waitFor(() => expect(screen.queryByRole("dialog", { name: /challenge/i })).toBeNull());
      expect(await screen.findByText(/challenge (was )?submitted|challenged/i)).toBeInTheDocument();
      await waitFor(() => expect(mockGetDetails.mock.calls.length).toBeGreaterThan(detailsCalls));
    });

    it("keeps the dialog open and says so when the API refuses", async () => {
      asRole(["CISO"]);
      mockChallenge.mockRejectedValue(new Error("nope"));
      const user = await open();
      await user.click(screen.getByRole("button", { name: "Challenge verdict" }));
      await user.click(screen.getByRole("button", { name: "Safe" }));
      await user.type(screen.getByLabelText(/why is the verdict wrong/i), "a long enough reason");
      await user.click(screen.getByRole("button", { name: "Confirm" }));
      expect(await screen.findByRole("alert")).toHaveTextContent(/failed to challenge/i);
      expect(screen.getByRole("dialog", { name: /challenge/i })).toBeInTheDocument();
    });
  });
});
