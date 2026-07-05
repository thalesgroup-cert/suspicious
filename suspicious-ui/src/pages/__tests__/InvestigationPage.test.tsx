import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
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
  buildSortOrdering: vi.fn((field: string, dir: string) => `${dir === "asc" ? "" : "-"}${field}`),
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
} from "@/features/investigation/api";
import InvestigationPage from "@/pages/InvestigationPage";

const mockGetMe = vi.mocked(getMe);
const mockGetAll = vi.mocked(getAllInvestigations);
const mockGetDetails = vi.mocked(getInvestigationDetails);

function renderInvestigation() {
  return renderWithProviders(<InvestigationPage />, { initialPath: "/investigation" });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("InvestigationPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetMe.mockResolvedValue({ ...mockMe, groups: ["CERT"] } as never);
    mockGetAll.mockResolvedValue(mockListResponse as never);
    mockGetDetails.mockResolvedValue(mockDetails as never);
  });

  it("renders the investigations table", async () => {
    renderInvestigation();

    await waitFor(() => {
      // Row artifact or reporter email should appear
      expect(
        screen.getByText(/phish\.evil\.com|reporter@corp/i)
      ).toBeInTheDocument();
    });
  });

  it("shows correct result chip for a suspicious case", async () => {
    renderInvestigation();

    // The uppercase chip label "SUSPICIOUS" disambiguates from prose text.
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

    // Click the investigation row
    const row = screen.getByText(/phish\.evil\.com|reporter@corp/i).closest("tr") ??
                 screen.getByText(/phish\.evil\.com|reporter@corp/i);
    await user.click(row);

    await waitFor(() => {
      // The details query should be triggered and the analyzer name should render
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

    await waitFor(() => {
      // PhishingURLAnalyzer name should appear in the drawer
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
      expect(screen.getByText(/PhishingURLAnalyzer/i)).toBeInTheDocument();
    });

    expect(screen.queryByText(/reporter's challenge/i)).not.toBeInTheDocument();
  });

  it("redirects non-elevated users away from the page", async () => {
    // Render without elevated groups — the component should show nothing / redirect
    mockGetMe.mockResolvedValue({ ...mockMe, groups: [] } as never);

    renderInvestigation();

    // The investigations table should never appear
    await waitFor(() => {
      expect(mockGetAll).not.toHaveBeenCalled();
    });
  });
});
