import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { InvestigationDrawer, type InvestigationDrawerProps } from "../InvestigationDrawer";

vi.mock("@/features/settings/components/connectors", () => ({
  getEnabledConnectors: vi.fn().mockResolvedValue([]),
}));
vi.mock("@/features/submissions/api", () => ({
  pushSubmissionToTheHive: vi.fn(),
}));

import { getEnabledConnectors } from "@/features/settings/components/connectors";
const mockEnabled = vi.mocked(getEnabledConnectors);

const idle = { isPending: false, isError: false, mutate: vi.fn(), mutateAsync: vi.fn(), reset: vi.fn() };

const row = {
  id: 7, status: "DONE", type: "URL", result: "SUSPICIOUS", tests_done: 3,
  info: "http://phish.example/login", reporter_email: "reporter@corp.test", created_at: "2026-01-01T00:00:00Z",
};

const explanation = {
  band: "SUSPICIOUS", confidence: 70, decisive_rule: "r1",
  analyst_paragraph: "Two reputation sources flagged the URL.",
  reporter_paragraph: "x", confidence_reading: "Moderate confidence.",
  sources: [{ name: "VirusTotal", tier: 1, verdict: "malicious", counted: true, note: "" }],
};

const details = (over: Record<string, unknown> = {}) => ({
  ...row,
  analyzer_reports: [
    { id: 1, cortex_job_id: "c", type: "url", status: "Success", analyzer_name: "UrlScan", analyzer_id: "u",
      level: "suspicious", confidence: 0.8, score: 6, category: null, categories: [], target: { kind: "URL", id: null, value: row.info } },
  ],
  case_infos: { score: 6, confidence: 70, classification: "SUSPICIOUS", score_ai: 0, confidence_ai: 0, classification_ai: "SAFE", verdict_explanation: explanation },
  is_allowlisted: false, is_denylisted: false, list_reason: "",
  ...over,
});

const loaded = (d: Record<string, unknown>) =>
  ({ data: d, isLoading: false, isError: false, isFetching: false, isPlaceholderData: false, dataUpdatedAt: 1 }) as never;

function props(over: Partial<InvestigationDrawerProps> = {}): InvestigationDrawerProps {
  return {
    open: true,
    onClose: vi.fn(),
    drawerRow: row as never,
    caseId: 7,
    detailsQuery: loaded(details()),
    editMutation: idle as never,
    editMode: false,
    setEditMode: vi.fn(),
    editScore: "",
    setEditScore: vi.fn(),
    editConfidence: "",
    setEditConfidence: vi.fn(),
    editClassification: "UNKNOWN",
    setEditClassification: vi.fn(),
    onRedo: vi.fn(),
    commentsQuery: { data: [], isLoading: false } as never,
    addCommentMutation: idle as never,
    expandedGroups: {},
    setExpandedGroups: vi.fn(),
    expandedAnalyzerIds: {},
    setExpandedAnalyzerIds: vi.fn(),
    ...over,
  };
}

const headings = () => screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);

describe("InvestigationDrawer", () => {
  beforeEach(() => { mockEnabled.mockResolvedValue([]); });

  it("shows the empty state without a row", () => {
    renderWithProviders(<InvestigationDrawer {...props({ drawerRow: undefined })} />);
    expect(screen.getByText("Select a row.")).toBeInTheDocument();
  });

  it("calls onClose from Close", async () => {
    const p = props();
    renderWithProviders(<InvestigationDrawer {...p} />);
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(p.onClose).toHaveBeenCalled();
  });
});

describe("InvestigationDrawer - header band", () => {
  it("ID once as the h2, one verdict chip, a quiet meta line", async () => {
    renderWithProviders(<InvestigationDrawer {...props()} />);
    const header = await screen.findByTestId("sheet-header");
    expect(screen.getAllByText("#7")).toHaveLength(1);
    expect(within(header).getByRole("heading", { level: 2, name: "#7" })).toBeInTheDocument();
    expect(within(header).getAllByText("SUSPICIOUS")).toHaveLength(1);
    expect(within(header).getByText(/^Done · URL · 3 tests · /)).toBeInTheDocument();
    expect(screen.getByTestId("verdict-accent")).toBeInTheDocument();
    // The old strip and chips row are gone.
    expect(screen.queryByText("Tests run")).toBeNull();
    expect(screen.queryByText("3 tests")).toBeNull();
  });

  it("an IOC group reads Indicators; no tests segment without tests_done", async () => {
    const r = { ...row, type: "UNKNOWN", tests_done: null };
    renderWithProviders(<InvestigationDrawer {...props({ drawerRow: r as never, detailsQuery: loaded(details(r)) })} />);
    const header = await screen.findByTestId("sheet-header");
    expect(within(header).getByText(/^Done · Indicators · Jan/)).toBeInTheDocument();
  });

  it("tabs with counts, linked to their panel, reset to Overview for another case", async () => {
    const { rerender } = renderWithProviders(<InvestigationDrawer {...props({ commentsQuery: { data: [{ id: 1 }, { id: 2 }], isLoading: false } as never })} />);
    expect(screen.getByRole("tablist", { name: "Investigation sections" })).toBeInTheDocument();
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual(["Overview", "Analysis (1)", "Discussion (2)", "Raw"]);
    const overview = screen.getByRole("tab", { name: "Overview" });
    const panel = screen.getByRole("tabpanel");
    expect(overview).toHaveAttribute("aria-controls", panel.id);
    expect(panel).toHaveAttribute("aria-labelledby", overview.id);
    await userEvent.click(screen.getByRole("tab", { name: "Raw" }));
    expect(screen.getByRole("tab", { name: "Raw" })).toHaveAttribute("aria-selected", "true");
    const r8 = { ...row, id: 8 };
    rerender(<InvestigationDrawer {...props({ drawerRow: r8 as never, caseId: 8, detailsQuery: loaded(details(r8)) })} />);
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  });

  it("tab labels carry no count while unknown", () => {
    renderWithProviders(<InvestigationDrawer {...props({
      detailsQuery: { data: undefined, isLoading: true, isError: false, isFetching: true, isPlaceholderData: false } as never,
      commentsQuery: { data: undefined, isLoading: true } as never,
    })} />);
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual(["Overview", "Analysis", "Discussion", "Raw"]);
  });

  it("previous and next are disabled off the page and navigate within it", async () => {
    const onNavigate = vi.fn();
    const { rerender } = renderWithProviders(<InvestigationDrawer {...props({ siblings: [9, 8], onNavigate })} />);
    expect(screen.getByRole("button", { name: "Previous case" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next case" })).toBeDisabled();
    rerender(<InvestigationDrawer {...props({ siblings: [9, 7, 6], onNavigate })} />);
    await userEvent.click(screen.getByRole("button", { name: "Previous case" }));
    expect(onNavigate).toHaveBeenLastCalledWith(9);
    await userEvent.click(screen.getByRole("button", { name: "Next case" }));
    expect(onNavigate).toHaveBeenLastCalledWith(6);
  });
});

describe("InvestigationDrawer - actions", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("Edit verdict is primary; Push to TheHive only when the connector is enabled", async () => {
    const { unmount } = renderWithProviders(<InvestigationDrawer {...props()} />);
    expect(screen.getByRole("button", { name: "Edit verdict" })).toBeEnabled();
    await waitFor(() => expect(mockEnabled).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /push to thehive/i })).toBeNull();
    unmount();
    mockEnabled.mockResolvedValue(["thehive"]);
    renderWithProviders(<InvestigationDrawer {...props()} />);
    expect(await screen.findByRole("button", { name: /push to thehive/i })).toBeInTheDocument();
  });

  it("More holds Full report, Markdown report, Copy link and Redo analysis", async () => {
    const open = vi.spyOn(window, "open").mockImplementation(() => null);
    const p = props();
    renderWithProviders(<InvestigationDrawer {...p} />);
    await userEvent.click(screen.getByRole("button", { name: "More actions" }));
    expect(screen.getAllByRole("menuitem").map((m) => m.textContent)).toEqual(
      ["Full report", "Markdown report", "Copy link", "Redo analysis"],
    );
    await userEvent.click(screen.getByRole("menuitem", { name: "Full report" }));
    expect(open).toHaveBeenLastCalledWith("/api/cases/7/report/", "_blank");
    await userEvent.click(screen.getByRole("button", { name: "More actions" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "Markdown report" }));
    expect(open).toHaveBeenLastCalledWith("/api/cases/7/report.md", "_blank");
    await userEvent.click(screen.getByRole("button", { name: "More actions" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "Redo analysis" }));
    expect(p.onRedo).toHaveBeenCalledTimes(1);
    open.mockRestore();
  });

  it("Redo analysis is disabled while the case is not terminal", async () => {
    const r = { ...row, status: "IN_PROGRESS" };
    renderWithProviders(<InvestigationDrawer {...props({ detailsQuery: loaded(details(r)) })} />);
    await userEvent.click(screen.getByRole("button", { name: "More actions" }));
    expect(screen.getByRole("menuitem", { name: /redo analysis/i })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("Case is still being analyzed.")).toBeInTheDocument();
  });

  it("Copy link writes the investigation URL and says so", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
    renderWithProviders(<InvestigationDrawer {...props()} />);
    await userEvent.click(screen.getByRole("button", { name: "More actions" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "Copy link" }));
    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/investigation?open=7`);
    expect(await screen.findByText("Link copied")).toBeInTheDocument();
  });

  it("Copy link says so when the write fails", async () => {
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    renderWithProviders(<InvestigationDrawer {...props()} />);
    await userEvent.click(screen.getByRole("button", { name: "More actions" }));
    await userEvent.click(screen.getByRole("menuitem", { name: "Copy link" }));
    expect(await screen.findByText("Could not copy the link. Copy it from the address bar.")).toBeInTheDocument();
  });
});

describe("InvestigationDrawer - overview", () => {
  it("banners first, then verdict, explanation, AI, reporter, artifact", () => {
    const d = details({
      is_denylisted: true, list_reason: "Domain deny-listed.",
      analysis_health: { total: 3, failed: 1, pending: 0, failures: [{ analyzer: "Shodan", target: "x", status: "Failure" }] },
      challenge_proposed_result: "Dangerous", reporter_context: "please check",
    });
    renderWithProviders(<InvestigationDrawer {...props({ detailsQuery: loaded(d) })} />);
    const panel = screen.getByRole("tabpanel");
    const text = panel.textContent ?? "";
    expect(text.indexOf("deny list")).toBeLessThan(text.indexOf("analyzers failed"));
    expect(text.indexOf("analyzers failed")).toBeLessThan(text.indexOf("Verdict"));
    expect(headings()).toEqual([
      "Verdict", "Why this verdict", "AI classifier", "Reporter's challenge", "Reporter's context", "Artifact", "Reported by",
    ]);
  });

  it("shows the real explanation text with its source breakdown", async () => {
    renderWithProviders(<InvestigationDrawer {...props()} />);
    expect(screen.getByText("Two reputation sources flagged the URL.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show source breakdown" }));
    expect(screen.getByText("VirusTotal")).toBeInTheDocument();
  });

  it("score and confidence stats; AI with score 0 and confidence 0 reads Not classified", () => {
    renderWithProviders(<InvestigationDrawer {...props()} />);
    expect(screen.getByText("6/10")).toBeInTheDocument();
    expect(screen.getByText("70%")).toBeInTheDocument();
    expect(screen.getByText("Not classified")).toBeInTheDocument();
  });

  it("AI with a score keeps its chips", () => {
    const d = details({ case_infos: { ...details().case_infos, score_ai: 7, confidence_ai: 80 } });
    renderWithProviders(<InvestigationDrawer {...props({ detailsQuery: loaded(d) })} />);
    expect(screen.getByText("score 7")).toBeInTheDocument();
    expect(screen.getByText("conf 80%")).toBeInTheDocument();
    expect(screen.queryByText("Not classified")).toBeNull();
  });

  it("nothing ran: stats show a dash and no bar", () => {
    const r = { ...row, tests_done: 0 };
    const d = details({ ...r, analyzer_reports: [], case_infos: { score: 0, confidence: 0, classification: "SAFE" } });
    renderWithProviders(<InvestigationDrawer {...props({ drawerRow: r as never, detailsQuery: loaded(d) })} />);
    expect(screen.getAllByText("—")).toHaveLength(2);
    expect(screen.queryByText("0/10")).toBeNull();
    expect(screen.queryByText("0%")).toBeNull();
    expect(screen.queryByRole("progressbar")).toBeNull();
    expect(screen.getByText("No analyzers ran for this submission.")).toBeInTheDocument();
  });

  it("IOC road: no analyst score, the threat badge instead", () => {
    const r = { ...row, type: "UNKNOWN", tests_done: 49, info: "6 indicators" };
    const d = details({
      ...r,
      observable_group: { observables: [], summary: {} },
      threat_classification: { label: "trojan.emotet", category: "malware", source: "virustotal" },
    });
    renderWithProviders(<InvestigationDrawer {...props({ drawerRow: r as never, detailsQuery: loaded(d) })} />);
    expect(screen.queryByText("6/10")).toBeNull();
    expect(screen.queryByText("Score")).toBeNull();
    expect(screen.getByText("trojan.emotet")).toBeInTheDocument();
    expect(screen.getByText("70%")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Summary" })).toBeInTheDocument();
  });

  it("artifact and reporter have copy buttons; screenshot only when captured", () => {
    const { unmount } = renderWithProviders(<InvestigationDrawer {...props()} />);
    expect(screen.getByRole("button", { name: "Copy artifact" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy email" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Page screenshot" })).toBeNull();
    unmount();
    renderWithProviders(<InvestigationDrawer {...props({ detailsQuery: loaded(details({ screenshot_url: "/s.png" })) })} />);
    expect(headings().at(-1)).toBe("Page screenshot");
  });

  it("the override panel sits after the reporter's context and before the artifact", () => {
    const d = details({ challenge_proposed_result: "Safe", reporter_note: "n" });
    renderWithProviders(<InvestigationDrawer {...props({ detailsQuery: loaded(d), editMode: true, editScore: "6", editConfidence: "70", editClassification: "SUSPICIOUS" })} />);
    const h = headings();
    expect(h.indexOf("Verdict override")).toBe(h.indexOf("Reporter's context") + 1);
    expect(h.indexOf("Artifact")).toBe(h.indexOf("Verdict override") + 1);
  });
});
