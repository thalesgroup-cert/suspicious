import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createTestQueryClient, renderWithProviders } from "@/test/utils";
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

  it("a case with no observable (UNKNOWN) reads Indicators; no tests segment without tests_done", async () => {
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
    const queryClient = createTestQueryClient();
    const { unmount } = renderWithProviders(<InvestigationDrawer {...props()} />, { queryClient });
    expect(screen.getByRole("button", { name: "Edit verdict" })).toBeEnabled();
    // Positive signal first: the connector query has resolved (to "none enabled"), so absence is meaningful.
    await waitFor(() => expect(queryClient.getQueryState(["enabledConnectors"])?.status).toBe("success"));
    expect(queryClient.getQueryData(["enabledConnectors"])).toEqual([]);
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
    const p = props({ detailsQuery: loaded(details(r)) });
    renderWithProviders(<InvestigationDrawer {...p} />);
    await userEvent.click(screen.getByRole("button", { name: "More actions" }));
    const item = screen.getByRole("menuitem", { name: /redo analysis/i });
    expect(item).toHaveAttribute("aria-disabled", "true");
    const reason = screen.getByText("Case is still being analyzed.");
    // The only explanation must stay readable: no inherited disabled opacity on the item or the line.
    expect(getComputedStyle(item).opacity).toBe("1");
    expect(getComputedStyle(reason).opacity).toBe("1");
    await userEvent.click(item, { pointerEventsCheck: 0 });
    expect(p.onRedo).not.toHaveBeenCalled();
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

  // Real shape: this endpoint types observable-group cases "IOC" (serializers/investigations.py get_case_type).
  const six = ["8.8.8.8", "www.google.com", "203.0.113.77", "a.example", "b.example", "c.example"]
    .map((value) => ({ value, type: "x", verdict: null, sources: [] }));

  it("an IOC-group case (type IOC) gets the Summary view with its observable count; meta keeps the raw type", () => {
    const r = { ...row, type: "IOC", tests_done: 49, info: "8.8.8.8, www.google.com, 203.0.113.77 +3 more" };
    renderWithProviders(<InvestigationDrawer {...props({ drawerRow: r as never, detailsQuery: loaded(details({ ...r, observable_group: { observables: six } })) })} />);
    expect(screen.getByRole("heading", { name: "Summary" })).toBeInTheDocument();
    expect(screen.getByText("6 observables")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Artifact" })).toBeNull();
    expect(within(screen.getByTestId("sheet-header")).getByText(/^Done · IOC · 49 tests · /)).toBeInTheDocument();
  });

  it("a case with no observable (UNKNOWN) keeps the Summary view without crashing", () => {
    const r = { ...row, type: "UNKNOWN", tests_done: 0, info: "" };
    renderWithProviders(<InvestigationDrawer {...props({ drawerRow: r as never, detailsQuery: loaded(details({ ...r, analyzer_reports: [] })) })} />);
    expect(screen.getByRole("heading", { name: "Summary" })).toBeInTheDocument();
    expect(screen.queryByText(/observables?$/)).toBeNull();
  });

  it("a URL case with several report groups keeps Artifact with copy", () => {
    const rep = (id: number, value: string) => ({ ...details().analyzer_reports[0], id, target: { kind: "URL", id: null, value } });
    renderWithProviders(<InvestigationDrawer {...props({ detailsQuery: loaded(details({ analyzer_reports: [rep(1, "a"), rep(2, "b"), rep(3, "c")] })) })} />);
    expect(screen.getByRole("heading", { name: "Artifact" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy artifact" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Summary" })).toBeNull();
  });

  it("IOC road: no analyst score, the threat badge instead", () => {
    const r = { ...row, type: "IOC", tests_done: 49, info: "6 indicators" };
    const d = details({
      ...r,
      observable_group: { observables: six },
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

describe("InvestigationDrawer - analysis tab", () => {
  const rep = (id: number, name: string, score: number, value: string, kind: string, status = "Success", confidence = 20) => ({
    id, cortex_job_id: `j${id}`, type: kind.toLowerCase(), status, analyzer_name: name, analyzer_id: name,
    level: "info", confidence, score, category: null, categories: [], target: { kind, id: null, value },
  });
  // Backend order URL, domain, hash: the tab must reorder by worst risk.
  const reports3 = [
    rep(1, "UrlLow", 1, "http://u.example", "URL"),
    rep(2, "DomFailed", 10, "d.example", "DOMAIN", "Failure"),
    rep(3, "DomLow", 2, "d.example", "DOMAIN"),
    rep(4, "HashHigh", 9, "aa11", "HASH", "Success", 90),
    rep(5, "HashLow", 1, "aa11", "HASH"),
  ];
  const three = (over: Partial<InvestigationDrawerProps> = {}, data: Record<string, unknown> = {}) =>
    props({ detailsQuery: loaded(details({ analyzer_reports: reports3, ...data })), ...over });
  const toAnalysis = async () => userEvent.click(await screen.findByRole("tab", { name: /^Analysis/ }));
  const groupItems = () => within(screen.getByRole("list", { name: "Observables" })).getAllByRole("listitem");
  const group = (value: string) => {
    const li = groupItems().find((g) => g.querySelector("[aria-controls]")?.textContent?.includes(value));
    if (!li) throw new Error(`no group ${value}`);
    return li;
  };
  const row = (name: string) => screen.getByRole("button", { name: new RegExp(`^${name}`) });

  it("a level-3 Analysis heading with the count as text; no count while loading or on error", async () => {
    const { rerender } = renderWithProviders(<InvestigationDrawer {...three()} />);
    await toAnalysis();
    expect(screen.getByRole("heading", { level: 3, name: "Analysis" })).toBeInTheDocument();
    expect(screen.getByText("5 reports")).toBeInTheDocument();
    rerender(<InvestigationDrawer {...three({ detailsQuery: { data: undefined, isLoading: true, isError: false, isFetching: true, isPlaceholderData: false } as never })} />);
    expect(screen.getByText("Loading analysis…")).toBeInTheDocument();
    expect(screen.queryByText(/reports?$/)).toBeNull();
    rerender(<InvestigationDrawer {...three({ detailsQuery: { data: undefined, isLoading: false, isError: true, isFetching: false, isPlaceholderData: false } as never })} />);
    expect(screen.getByText("Could not load analysis details.")).toBeInTheDocument();
    expect(screen.queryByText(/reports?$/)).toBeNull();
    rerender(<InvestigationDrawer {...three({}, { analyzer_reports: [] })} />);
    expect(screen.getByText("No analysis reports yet.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Expand all groups" })).toBeNull();
  });

  it("groups sorted by worst risk with a worst-risk dot; only the worst starts open", async () => {
    renderWithProviders(<InvestigationDrawer {...three()} />);
    await toAnalysis();
    const names = groupItems().map((g) => g.querySelector("[aria-controls]")?.textContent?.match(/aa11|d\.example|http:\/\/u\.example/)?.[0]);
    expect(names).toEqual(["aa11", "d.example", "http://u.example"]);
    expect(within(group("aa11")).getByRole("img", { name: "Worst result: High risk" })).toBeInTheDocument();
    expect(within(group("d.example")).getByRole("img", { name: "Worst result: Low risk" })).toBeInTheDocument();
    expect(within(group("aa11")).getByText("2 analyzers")).toBeInTheDocument();
    expect(within(group("aa11")).getByText("HashHigh")).toBeInTheDocument();
    expect(within(group("http://u.example")).queryByText("UrlLow")).toBeNull();
    expect(within(group("d.example")).queryByText("DomFailed")).toBeNull();
    // aria-controls targets exist.
    for (const el of document.querySelectorAll("[aria-controls]")) {
      expect(document.getElementById(el.getAttribute("aria-controls")!)).not.toBeNull();
    }
  });

  it("a failed analyzer reads Failed with no risk or confidence; its group says 1 failed", async () => {
    renderWithProviders(<InvestigationDrawer {...three()} />);
    await toAnalysis();
    expect(within(group("d.example")).getByText("1 failed")).toBeInTheDocument();
    expect(within(group("aa11")).queryByText(/failed/)).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Expand all groups" }));
    const failed = row("DomFailed");
    expect(within(failed).getByText("Failed")).toBeInTheDocument();
    expect(failed.textContent).not.toMatch(/Low risk|Low confidence|risk|confidence/i);
    expect(row("DomLow").textContent).toMatch(/Low risk/);
  });

  it("Expired, Running, Queued and Unknown are neutral and never counted as failed", async () => {
    const odd = [
      rep(1, "Ok", 2, "x.example", "DOMAIN"),
      rep(2, "Gone", 9, "x.example", "DOMAIN", "Deleted"),
      rep(3, "Busy", 0, "y.example", "DOMAIN", "InProgress"),
      rep(4, "Later", 0, "y.example", "DOMAIN", "Waiting"),
      rep(5, "Blank", 0, "y.example", "DOMAIN", ""),
    ];
    renderWithProviders(<InvestigationDrawer {...three({}, { analyzer_reports: odd })} />);
    await toAnalysis();
    // The Success keeps its risk as the worst; a purged job does not raise it.
    expect(within(group("x.example")).getByRole("img", { name: "Worst result: Low risk" })).toBeInTheDocument();
    expect(screen.queryByText(/failed/)).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Expand all groups" }));
    expect(within(row("Gone")).getByText("Expired")).toBeInTheDocument();
    expect(within(row("Busy")).getByText("Running")).toBeInTheDocument();
    expect(within(row("Later")).getByText("Queued")).toBeInTheDocument();
    expect(within(row("Blank")).getByText("Unknown")).toBeInTheDocument();
    await userEvent.click(row("Gone"));
    expect(await screen.findByText(/no longer available in Cortex/)).toBeInTheDocument();
  });

  it("confidence only after expanding a row", async () => {
    renderWithProviders(<InvestigationDrawer {...three()} />);
    await toAnalysis();
    expect(row("HashHigh").textContent).toMatch(/High risk/);
    expect(screen.queryByText(/High confidence/)).toBeNull();
    await userEvent.click(row("HashHigh"));
    expect(await screen.findByText(/High confidence/)).toBeInTheDocument();
    expect(row("HashHigh")).toHaveAttribute("aria-expanded", "true");
  });

  it("expand all and collapse all icon buttons", async () => {
    renderWithProviders(<InvestigationDrawer {...three()} />);
    await toAnalysis();
    await userEvent.click(screen.getByRole("button", { name: "Expand all groups" }));
    expect(await screen.findByText("UrlLow")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Collapse all groups" }));
    await waitFor(() => {
      expect(screen.queryByText("HashHigh")).toBeNull();
      expect(screen.queryByText("UrlLow")).toBeNull();
    });
  });

  it("another case and a reopen start from the default again", async () => {
    const { rerender } = renderWithProviders(<InvestigationDrawer {...three()} />);
    await toAnalysis();
    await userEvent.click(screen.getByRole("button", { name: "Expand all groups" }));
    expect(await screen.findByText("UrlLow")).toBeInTheDocument();
    const r8 = { ...row, id: 8 };
    rerender(<InvestigationDrawer {...three({ drawerRow: r8 as never, caseId: 8 }, { id: 8 })} />);
    await toAnalysis();
    expect(await screen.findByText("HashHigh")).toBeInTheDocument();
    expect(screen.queryByText("UrlLow")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Expand all groups" }));
    expect(await screen.findByText("UrlLow")).toBeInTheDocument();
    rerender(<InvestigationDrawer {...three({ drawerRow: r8 as never, caseId: 8, open: false }, { id: 8 })} />);
    await waitFor(() => expect(screen.queryByText("UrlLow")).toBeNull());
    rerender(<InvestigationDrawer {...three({ drawerRow: r8 as never, caseId: 8 }, { id: 8 })} />);
    if (!screen.queryByRole("tab", { name: /^Analysis/, selected: true })) await toAnalysis();
    expect(await screen.findByText("HashHigh")).toBeInTheDocument();
    expect(screen.queryByText("UrlLow")).toBeNull();
  });

  it("the IOC observable panel sits above the groups for an IOC case and is absent for a mail case", async () => {
    const obs = [{ value: "8.8.8.8", type: "ip", verdict: { band: "Safe", confidence: 80, rationale: [] }, sources: [] }];
    const r = { ...row, type: "IOC" };
    const { unmount } = renderWithProviders(<InvestigationDrawer {...three({ drawerRow: r as never }, { ...r, observable_group: { observables: obs } })} />);
    await toAnalysis();
    const panelText = screen.getByRole("tabpanel").textContent ?? "";
    expect(panelText).toMatch(/0 \/ 0 sources flagged this/);
    expect(panelText.indexOf("sources flagged")).toBeLessThan(panelText.indexOf("HashHigh"));
    unmount();
    const m = { ...row, type: "MAIL" };
    renderWithProviders(<InvestigationDrawer {...three({ drawerRow: m as never })} />);
    await toAnalysis();
    expect(screen.queryByText(/sources flagged this/)).toBeNull();
    expect(screen.getByRole("list", { name: "Observables" })).toBeInTheDocument();
  });
});

describe("InvestigationDrawer - discussion and raw tabs", () => {
  it("Discussion shows the thread with the count in the tab label", async () => {
    const comments = [{ id: 1, body: "Looks like a credential lure.", author_email: "elena@x.test", created_at: "2026-01-01T00:00:00Z" }];
    renderWithProviders(<InvestigationDrawer {...props({ commentsQuery: { data: comments, isLoading: false } as never })} />);
    await userEvent.click(screen.getByRole("tab", { name: "Discussion (1)" }));
    expect(screen.getByText("Looks like a credential lure.")).toBeInTheDocument();
  });

  it("Raw shows the payload in monospace without an accordion", async () => {
    renderWithProviders(<InvestigationDrawer {...props({ detailsQuery: loaded(details({ raw: { marker: "raw-marker-42" } })) })} />);
    await userEvent.click(screen.getByRole("tab", { name: "Raw" }));
    const pre = screen.getByText(/raw-marker-42/);
    expect(pre.tagName).toBe("PRE");
    expect(getComputedStyle(pre).fontFamily).toMatch(/mono/i);
    expect(within(screen.getByRole("tabpanel")).queryByRole("button")).toBeNull();
  });
});
