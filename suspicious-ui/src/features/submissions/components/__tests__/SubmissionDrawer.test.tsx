import { afterEach, describe, it, expect, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/utils";
import { SubmissionDrawer, type SubmissionDrawerProps } from "../SubmissionDrawer";
import { useColorStore } from "@/styles/colorStore";

const row = {
  id: 18, status: "DONE", artifact: "http://x.example", created_at: "2026-09-21T10:00:00Z",
  tests_done: 3, type: "URL", result: "Dangerous",
} as never;

const base = (over: Partial<SubmissionDrawerProps> = {}): SubmissionDrawerProps => ({
  open: true,
  onClose: vi.fn(),
  row,
  submissionId: 18,
  details: { data: undefined, isLoading: false, isError: false } as never,
  comments: { data: [], isLoading: false } as never,
  onAddComment: vi.fn().mockResolvedValue(undefined),
  isAddingComment: false,
  ...over,
});

const rep = (id: number, analyzer_name: string, score: number, value = "a.example", kind = "DOMAIN", status = "Success", confidence: number | null = null) => ({
  id, cortex_job_id: null, type: "x", status, analyzer_name, analyzer_id: analyzer_name,
  level: null, confidence, score, category: null, categories: [],
  report_summary: null, report_taxonomy: null, report_full: null,
  target: { kind, id: null, value }, created_at: "2026-09-21T10:00:00Z",
});

const SUMMARY = "40/49 analyzers succeeded. Consider rerunning the rest for a complete analysis.";
const GROUPS = ["g1.example", "g2.example", "g3.example", "g4.example", "g5.example", "g6.example"];
// 49 reports across 6 groups: four risky ones, one failed high scorer, the rest low.
const reports49 = [
  rep(1, "LowOne", 2, GROUPS[0]),
  rep(2, "HighTen", 10, GROUPS[1]),
  rep(3, "MediumSix", 6, GROUPS[2]),
  rep(4, "HighNine", 9, GROUPS[3]),
  rep(5, "FailedTen", 10, GROUPS[4], "DOMAIN", "Failure"),
  rep(6, "MediumFiveFive", 5.5, GROUPS[5]),
  ...Array.from({ length: 43 }, (_, i) => rep(10 + i, `Low${i}`, 1, GROUPS[i % 6])),
];
const ci = (over = {}) => ({
  score: 9, confidence: 60, classification: "DANGEROUS",
  score_ai: 0, confidence_ai: 0, classification_ai: "SUSPICIOUS", category_ai: "Uncategorized", ...over,
});
const multiRow = { id: 18, status: "DONE", artifact: SUMMARY, created_at: "2026-09-21T10:00:00Z", tests_done: 49, type: "UNKNOWN", result: "DANGEROUS" };
const multi = (over: Partial<SubmissionDrawerProps> = {}, ciOver = {}) =>
  base({
    row: multiRow as never,
    details: { data: { ...multiRow, analyzer_reports: reports49, case_infos: ci(ciOver) }, isLoading: false, isError: false } as never,
    ...over,
  });

describe("SubmissionDrawer", () => {
  it("shows the id and calls onClose from Close", async () => {
    const props = base();
    renderWithProviders(<SubmissionDrawer {...props} />);
    expect(await screen.findByText("#18")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(props.onClose).toHaveBeenCalled();
  });

  it("asks for a row when none is selected", async () => {
    renderWithProviders(<SubmissionDrawer {...base({ row: undefined })} />);
    expect(await screen.findByText("Select a row.")).toBeInTheDocument();
  });
});

describe("SubmissionDrawer - header band", () => {
  it("ID once, one verdict chip, a meta line with Indicators and no UNKNOWN", async () => {
    renderWithProviders(<SubmissionDrawer {...multi()} />);
    const header = await screen.findByTestId("sheet-header");
    expect(screen.getAllByText("#18")).toHaveLength(1);
    expect(within(header).getByRole("heading", { level: 2, name: "#18" })).toBeInTheDocument();
    expect(within(header).getAllByText("DANGEROUS")).toHaveLength(1);
    expect(within(header).queryByText(/unknown/i)).toBeNull();
    expect(within(header).getByText(/^Done · Indicators · 49 tests · /)).toBeInTheDocument();
  });

  it("an email with several report groups stays an Email, not Indicators", async () => {
    const mailRow = { ...multiRow, type: "MAIL", artifact: "Invoice overdue" };
    renderWithProviders(<SubmissionDrawer {...base({
      row: mailRow as never,
      details: { data: { ...mailRow, analyzer_reports: [rep(1, "A", 1, "x"), rep(2, "B", 1, "y")], case_infos: ci() }, isLoading: false, isError: false } as never,
    })} />);
    const header = await screen.findByTestId("sheet-header");
    expect(within(header).getByText(/^Done · Email · 49 tests · /)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Summary" })).toBeNull();
  });

  it("tabs: Overview selected, counts in labels, panels linked by aria", async () => {
    renderWithProviders(<SubmissionDrawer {...multi()} />);
    expect(await screen.findByRole("tablist", { name: "Submission sections" })).toBeInTheDocument();
    const overview = screen.getByRole("tab", { name: "Overview" });
    expect(overview).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "Analysis (49)" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Comments (0)" })).toBeInTheDocument();
    const panel = screen.getByRole("tabpanel");
    expect(overview).toHaveAttribute("aria-controls", panel.id);
    expect(panel).toHaveAttribute("aria-labelledby", overview.id);
  });

  it("labels the tabs without counts while unknown", async () => {
    renderWithProviders(<SubmissionDrawer {...base({ comments: { data: undefined, isLoading: true } as never })} />);
    expect(await screen.findByRole("tab", { name: "Analysis" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Comments" })).toBeInTheDocument();
  });

  it("opening another submission resets to Overview", async () => {
    const { rerender } = renderWithProviders(<SubmissionDrawer {...multi()} />);
    await userEvent.click(await screen.findByRole("tab", { name: "Analysis (49)" }));
    expect(screen.getByRole("tab", { name: "Analysis (49)" })).toHaveAttribute("aria-selected", "true");
    rerender(<SubmissionDrawer {...base({ row: { ...multiRow, id: 22 } as never, submissionId: 22 })} />);
    expect(await screen.findByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  });
});

describe("SubmissionDrawer - overview", () => {
  it("score and confidence stat blocks", async () => {
    renderWithProviders(<SubmissionDrawer {...multi()} />);
    expect(await screen.findByText("9/10")).toBeInTheDocument();
    expect(screen.getByText("60%")).toBeInTheDocument();
  });

  it("why this verdict: top three by risk, failed skipped, links to Analysis", async () => {
    renderWithProviders(<SubmissionDrawer {...multi()} />);
    const section = (await screen.findByRole("heading", { name: "Why this verdict" })).closest("section")!;
    const items = within(section).getAllByRole("listitem");
    expect(items.map((li) => li.textContent)).toEqual([
      expect.stringContaining("HighTen"), expect.stringContaining("HighNine"), expect.stringContaining("MediumSix"),
    ]);
    expect(within(section).queryByText("FailedTen")).toBeNull();
    expect(within(items[0]).getByText("High risk")).toBeInTheDocument();
    await userEvent.click(within(section).getByRole("button", { name: "See all 49 in Analysis" }));
    expect(screen.getByRole("tab", { name: "Analysis (49)" })).toHaveAttribute("aria-selected", "true");
  });

  it("why this verdict is absent with no reports or only low risk", async () => {
    const { rerender } = renderWithProviders(<SubmissionDrawer {...multi({
      details: { data: { ...multiRow, analyzer_reports: [], case_infos: ci() }, isLoading: false, isError: false } as never,
    })} />);
    await screen.findByText("9/10");
    expect(screen.queryByText("Why this verdict")).toBeNull();
    rerender(<SubmissionDrawer {...multi({
      details: { data: { ...multiRow, analyzer_reports: [rep(1, "A", 1), rep(2, "B", 3)], case_infos: ci() }, isLoading: false, isError: false } as never,
    })} />);
    await screen.findByText("9/10");
    expect(screen.queryByText("Why this verdict")).toBeNull();
  });

  it("AI classifier with score 0 and confidence 0 reads Not classified", async () => {
    renderWithProviders(<SubmissionDrawer {...multi()} />);
    expect(await screen.findByText("Not classified")).toBeInTheDocument();
    expect(screen.queryByText("conf 0%")).toBeNull();
  });

  it("AI classifier with a score keeps its chips", async () => {
    renderWithProviders(<SubmissionDrawer {...multi({}, { score_ai: 7, confidence_ai: 80 })} />);
    expect(await screen.findByText("score 7")).toBeInTheDocument();
    expect(screen.getByText("conf 80%")).toBeInTheDocument();
    expect(screen.queryByText("Not classified")).toBeNull();
  });

  it("multi-observable: Summary with the sentence and the observable count", async () => {
    renderWithProviders(<SubmissionDrawer {...multi()} />);
    expect(await screen.findByRole("heading", { name: "Summary" })).toBeInTheDocument();
    expect(screen.getByText(SUMMARY)).toBeInTheDocument();
    expect(screen.getByText("6 observables")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Artifact" })).toBeNull();
  });

  it("single observable: monospace artifact with a copy button", async () => {
    renderWithProviders(<SubmissionDrawer {...base({
      details: { data: { ...(row as object), analyzer_reports: [rep(1, "A", 1, "http://x.example", "URL")], case_infos: ci() }, isLoading: false, isError: false } as never,
    })} />);
    expect(await screen.findByRole("heading", { name: "Artifact" })).toBeInTheDocument();
    expect(getComputedStyle(screen.getByText("http://x.example", { selector: "p" })).fontFamily).toContain("IBM Plex Mono");
    expect(screen.getByRole("button", { name: "Copy artifact" })).toBeInTheDocument();
  });
});

describe("SubmissionDrawer - fix round 1", () => {
  afterEach(() => useColorStore.getState().reset());

  const single = (type: string, artifact: string, groups: [string, string][]) => {
    const r = { ...multiRow, type, artifact };
    return base({
      row: r as never,
      details: { data: { ...r, analyzer_reports: groups.map(([kind, value], i) => rep(i + 1, `A${i}`, 1, value, kind)), case_infos: ci() }, isLoading: false, isError: false } as never,
    });
  };

  it.each([
    ["URL", "URL", "http://u.example/x", [["URL", "http://u.example/x"], ["DOMAIN", "u.example"]]],
    ["FILE", "File", "sample.exe", [["FILE", "sample.exe"], ["HASH", "abc123"]]],
  ] as const)("a %s case with two report groups keeps its type, Artifact title and copy", async (type, label, artifact, groups) => {
    renderWithProviders(<SubmissionDrawer {...single(type, artifact, groups as never)} />);
    const header = await screen.findByTestId("sheet-header");
    expect(within(header).getByText(new RegExp(`^Done · ${label} · 49 tests · `))).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Artifact" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy artifact" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Summary" })).toBeNull();
  });

  it("nothing ran: stats show a dash, no 0/10 or 0% anywhere", async () => {
    const r = { ...multiRow, type: "URL", tests_done: 0 };
    renderWithProviders(<SubmissionDrawer {...base({
      row: r as never,
      details: { data: { ...r, analyzer_reports: [], case_infos: ci({ score: 0, confidence: 0 }) }, isLoading: false, isError: false } as never,
    })} />);
    expect(await screen.findByText("No analyzers ran for this submission.")).toBeInTheDocument();
    expect(screen.getAllByText("—")).toHaveLength(2);
    expect(screen.queryByText(/0\/10/)).toBeNull();
    expect(screen.queryByText(/(^|\s)0%/)).toBeNull();
    expect(screen.queryByRole("progressbar")).toBeNull();
  });

  it("Sources is plain text: classification label, no score or confidence chips", async () => {
    renderWithProviders(<SubmissionDrawer {...multi()} />);
    const section = (await screen.findByRole("heading", { name: "Sources" })).closest("section")!;
    expect(within(section).getByText("Dangerous")).toBeInTheDocument();
    expect(within(section).queryByText(/Score|Confidence/)).toBeNull();
    expect(section.querySelector(".MuiChip-root")).toBeNull();
  });

  it("no observables line while details load; no tests segment when tests_done is missing", async () => {
    const r = { ...multiRow, tests_done: undefined };
    renderWithProviders(<SubmissionDrawer {...base({ row: r as never, details: { data: undefined, isLoading: true, isError: false } as never })} />);
    const header = await screen.findByTestId("sheet-header");
    expect(within(header).getByText(/^Done · Indicators · [A-Z]/)).toBeInTheDocument();
    expect(within(header).queryByText(/tests?/)).toBeNull();
    expect(screen.queryByText(/observables?$/)).toBeNull();
  });

  it("accent line and stat bars use the user's verdict colour", async () => {
    useColorStore.getState().setResultColor("dangerous", "#123456");
    renderWithProviders(<SubmissionDrawer {...multi()} />);
    const accent = await screen.findByTestId("verdict-accent");
    expect(getComputedStyle(accent).backgroundColor).toBe("rgb(18, 52, 86)");
    const bar = screen.getByRole("progressbar", { name: "Score" }).querySelector(".MuiLinearProgress-bar")!;
    expect(getComputedStyle(bar).backgroundColor).toBe("rgb(18, 52, 86)");
  });
});

describe("SubmissionDrawer - analysis tab", () => {
  // Backend order URL, domain, hash: the tab must reorder by worst risk.
  const reports3 = [
    rep(1, "UrlLow", 1, "http://u.example", "URL"),
    rep(2, "DomFailed", 10, "d.example", "DOMAIN", "Failure"),
    rep(3, "DomLow", 2, "d.example", "DOMAIN"),
    rep(4, "HashHigh", 9, "aa11", "HASH", "Success", 90),
    rep(5, "HashLow", 1, "aa11", "HASH"),
  ];
  const urls = [{ id: 1, address: "http://u.example/x", analysis_status: "analyzed", interestingness: 1, canonical_key: "k", analyzed_url_id: null }];
  const three = (over: Partial<SubmissionDrawerProps> = {}, data: object = {}) =>
    base({
      row: multiRow as never,
      details: { data: { ...multiRow, analyzer_reports: reports3, case_infos: ci(), url_artifacts: urls, ...data }, isLoading: false, isError: false } as never,
      ...over,
    });
  const toAnalysis = async () => userEvent.click(await screen.findByRole("tab", { name: /^Analysis/ }));
  // One list item per observable group; the header button's text carries its name (no landmark per group).
  const groupItems = () => within(screen.getByRole("list", { name: "Observables" })).getAllByRole("listitem");
  const region = (name: string) => {
    const li = groupItems().find((g) => g.querySelector("[aria-controls]")?.textContent?.includes(name.split(" ").slice(1).join(" ")));
    if (!li) throw new Error(`no group ${name}`);
    return li;
  };
  const row = (name: string) => screen.getByRole("button", { name: new RegExp(`^${name}`) });

  it("a level-3 Analysis heading with the count as text", async () => {
    renderWithProviders(<SubmissionDrawer {...three()} />);
    await toAnalysis();
    expect(screen.getByRole("heading", { level: 3, name: "Analysis" })).toBeInTheDocument();
    expect(screen.getByText("5 reports")).toBeInTheDocument();
  });

  it("groups sorted by worst risk; a failed analyzer neither raises nor lowers it", async () => {
    renderWithProviders(<SubmissionDrawer {...three()} />);
    await toAnalysis();
    const names = groupItems().map((g) => g.querySelector("[aria-controls]")?.textContent);
    expect(names.map((n) => n?.match(/aa11|d\.example|http:\/\/u\.example/)?.[0])).toEqual(["aa11", "d.example", "http://u.example"]);
    expect(screen.queryAllByRole("region").filter((r) => r.getAttribute("aria-label"))).toHaveLength(0);
    expect(within(region("Hash aa11")).getByRole("img", { name: "Worst result: High risk" })).toBeInTheDocument();
    expect(within(region("Domain d.example")).getByRole("img", { name: "Worst result: Low risk" })).toBeInTheDocument();
  });

  it("only the worst group starts open", async () => {
    renderWithProviders(<SubmissionDrawer {...three()} />);
    await toAnalysis();
    expect(within(region("Hash aa11")).getByText("HashHigh")).toBeInTheDocument();
    expect(within(region("URL http://u.example")).queryByText("UrlLow")).not.toBeInTheDocument();
    expect(within(region("Domain d.example")).queryByText("DomFailed")).not.toBeInTheDocument();
  });

  it("a failed analyzer reads Failed, no risk or confidence; its group says 1 failed", async () => {
    renderWithProviders(<SubmissionDrawer {...three()} />);
    await toAnalysis();
    expect(within(region("Domain d.example")).getByText("1 failed")).toBeInTheDocument();
    expect(within(region("Hash aa11")).queryByText(/failed/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Expand all groups" }));
    const failed = row("DomFailed");
    expect(within(failed).getByText("Failed")).toBeInTheDocument();
    expect(failed.textContent).not.toMatch(/risk|confidence/i);
    expect(row("DomLow").textContent).toMatch(/Low risk/);
    // Inside a group the riskiest result leads and runs with no result go last (backend order was DomFailed, DomLow).
    const rows = within(region("Domain d.example")).getAllByRole("button", { expanded: false }).map((b) => b.textContent);
    expect(rows[0]).toMatch(/^DomLow/);
    expect(rows[1]).toMatch(/^DomFailed/);
  });

  it("confidence only after expanding a row", async () => {
    renderWithProviders(<SubmissionDrawer {...three()} />);
    await toAnalysis();
    expect(row("HashHigh").textContent).toMatch(/High risk/);
    expect(screen.queryByText(/High confidence/)).not.toBeInTheDocument();
    await userEvent.click(row("HashHigh"));
    expect(await screen.findByText(/High confidence/)).toBeInTheDocument();
    expect(row("HashHigh")).toHaveAttribute("aria-expanded", "true");
  });

  it("expand all and collapse all icon buttons", async () => {
    renderWithProviders(<SubmissionDrawer {...three()} />);
    await toAnalysis();
    await userEvent.click(screen.getByRole("button", { name: "Expand all groups" }));
    expect(await screen.findByText("UrlLow")).toBeInTheDocument();
    expect(screen.getByText("DomLow")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Collapse all groups" }));
    await waitFor(() => {
      expect(screen.queryByText("HashHigh")).not.toBeInTheDocument();
      expect(screen.queryByText("UrlLow")).not.toBeInTheDocument();
    });
    const btn = screen.getByRole("button", { name: "Collapse all groups" }).getBoundingClientRect();
    expect(Math.min(btn.width, btn.height)).toBeGreaterThanOrEqual(36);
  });

  it("another submission and a reopen start from the default again", async () => {
    const { rerender } = renderWithProviders(<SubmissionDrawer {...three()} />);
    await toAnalysis();
    await userEvent.click(screen.getByRole("button", { name: "Expand all groups" }));
    expect(await screen.findByText("UrlLow")).toBeInTheDocument();
    const other = { ...multiRow, id: 22 };
    rerender(<SubmissionDrawer {...three({ row: other as never, submissionId: 22 })} />);
    await toAnalysis();
    expect(await screen.findByText("HashHigh")).toBeInTheDocument();
    expect(screen.queryByText("UrlLow")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Expand all groups" }));
    expect(await screen.findByText("UrlLow")).toBeInTheDocument();
    rerender(<SubmissionDrawer {...three({ row: other as never, submissionId: 22, open: false })} />);
    await waitFor(() => expect(screen.queryByText("UrlLow")).not.toBeInTheDocument());
    rerender(<SubmissionDrawer {...three({ row: other as never, submissionId: 22 })} />);
    if (!screen.queryByRole("tab", { name: /^Analysis/, selected: true })) await toAnalysis();
    expect(await screen.findByText("HashHigh")).toBeInTheDocument();
    expect(screen.queryByText("UrlLow")).not.toBeInTheDocument();
  });

  it("loading, error and empty states keep their text", async () => {
    const { rerender } = renderWithProviders(<SubmissionDrawer {...three({ details: { data: undefined, isLoading: true, isError: false } as never })} />);
    await toAnalysis();
    expect(screen.getByText("Loading analysis…")).toBeInTheDocument();
    rerender(<SubmissionDrawer {...three({ details: { data: undefined, isLoading: false, isError: true } as never })} />);
    expect(screen.getByText("Could not load analysis details.")).toBeInTheDocument();
    rerender(<SubmissionDrawer {...three({}, { analyzer_reports: [] })} />);
    expect(screen.getByText("No analysis reports yet.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Expand all groups" })).not.toBeInTheDocument();
  });

  it("URL artifacts stay under the analysis groups", async () => {
    renderWithProviders(<SubmissionDrawer {...three()} />);
    await toAnalysis();
    expect(screen.getByRole("heading", { level: 3, name: "URLs" })).toBeInTheDocument();
    expect(screen.getByText("1 artifact")).toBeInTheDocument();
    expect(screen.getAllByText(/u\.example/).length).toBeGreaterThan(1);
  });
});

describe("SubmissionDrawer - analysis tab statuses and aria", () => {
  // One observable: a success plus every non-success status the backend sets (Waiting, InProgress, Deleted, Failure) and an empty one.
  const reports = [
    rep(1, "Gone", 1, "s.example", "DOMAIN", "Deleted"),
    rep(2, "Ok", 9, "s.example", "DOMAIN", "Success"),
    rep(3, "Busy", 1, "s.example", "DOMAIN", "InProgress"),
    rep(4, "Waits", 1, "s.example", "DOMAIN", "Waiting"),
    rep(5, "Blank", 1, "s.example", "DOMAIN", ""),
  ];
  const props = (rs = reports) => base({
    row: multiRow as never,
    details: { data: { ...multiRow, analyzer_reports: rs.map((r) => ({ ...r, type: "domain" })), case_infos: ci() }, isLoading: false, isError: false } as never,
  });
  const open = async (rs = reports) => {
    renderWithProviders(<SubmissionDrawer {...props(rs)} />);
    await userEvent.click(await screen.findByRole("tab", { name: /^Analysis/ }));
  };
  const row = (name: string) => screen.getByRole("button", { name: new RegExp(`^${name}`) });

  it.each([
    ["Busy", "Running", "has not finished yet"],
    ["Waits", "Queued", "has not finished yet"],
    ["Gone", "Expired", "is no longer available in Cortex"],
    ["Blank", "Unknown", "no status reported"],
  ])("%s reads %s: neutral chip, type-only caption, no risk, honest details", async (name, label, says) => {
    await open();
    const r = row(name);
    expect(r).toHaveTextContent(new RegExp(`^${name}Domain check${label}$`));
    expect(r.textContent).not.toMatch(/risk|confidence|Failed/i);
    await userEvent.click(r);
    expect(await screen.findByText(new RegExp(says))).toBeInTheDocument();
    expect(screen.queryByText("Risk score")).not.toBeInTheDocument();
  });

  it("only Failure counts as failed and keeps today's wording; success keeps its status caption", async () => {
    await open([...reports, rep(6, "Broke", 1, "s.example", "DOMAIN", "Failure")]);
    expect(screen.getByText("1 failed")).toBeInTheDocument();
    expect(row("Broke")).toHaveTextContent(/^BrokeDomain checkFailed$/);
    expect(row("Ok")).toHaveTextContent(/Domain check · Success/);
    await userEvent.click(row("Broke"));
    expect(await screen.findByText(/did not return a result \(status: Failure\)/)).toBeInTheDocument();
  });

  it("a Success next to a Deleted keeps the success as worst risk and shows no failed", async () => {
    await open([rep(1, "Gone", 1, "s.example", "DOMAIN", "Deleted"), rep(2, "Ok", 9, "s.example", "DOMAIN", "Success")]);
    expect(screen.getByRole("img", { name: "Worst result: High risk" })).toBeInTheDocument();
    expect(screen.queryByText(/failed/)).not.toBeInTheDocument();
  });

  it("group headers and rows point at what they expand with aria-controls", async () => {
    await open();
    const header = screen.getByRole("button", { name: /s\.example/, expanded: true });
    const panel = document.getElementById(header.getAttribute("aria-controls")!);
    expect(panel).not.toBeNull();
    expect(within(panel!).getByText("Ok")).toBeInTheDocument();
    const r = row("Ok");
    const id = r.getAttribute("aria-controls")!;
    expect(document.getElementById(id)).not.toBeNull();
    await userEvent.click(r);
    expect(await within(document.getElementById(id)!).findByText("What this means")).toBeInTheDocument();
  });
});
