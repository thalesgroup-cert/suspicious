import { afterEach, describe, it, expect, vi } from "vitest";
import { screen, within } from "@testing-library/react";
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
  expandedGroups: {},
  setExpandedGroups: vi.fn(),
  expandedAnalyzerIds: {},
  setExpandedAnalyzerIds: vi.fn(),
  ...over,
});

const rep = (id: number, analyzer_name: string, score: number, value = "a.example", kind = "DOMAIN", status = "Success") => ({
  id, cortex_job_id: null, type: "x", status, analyzer_name, analyzer_id: analyzer_name,
  level: null, confidence: null, score, category: null, categories: [],
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
