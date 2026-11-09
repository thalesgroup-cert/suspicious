import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SnackbarProvider } from "notistack";

vi.mock("../../api", () => ({
  getStatus: vi.fn(),
  getCandidates: vi.fn(),
  postShadowStart: vi.fn(),
  postDiscard: vi.fn(),
}));

import * as api from "../../api";
import type { AiModelStatus, CandidateRow, Gate } from "../../api";
import { CandidateTab } from "../CandidateTab";

const gate = (over: Partial<Gate> = {}): Gate => ({
  checks: {
    macro_f1: { passed: true, value: 0.91, threshold: 0.9, detail: "ok" },
    dangerous_called_safe: { passed: false, value: 0.04, threshold: 0.02, detail: "too many" },
    ece: { passed: true, value: 0.03, threshold: 0.05, detail: "ok" },
  },
  candidate: null,
  baseline: null,
  campaign: { dangerous_called_safe: 0.01, baseline_dangerous_called_safe: 0.02, groups: 17 },
  tier_cutoffs: { high: 0.93, medium: 0.6 },
  ...over,
});

const cand = (over: Partial<CandidateRow> = {}): CandidateRow => ({
  version_id: "v4", status: "candidate", created_at: "2026-11-01T00:00:00Z", trigger: "manual",
  rows: 1200, excluded_rows: 30, eligible: true, gate: gate(), ...over,
});

const status = (shadow: unknown = null) => ({ shadow }) as unknown as AiModelStatus;

function renderTab(rows: CandidateRow[], st: AiModelStatus = status()) {
  vi.mocked(api.getStatus).mockResolvedValue(st);
  vi.mocked(api.getCandidates).mockResolvedValue({ count: rows.length, next: null, previous: null, results: rows });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <SnackbarProvider>
        <CandidateTab />
      </SnackbarProvider>
    </QueryClientProvider>,
  );
}

describe("CandidateTab", () => {
  beforeEach(() => vi.clearAllMocks());

  it("says so with no candidate", async () => {
    renderTab([]);
    expect(await screen.findByText(/No candidate/i)).toBeInTheDocument();
  });

  it("shows rows, excluded rows, trigger and date", async () => {
    renderTab([cand()]);
    expect(await screen.findByText(/1200 rows/)).toBeInTheDocument();
    expect(screen.getByText(/30 excluded/)).toBeInTheDocument();
    expect(screen.getByText(/manual/)).toBeInTheDocument();
    expect(screen.getByText(new Date("2026-11-01T00:00:00Z").toLocaleDateString())).toBeInTheDocument();
  });

  it("lists failed checks first, in words, with value and threshold", async () => {
    renderTab([cand()]);
    const table = await screen.findByRole("table", { name: /gate checks/i });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getByRole("rowheader")).toHaveTextContent("dangerous_called_safe");
    expect(within(rows[0]).getByText("Failed")).toBeInTheDocument();
    expect(within(rows[0]).getByText("0.04")).toBeInTheDocument();
    expect(within(rows[0]).getByText("0.02")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Passed")).toBeInTheDocument();
  });

  it("shows the campaign line and the tier cutoffs", async () => {
    renderTab([cand()]);
    expect(await screen.findByText(/Campaign held-out: 0.01 Dangerous called Safe, baseline 0.02, 17 groups/)).toBeInTheDocument();
    expect(screen.getByText(/High 0.93/)).toBeInTheDocument();
    expect(screen.getByText(/Medium 0.6/)).toBeInTheDocument();
  });

  it("shows not available for absent parts and renders no unlisted key", async () => {
    const g = gate({ checks: null, campaign: null, tier_cutoffs: null });
    (g as Record<string, unknown>).secret = "LEAK";
    (g.candidate as unknown) = { macro_f1: 0.9 };
    renderTab([cand({ gate: g })]);
    expect((await screen.findAllByText(/not available/i)).length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText(/LEAK/)).toBeNull();
  });

  it("starts the shadow after confirmation", async () => {
    vi.mocked(api.postShadowStart).mockResolvedValue({} as never);
    renderTab([cand()]);
    const btn = await screen.findByRole("button", { name: "Start shadow" });
    expect(btn).toBeEnabled();
    await userEvent.click(btn);
    expect(api.postShadowStart).not.toHaveBeenCalled();
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Start shadow" }));
    await waitFor(() => expect(vi.mocked(api.postShadowStart).mock.calls[0][0]).toEqual({ version_id: "v4" }));
  });

  it("shows a 409 refusal text", async () => {
    vi.mocked(api.postShadowStart).mockRejectedValue({ response: { status: 409, data: { detail: "Another shadow is running." } } });
    renderTab([cand()]);
    await userEvent.click(await screen.findByRole("button", { name: "Start shadow" }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Start shadow" }));
    expect((await screen.findAllByText(/Another shadow is running/)).length).toBeGreaterThan(0);
  });

  it("disables Start shadow while a shadow exists", async () => {
    renderTab([cand()], status({ version_id: "v3" }));
    await waitFor(() => expect(api.getStatus).toHaveBeenCalled());
    expect(await screen.findByRole("button", { name: "Start shadow" })).toBeDisabled();
    expect(await screen.findByText(/shadow is already running/i)).toBeInTheDocument();
  });

  it("names the failed checks beside the disabled button for an ineligible candidate", async () => {
    renderTab([cand({ eligible: false })]);
    expect(await screen.findByRole("button", { name: "Start shadow" })).toBeDisabled();
    expect(screen.getByText(/Not eligible: dangerous_called_safe/)).toBeInTheDocument();
  });

  it("asks before discarding, then posts", async () => {
    vi.mocked(api.postDiscard).mockResolvedValue({} as never);
    renderTab([cand()]);
    await userEvent.click(await screen.findByRole("button", { name: "Discard" }));
    expect(api.postDiscard).not.toHaveBeenCalled();
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Discard" }));
    await waitFor(() => expect(vi.mocked(api.postDiscard).mock.calls[0][0]).toEqual({ version_id: "v4", expected_status: "candidate" }));
  });
});
