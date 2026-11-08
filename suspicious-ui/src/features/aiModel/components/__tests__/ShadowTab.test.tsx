import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SnackbarProvider } from "notistack";

vi.mock("../../api", () => ({
  getShadow: vi.fn(), getStatus: vi.fn(), postReview: vi.fn(), postPromote: vi.fn(), postExtend: vi.fn(), postRecheck: vi.fn(), postDiscard: vi.fn(),
}));

import * as api from "../../api";
import type { ShadowDetail } from "../../api";
import { ShadowTab } from "../ShadowTab";

const detail = (over: Partial<ShadowDetail> = {}): ShadowDetail => ({
  version_id: "v5", status: "shadow", trigger: "manual", created_at: "2026-10-01T00:00:00Z",
  shadow_since: new Date(Date.now() - 3 * 86_400_000).toISOString(), shadow_min_days: 7, recheck: null,
  live_results: 250,
  agreement: { class: { agree: 90, total: 100 }, verdict: { agree: 40, total: 50 } },
  flips: { count: 2, results: [
    { case_id: 11, flip: "critical", live_result: "Safe", would_be_result: "Dangerous", reviewable: true, reviewed: false },
    { case_id: 12, flip: "changed", live_result: "Inconclusive", would_be_result: "Suspicious", reviewable: false },
  ] },
  campaign_effects: { count: 1, results: [{ case_id: 21, effect: "joins", live_campaign_id: "C-1", reviewable: false }] },
  alert_delta: { candidate_only: { count: 1, results: [31] }, active_only: { count: 0, results: [] } },
  conditions: ["too_young", "recheck_missing"],
  ...over,
});

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <SnackbarProvider>
        <ShadowTab onSeeCandidate={() => {}} />
      </SnackbarProvider>
    </QueryClientProvider>,
  );
}

describe("ShadowTab", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.getStatus).mockResolvedValue({ job_running: false } as never);
  });

  it("points to the Candidate tab with no shadow", async () => {
    vi.mocked(api.getShadow).mockResolvedValue({ shadow: null });
    renderTab();
    expect(await screen.findByText(/No shadow is running/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Go to Candidate/ })).toBeInTheDocument();
  });

  it("shows age, progress and agreement", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail());
    renderTab();
    expect(await screen.findByText(/3 of 7 days/)).toBeInTheDocument();
    expect(screen.getByText(/250 of 500 live results/)).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "50");
    const t = screen.getByRole("table", { name: /agreement/i });
    expect(within(t).getByRole("rowheader", { name: "Verdict" })).toBeInTheDocument();
    expect(within(t).getByText("90%")).toBeInTheDocument();
  });

  it("offers Review only for reviewable flips, and posts an integer case id", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail());
    vi.mocked(api.postReview).mockResolvedValue({ version_id: "v5", kind: "flip", case_id: 11 });
    renderTab();
    await screen.findByText(/3 of 7 days/);
    expect(screen.getAllByRole("button", { name: /^Review case/ })).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: "Review case 11" }));
    const save = screen.getByRole("button", { name: "Save review" });
    expect(save).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Review note/), "checked");
    expect(screen.getByText("7 / 2000")).toBeInTheDocument();
    vi.mocked(api.getShadow).mockResolvedValue(
      detail({ flips: { count: 1, results: [{ case_id: 11, flip: "critical", live_result: "Safe", would_be_result: "Dangerous", reviewable: true, reviewed: true }] } }),
    );
    await userEvent.click(save);
    expect(vi.mocked(api.postReview).mock.calls[0][0]).toEqual({ kind: "flip", case_id: 11, note: "checked" });
    expect(await screen.findByText("Reviewed")).toBeInTheDocument();
  });

  it("lists case ids for campaign effects and alert delta", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail());
    renderTab();
    const fx = await screen.findByRole("table", { name: "Campaign effects" });
    expect(within(fx).getByRole("rowheader", { name: "21" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review alert case 31" })).toBeInTheDocument();
  });

  it("lists unmet conditions in words and keeps Promote off", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail());
    renderTab();
    expect(await screen.findByText(/Not met: The shadow period has not run/)).toBeInTheDocument();
    expect(screen.getByText(/Done: Enough live results/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Promote" })).toBeDisabled();
  });

  it("promotes after confirmation naming the version; a 409 shows the codes", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail({ conditions: [] }));
    vi.mocked(api.postPromote).mockRejectedValue({ response: { status: 409, data: { codes: ["recheck_stale"] } } });
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Promote" }));
    const dlg = await screen.findByRole("dialog");
    expect(within(dlg).getByText(/v5 becomes the active/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole("button", { name: "Promote" }));
    await waitFor(() => expect(api.postPromote).toHaveBeenCalled());
    await waitFor(() => expect(within(screen.getAllByRole("status")[0]).getByText(/out of date/)).toBeInTheDocument());
    await waitFor(() => expect(vi.mocked(api.getShadow).mock.calls.length).toBeGreaterThan(1));
  });

  it("extends only with a whole number above the current total", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail());
    vi.mocked(api.postExtend).mockResolvedValue({} as never);
    renderTab();
    const input = await screen.findByLabelText("New total days");
    const btn = screen.getByRole("button", { name: "Extend" });
    await userEvent.type(input, "7");
    expect(btn).toBeDisabled();
    await userEvent.clear(input);
    await userEvent.type(input, "14");
    await userEvent.click(btn);
    expect(vi.mocked(api.postExtend).mock.calls[0][0]).toEqual({ days: 14 });
  });

  it("rechecks, shows its result, and discards after confirmation", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail({ recheck: { passed: false, finished_at: "2026-11-02T00:00:00Z" } }));
    vi.mocked(api.postRecheck).mockResolvedValue({ job_id: "j" });
    vi.mocked(api.postDiscard).mockResolvedValue({} as never);
    renderTab();
    expect(await screen.findByText(/Last recheck: Failed/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Recheck" }));
    expect(vi.mocked(api.postRecheck).mock.calls[0][0]).toEqual({});
    await userEvent.click(screen.getByRole("button", { name: "Discard" }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Discard" }));
    await waitFor(() => expect(vi.mocked(api.postDiscard).mock.calls[0][0]).toEqual({}));
  });

  it("disables the other actions while one is in flight", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail({ conditions: [] }));
    vi.mocked(api.postRecheck).mockReturnValue(new Promise(() => {}));
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Recheck" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Promote" })).toBeDisabled());
    expect(screen.getByRole("button", { name: "Discard" })).toBeDisabled();
  });

  it("pages each sub-list with its own prefix and keeps the page after a review", async () => {
    const many = <T,>(n: number, f: (i: number) => T) => Array.from({ length: n }, (_, i) => f(i + 1));
    vi.mocked(api.getShadow).mockImplementation(async (p) => {
      const o = (k: string) => Number((p as Record<string, number>)?.[`${k}_offset`] ?? 0);
      return detail({
        flips: { count: 25, results: many(10, (i) => ({ case_id: 100 + o("flips") + i, flip: "critical", live_result: "Safe", would_be_result: "Dangerous", reviewable: true, reviewed: false })) as never },
        campaign_effects: { count: 25, results: many(10, (i) => ({ case_id: 200 + o("effects") + i, effect: "joins", live_campaign_id: null, reviewable: true, reviewed: false })) as never },
        alert_delta: {
          candidate_only: { count: 25, results: many(10, (i) => 300 + o("candidate_only") + i) },
          active_only: { count: 25, results: many(10, (i) => 400 + o("active_only") + i) },
        },
      });
    });
    vi.mocked(api.postReview).mockResolvedValue({ version_id: "v5", kind: "campaign", case_id: 211 });
    renderTab();
    await screen.findByRole("button", { name: "Review campaign case 201" });
    await userEvent.click(screen.getByRole("button", { name: "Next page of campaign effects" }));
    await screen.findByRole("button", { name: "Review campaign case 211" });
    const last = () => vi.mocked(api.getShadow).mock.calls.at(-1)![0] as Record<string, number>;
    expect(last()).toMatchObject({ effects_offset: 10, flips_offset: 0, candidate_only_offset: 0, active_only_offset: 0 });
    await userEvent.click(screen.getByRole("button", { name: "Next page of Alerts only the candidate would raise" }));
    await userEvent.click(screen.getByRole("button", { name: "Next page of Alerts only the active model raises" }));
    await userEvent.click(screen.getByRole("button", { name: "Next page of verdict changes" }));
    await waitFor(() => expect(last()).toMatchObject({ effects_offset: 10, flips_offset: 10, candidate_only_offset: 10, active_only_offset: 10 }));
    // the campaign-effect Review button posts kind campaign; the page stays after it
    await userEvent.click(screen.getByRole("button", { name: "Review campaign case 211" }));
    await userEvent.type(screen.getByLabelText(/Review note/), "ok");
    await userEvent.click(screen.getByRole("button", { name: "Save review" }));
    await waitFor(() => expect(vi.mocked(api.postReview).mock.calls[0][0]).toEqual({ kind: "campaign", case_id: 211, note: "ok" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await screen.findByRole("button", { name: "Review campaign case 211" })).toBeInTheDocument();
    expect(last()).toMatchObject({ effects_offset: 10, flips_offset: 10 });
  });

  it("refuses a note over 2000 characters", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail());
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Review case 11" }));
    const note = screen.getByLabelText(/Review note/);
    await userEvent.click(note);
    await userEvent.paste("x".repeat(2001));
    expect(screen.getByText("2001 / 2000")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save review" })).toBeDisabled();
  });

  it("polls the shadow while a job runs and shows the new recheck result", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.getStatus).mockResolvedValue({ job_running: true } as never);
    vi.mocked(api.getShadow).mockResolvedValue(detail());
    renderTab();
    await screen.findByText(/3 of 7 days/);
    vi.mocked(api.getShadow).mockResolvedValue(detail({ recheck: { passed: true, finished_at: "2026-11-03T00:00:00Z" } }));
    await vi.advanceTimersByTimeAsync(10_500);
    expect(await screen.findByText(/Last recheck: Passed/)).toBeInTheDocument();
    vi.useRealTimers();
  });

  it("does not keep an old refusal after a later success", async () => {
    vi.mocked(api.getShadow).mockResolvedValue(detail({ conditions: [] }));
    vi.mocked(api.postPromote).mockRejectedValue({ response: { status: 409, data: { codes: ["recheck_stale"] } } });
    vi.mocked(api.postExtend).mockResolvedValue({} as never);
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Promote" }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Promote" }));
    await waitFor(() => expect(within(screen.getAllByRole("status")[0]).getByText(/out of date/)).toBeInTheDocument());
    await userEvent.type(screen.getByLabelText("New total days"), "14");
    await userEvent.click(screen.getByRole("button", { name: "Extend" }));
    await waitFor(() => expect(within(screen.getAllByRole("status")[0]).queryByText(/out of date/)).not.toBeInTheDocument());
  });
});
