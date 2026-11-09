import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SnackbarProvider } from "notistack";
import { MemoryRouter } from "react-router";

vi.mock("../../api", () => ({ getLedger: vi.fn(), getFlags: vi.fn(), getQueue: vi.fn(), postResolveFlag: vi.fn() }));

import * as api from "../../api";
import type { FlagRow, LedgerResponse, QueueResponse } from "../../api";
import { LedgerTab } from "../LedgerTab";

const ledger = (over: Partial<LedgerResponse> = {}): LedgerResponse => ({
  by_source: { imap_folder: { Dangerous: 30, Safe: 70 }, analyst: { Safe: 2 } },
  flagged: 1, trainable: 100,
  mix: { now: { Dangerous: 0.5, Safe: 0.3, Unwanted: 0.2 }, before: { Dangerous: 0.2, Safe: 0.6, Unwanted: 0.2 }, rows: { now: 100, before: 80 },
    jump: { class: "Dangerous", from: 0.2, to: 0.5 } },
  ...over,
});
const flag = (id: number, over: Partial<FlagRow> = {}): FlagRow => ({
  id, case_id: 100 + id, label_class: "Safe", source: "imap_folder", flag_reason: "folder_verdict_mismatch", observed_at: "2026-10-05T00:00:00Z", ...over,
});
const pg = <T,>(results: T[], count = results.length) => ({ count, next: null, previous: null, results });
const queue = (over: Partial<QueueResponse> = {}): QueueResponse => ({
  disagreements: { count: 1, results: [{ case_id: 7, verdict: "Dangerous", ai_class: "Safe", date: "2026-10-06T00:00:00Z" }] },
  campaign_conflicts: { count: 1, results: [{ campaign_ref: "CAMP-9", classes: ["Dangerous", "Safe"], date: "2026-10-07T00:00:00Z" }] },
  ...over,
});

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <SnackbarProvider>
        <MemoryRouter>
          <LedgerTab />
        </MemoryRouter>
      </SnackbarProvider>
    </QueryClientProvider>,
  );
}

describe("LedgerTab", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.getLedger).mockResolvedValue(ledger());
    vi.mocked(api.getFlags).mockResolvedValue(pg([flag(1), flag(2, { flag_reason: "weird_new" })]));
    vi.mocked(api.getQueue).mockResolvedValue(queue());
  });

  it("shows the mix against 30 days ago and the jump warning", async () => {
    renderTab();
    const t = await screen.findByRole("table", { name: /label mix/i });
    const r = within(within(t).getByRole("rowheader", { name: "Dangerous" }).closest("tr")!);
    expect(r.getByText("50%")).toBeInTheDocument();
    expect(r.getByText("20%")).toBeInTheDocument();
    expect(screen.getByText(/Dangerous moved from 20% to 50%/)).toBeInTheDocument();
    const s = screen.getByRole("table", { name: /labels by source/i });
    expect(within(s).getByText("70")).toBeInTheDocument();
  });

  it("handles an empty mix and no jump", async () => {
    vi.mocked(api.getLedger).mockResolvedValue(ledger({ mix: { now: {}, before: {}, rows: { now: 0, before: 0 }, jump: null } }));
    renderTab();
    expect(await screen.findByText(/No folder labels yet/)).toBeInTheDocument();
    expect(screen.queryByText(/moved from/)).toBeNull();
  });

  it("lists flagged labels with reasons in words and a safe fallback", async () => {
    renderTab();
    const t = await screen.findByRole("table", { name: /flagged labels/i });
    expect(within(t).getByText("folder label disagrees with the analyst verdict")).toBeInTheDocument();
    expect(within(t).getByText("flagged for review")).toBeInTheDocument();
    expect(within(t).getByRole("rowheader", { name: "101" })).toBeInTheDocument();
  });

  it("resolves a flag with a note and removes the row", async () => {
    vi.mocked(api.postResolveFlag).mockResolvedValue(flag(1));
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Keep label for case 101" }));
    const dlg = await screen.findByRole("dialog");
    const ok = within(dlg).getByRole("button", { name: "Keep label" });
    expect(ok).toBeDisabled();
    await userEvent.type(within(dlg).getByLabelText(/note/i), "checked by hand");
    vi.mocked(api.getFlags).mockResolvedValue(pg([flag(2, { flag_reason: "weird_new" })]));
    await userEvent.click(ok);
    expect(vi.mocked(api.postResolveFlag).mock.calls[0][0]).toEqual({ id: 1, keep: true, note: "checked by hand" });
    await waitFor(() => expect(screen.queryByRole("rowheader", { name: "101" })).toBeNull());
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/kept/i));
  });

  it("drops a label with keep false", async () => {
    vi.mocked(api.postResolveFlag).mockResolvedValue(flag(2));
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Drop label for case 102" }));
    const dlg = await screen.findByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText(/note/i), "wrong");
    await userEvent.click(within(dlg).getByRole("button", { name: "Drop label" }));
    expect(vi.mocked(api.postResolveFlag).mock.calls[0][0]).toEqual({ id: 2, keep: false, note: "wrong" });
  });

  it("says already closed on 409 and refreshes", async () => {
    vi.mocked(api.postResolveFlag).mockRejectedValue({ response: { status: 409, data: { detail: "The label is not flagged." } } });
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Keep label for case 101" }));
    const dlg = await screen.findByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText(/note/i), "x");
    const calls = vi.mocked(api.getFlags).mock.calls.length;
    await userEvent.click(within(dlg).getByRole("button", { name: "Keep label" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/already closed/i));
    await waitFor(() => expect(vi.mocked(api.getFlags).mock.calls.length).toBeGreaterThan(calls));
  });

  it("shows the queue with links by case id only", async () => {
    renderTab();
    const d = await screen.findByRole("table", { name: /AI disagrees with the evidence/i });
    expect(within(d).getByRole("link", { name: "7" })).toHaveAttribute("href", "/investigation?open=7");
    expect(within(d).getByText("Safe")).toBeInTheDocument();
    const c = screen.getByRole("table", { name: /campaign members disagree/i });
    expect(within(c).getByRole("rowheader", { name: "CAMP-9" })).toBeInTheDocument();
    expect(within(c).getByText("Dangerous, Safe")).toBeInTheDocument();
  });

  it("pages both lists with their own offsets and shows empty states", async () => {
    vi.mocked(api.getFlags).mockResolvedValue(pg([flag(1)], 25));
    vi.mocked(api.getQueue).mockResolvedValue(queue({ disagreements: { count: 25, results: queue().disagreements.results } }));
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Next page of flagged labels" }));
    await waitFor(() => expect(api.getFlags).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 10 })));
    await userEvent.click(screen.getByRole("button", { name: "Next page of AI disagreements" }));
    await waitFor(() => expect(api.getQueue).toHaveBeenLastCalledWith(expect.objectContaining({ disagreements_offset: 10, conflicts_offset: 0 })));
    expect(api.getFlags).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 10 }));
  });

  it("steps back a page when resolving empties the last page", async () => {
    let total = 11;
    vi.mocked(api.getFlags).mockImplementation(async (p) => {
      const o = Number(p?.offset ?? 0);
      return pg(Array.from({ length: Math.max(0, Math.min(10, total - o)) }, (_, i) => flag(o + i + 1)), total);
    });
    vi.mocked(api.postResolveFlag).mockImplementation(async () => { total = 10; return flag(11); });
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Next page of flagged labels" }));
    await userEvent.click(await screen.findByRole("button", { name: "Keep label for case 111" }));
    await userEvent.type(within(await screen.findByRole("dialog")).getByLabelText(/note/i), "ok");
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Keep label" }));
    expect(await screen.findByRole("rowheader", { name: "101" })).toBeInTheDocument();
    expect(api.getFlags).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 0 }));
  });

  it("steps back a queue page that came back empty", async () => {
    vi.mocked(api.getQueue).mockImplementation(async (p) =>
      Number(p?.disagreements_offset ?? 0) === 0
        ? queue({ disagreements: { count: 25, results: queue().disagreements.results } })
        : queue({ disagreements: { count: 5, results: [] } }));
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: "Next page of AI disagreements" }));
    await waitFor(() => expect(api.getQueue).toHaveBeenCalledWith(expect.objectContaining({ disagreements_offset: 10 })));
    await waitFor(() => expect(api.getQueue).toHaveBeenLastCalledWith(expect.objectContaining({ disagreements_offset: 0 })));
    expect(await screen.findByRole("link", { name: "7" })).toBeInTheDocument();
  });

  it("shows empty states", async () => {
    vi.mocked(api.getFlags).mockResolvedValue(pg<FlagRow>([]));
    vi.mocked(api.getQueue).mockResolvedValue({ disagreements: { count: 0, results: [] }, campaign_conflicts: { count: 0, results: [] } });
    renderTab();
    expect(await screen.findByText("No flagged labels.")).toBeInTheDocument();
    expect(screen.getByText("No cases where the AI disagrees with the evidence.")).toBeInTheDocument();
    expect(screen.getByText("No campaigns with disagreeing members.")).toBeInTheDocument();
  });
});
