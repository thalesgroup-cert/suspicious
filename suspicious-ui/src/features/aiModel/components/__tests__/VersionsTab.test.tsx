import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SnackbarProvider } from "notistack";

vi.mock("../../api", () => ({ getVersions: vi.fn(), getStatus: vi.fn(), postRollback: vi.fn() }));

import * as api from "../../api";
import type { VersionRow } from "../../api";
import { VersionsTab } from "../VersionsTab";

const row = (id: string, status: VersionRow["status"], over: Partial<VersionRow> = {}): VersionRow => ({
  version_id: id, status, trigger: "manual", created_at: "2026-10-01T00:00:00Z", shadow_since: null, shadow_min_days: 7, recheck: null,
  stats: { scored: 100, dangerous: 12, checks: 5, created: 2, joined: 3, alerts: 4 },
  purity: { labelled: 40, dangerous: 38, purity: 0.95, warning: false }, age_warning: false, ...over,
});
const page = (results: VersionRow[], count = results.length) => ({ count, next: null, previous: null, results });

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <SnackbarProvider>
        <VersionsTab />
      </SnackbarProvider>
    </QueryClientProvider>,
  );
}

describe("VersionsTab", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.getStatus).mockResolvedValue({ job_running: false, active: { version_id: "v3" }, previous: { version_id: "v0" } } as never);
  });

  it("lists versions with counters, purity and warnings in words", async () => {
    vi.mocked(api.getVersions).mockResolvedValue(page([
      row("v3", "active"),
      row("v2", "discarded", { purity: { labelled: 20, dangerous: 10, purity: 0.5, warning: true }, age_warning: true }),
      row("v0", "previous"),
    ]));
    renderTab();
    const t = await screen.findByRole("table", { name: /version history/i });
    expect(within(t).getByRole("rowheader", { name: "v3" })).toBeInTheDocument();
    expect(within(t).getByRole("rowheader", { name: "v0 (the original model)" })).toBeInTheDocument();
    const r = within(screen.getByRole("rowheader", { name: "v3" }).closest("tr")!);
    expect(r.getByText("100")).toBeInTheDocument();
    expect(r.getByText("95% of 40 labelled")).toBeInTheDocument();
    const bad = within(screen.getByRole("rowheader", { name: "v2" }).closest("tr")!);
    expect(bad.getByText(/Low purity/)).toBeInTheDocument();
    expect(bad.getByText(/Created more than 60 days ago/)).toBeInTheDocument();
    expect(within(screen.getByRole("rowheader", { name: "v3" }).closest("tr")!).queryByText(/Low purity|older than/)).toBeNull();
  });

  it("shows a purity just under the threshold without rounding up", async () => {
    vi.mocked(api.getVersions).mockResolvedValue(page([row("v2", "discarded", { purity: { labelled: 200, dangerous: 159, purity: 0.795, warning: true } })]));
    renderTab();
    expect(await screen.findByText(/79\.5% of 200 labelled members.*80% threshold/)).toBeInTheDocument();
  });

  it("offers Rollback only on the previous row and names both versions", async () => {
    vi.mocked(api.getVersions).mockResolvedValue(page([row("v3", "active"), row("v0", "previous")]));
    vi.mocked(api.postRollback).mockResolvedValue(row("v0", "active"));
    renderTab();
    await screen.findByRole("table");
    expect(screen.getAllByRole("button", { name: /Rollback/ })).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: /Rollback to v0/ }));
    const d = screen.getByRole("dialog");
    expect(d).toHaveTextContent("v3");
    expect(d).toHaveTextContent("v0 (the original model)");
    await userEvent.click(within(d).getByRole("button", { name: "Roll back" }));
    expect(api.postRollback).toHaveBeenCalledTimes(1);
  });

  it("shows the 409 text and only the latest outcome", async () => {
    vi.mocked(api.getVersions).mockResolvedValue(page([row("v3", "active"), row("v2", "previous")]));
    vi.mocked(api.postRollback).mockRejectedValue({ response: { status: 409, data: { codes: ["state_changed"] } } });
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: /Rollback to v2/ }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Roll back" }));
    expect(await within(await screen.findByRole("status")).findByText(/state changed/i)).toBeInTheDocument();
    vi.mocked(api.postRollback).mockResolvedValue(row("v2", "active"));
    await userEvent.click(await screen.findByRole("button", { name: /Rollback to v2/ }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Roll back" }));
    expect(await within(await screen.findByRole("status")).findByText(/rolled back/i)).toBeInTheDocument();
    expect(within(screen.getByRole("status")).queryByText(/state changed/i)).toBeNull();
  });

  it("keeps the open dialog while paging", async () => {
    let release: () => void = () => {};
    vi.mocked(api.getVersions).mockImplementation(async (p) => {
      if ((p?.offset ?? 0) === 0) return page([row("v3", "active"), row("v2", "previous")], 25);
      await new Promise<void>((r) => { release = r; });
      return page([row("v1", "discarded")], 25);
    });
    renderTab();
    await userEvent.click(await screen.findByRole("button", { name: /Rollback to v2/ }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    // MUI marks the page behind a modal aria-hidden; the pager is still clickable.
    await userEvent.click(screen.getByRole("button", { name: /Next page of versions/, hidden: true }));
    // Page 2 is still loading: the dialog and the old rows stay.
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    release();
    expect(await screen.findByRole("rowheader", { name: "v1", hidden: true })).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("shows the empty state", async () => {
    vi.mocked(api.getVersions).mockResolvedValue(page([]));
    renderTab();
    expect(await screen.findByText(/No versions yet/)).toBeInTheDocument();
  });
});
