import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SnackbarProvider } from "notistack";

vi.mock("../../api", () => ({
  getStatus: vi.fn(),
  getJobs: vi.fn(),
  postRetrain: vi.fn(),
  postResetBreaker: vi.fn(),
}));

import * as api from "../../api";
import type { AiModelStatus } from "../../api";
import { OverviewTab } from "../OverviewTab";

const NOW = new Date("2026-11-08T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

const version = (id: string, age: number) => ({
  version_id: id, status: "active" as const, trigger: "manual", created_at: daysAgo(age),
  shadow_since: null, shadow_min_days: 7, recheck: null,
});

const status = (over: Partial<AiModelStatus> = {}): AiModelStatus => ({
  active: version("v3", 10), previous: null, shadow: null, job_running: false, job_id: null,
  health: { ok: true, detail: "", checked_at: daysAgo(0) },
  breaker: { state: "closed", since: null },
  schedule: { enabled: true, interval_days: 30, next_run: "2026-12-01T00:00:00Z", backoff_until: null },
  counts: { candidate: 0, shadow: 0, active: 1, previous: 0, discarded: 0, failed: 0 },
  jobs: [],
  ledger: { by_source: { folder: { Dangerous: 12, Safe: 30 }, flag: { Dangerous: 2 } }, flagged: 1, trainable: 44 },
  ...over,
});

function renderTab(s: AiModelStatus, onSeeCandidate = vi.fn()) {
  vi.mocked(api.getStatus).mockResolvedValue(s);
  vi.mocked(api.getJobs).mockResolvedValue({ count: 0, next: null, previous: null, results: [] });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <SnackbarProvider>
        <OverviewTab onSeeCandidate={onSeeCandidate} />
      </SnackbarProvider>
    </QueryClientProvider>,
  );
  return { onSeeCandidate };
}

describe("OverviewTab", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ["Date"], now: NOW });
  });
  afterEach(() => vi.useRealTimers());

  it("shows health ok, failing with detail, and never checked", async () => {
    renderTab(status());
    expect(await screen.findByText(/Connector health: ok/i)).toBeInTheDocument();
  });
  it("shows a failing health with its stored detail", async () => {
    renderTab(status({ health: { ok: false, detail: "inference unreachable", checked_at: daysAgo(1) } }));
    expect(await screen.findByText(/Connector health: failing/i)).toBeInTheDocument();
    expect(screen.getByText(/inference unreachable/)).toBeInTheDocument();
  });
  it("shows never checked", async () => {
    renderTab(status({ health: { ok: null, detail: "", checked_at: null } }));
    expect(await screen.findByText(/Connector health: never checked/i)).toBeInTheDocument();
  });

  it("offers no reset when the breaker is closed", async () => {
    renderTab(status());
    expect(await screen.findByText(/Circuit breaker: closed/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /reset breaker/i })).toBeNull();
  });
  it("resets an open breaker after confirmation and announces the result", async () => {
    vi.mocked(api.postResetBreaker).mockResolvedValue({ epoch: 2 });
    renderTab(status({ breaker: { state: "open", since: daysAgo(0) } }));
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(await screen.findByRole("button", { name: /reset breaker/i }));
    expect(api.postResetBreaker).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: /^reset$/i }));
    await waitFor(() => expect(api.postResetBreaker).toHaveBeenCalled());
    expect(await screen.findByText(/breaker was reset/i)).toBeInTheDocument();
    expect(screen.getByText(/breaker was reset/i).closest("[role=status]")).not.toBeNull();
  });
  it("offers a reset for half-open", async () => {
    renderTab(status({ breaker: { state: "half-open", since: null } }));
    expect(await screen.findByRole("button", { name: /reset breaker/i })).toBeInTheDocument();
  });

  it("shows the active version, its age and the calibration note for v0", async () => {
    renderTab(status({ active: version("v0", 5) }));
    expect(await screen.findByText(/v0/)).toBeInTheDocument();
    expect(screen.getByText(/5 days old/)).toBeInTheDocument();
    expect(screen.getByText(/Confidence not calibrated/)).toBeInTheDocument();
    expect(screen.queryByText(/older than 60 days/i)).toBeNull();
  });
  it("warns when the active version is older than 60 days", async () => {
    renderTab(status({ active: version("v3", 61) }));
    expect(await screen.findByText(/older than 60 days/i)).toBeInTheDocument();
    expect(screen.queryByText(/Confidence not calibrated/)).toBeNull();
  });

  it("renders label counts by class and source", async () => {
    renderTab(status());
    const row = (await screen.findByRole("row", { name: /folder/i }));
    expect(within(row).getByText("12")).toBeInTheDocument();
    expect(within(row).getByText("30")).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /flag/i })).toBeInTheDocument();
  });

  it("shows the schedule, off, and the backoff", async () => {
    renderTab(status());
    expect(await screen.findByText(/Automatic retrain every 30 days, next about/)).toBeInTheDocument();
  });
  it("shows Off", async () => {
    renderTab(status({ schedule: { enabled: false, interval_days: 30, next_run: null, backoff_until: null } }));
    expect(await screen.findByText(/Automatic retrain: Off/)).toBeInTheDocument();
  });
  it("shows the wait after a failed run", async () => {
    renderTab(status({ schedule: { enabled: true, interval_days: 30, next_run: "2026-12-01T00:00:00Z", backoff_until: "2026-11-12T00:00:00Z" } }));
    expect(await screen.findByText(/waiting until .* after a failed run/i)).toBeInTheDocument();
  });

  it("retrains only after confirmation", async () => {
    vi.mocked(api.postRetrain).mockResolvedValue({ job_id: "j1" });
    renderTab(status());
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(await screen.findByRole("button", { name: /retrain now/i }));
    expect(api.postRetrain).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: /^start retrain$/i }));
    await waitFor(() => expect(api.postRetrain).toHaveBeenCalled());
  });
  it("disables retrain and shows the job while one runs", async () => {
    renderTab(status({
      job_running: true, job_id: "j1",
      jobs: [{ job_id: "j1", state: "running", trigger: "manual", rows: 120, excluded_rows: 3, started_at: daysAgo(0), finished_at: null, error: "" }],
    }));
    expect(await screen.findByRole("button", { name: /retrain now/i })).toBeDisabled();
    expect(screen.getByText(/running/i)).toBeInTheDocument();
    expect(screen.getByText(/120 rows/)).toBeInTheDocument();
  });
  it("shows the refusal text of a 409", async () => {
    vi.mocked(api.postRetrain).mockRejectedValue({ response: { status: 409, data: {} } });
    renderTab(status());
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(await screen.findByRole("button", { name: /retrain now/i }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: /^start retrain$/i }));
    const msgs = await screen.findAllByText(/The retrain was refused/);
    expect(msgs.some((m) => m.closest("[role=status]"))).toBe(true);
  });
  it("fetches jobs only while a job runs", async () => {
    renderTab(status());
    await screen.findByText(/Connector health/);
    expect(api.getJobs).not.toHaveBeenCalled();
  });
  it("fetches jobs while a job runs", async () => {
    renderTab(status({ job_running: true, job_id: "j1" }));
    await waitFor(() => expect(api.getJobs).toHaveBeenCalled());
  });
  it("says 1 day old", async () => {
    renderTab(status({ active: version("v3", 1) }));
    expect(await screen.findByText(/1 day old/)).toBeInTheDocument();
  });
  it("shows a failed reset inline", async () => {
    vi.mocked(api.postResetBreaker).mockRejectedValue({ response: { status: 503, data: { detail: "Shared cache is down." } } });
    renderTab(status({ breaker: { state: "open", since: null } }));
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(await screen.findByRole("button", { name: /reset breaker/i }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: /^reset$/i }));
    const msgs = await screen.findAllByText(/Shared cache is down/);
    expect(msgs.some((m) => m.closest("[role=status]"))).toBe(true);
  });
  it("offers See candidate for a succeeded job", async () => {
    const { onSeeCandidate } = renderTab(status({
      jobs: [{ job_id: "j2", state: "succeeded", trigger: "manual", rows: 100, excluded_rows: 0, started_at: daysAgo(1), finished_at: daysAgo(1), error: "" }],
    }));
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(await screen.findByRole("button", { name: /see candidate/i }));
    expect(onSeeCandidate).toHaveBeenCalled();
  });
});
