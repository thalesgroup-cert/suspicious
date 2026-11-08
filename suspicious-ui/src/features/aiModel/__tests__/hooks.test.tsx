import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook, waitFor, act, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SnackbarProvider } from "notistack";
import type { ReactNode } from "react";

vi.mock("../api", () => ({
  getStatus: vi.fn(),
  postRetrain: vi.fn(),
  postRollback: vi.fn(),
  postResetBreaker: vi.fn(),
}));

import * as api from "../api";
import { useAiModelStatus, useRetrain, useRollback } from "../hooks";
import { CODE_TEXT, refusalMessage } from "../labels";
import { aiModelKeys } from "../queryKeys";

function setup() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>
      <SnackbarProvider>{children}</SnackbarProvider>
    </QueryClientProvider>
  );
  return { qc, wrapper };
}

const conflict = (data: unknown) => ({ isAxiosError: true, response: { status: 409, data } });

describe("aiModel data layer", () => {
  beforeEach(() => vi.clearAllMocks());

  it("polls the status every 30 s under [ai-model, status]", async () => {
    vi.mocked(api.getStatus).mockResolvedValue({} as never);
    const { qc, wrapper } = setup();
    renderHook(() => useAiModelStatus(), { wrapper });
    await waitFor(() => expect(api.getStatus).toHaveBeenCalled());
    expect(aiModelKeys.status()).toEqual(["ai-model", "status"]);
    const q = qc.getQueryCache().find({ queryKey: ["ai-model", "status"] })!;
    expect((q.observers[0].options as { refetchInterval?: number }).refetchInterval).toBe(30_000);
  });

  it("invalidates the ai-model root after a successful mutation", async () => {
    vi.mocked(api.postRetrain).mockResolvedValue({ job_id: "j1" });
    const { qc, wrapper } = setup();
    const spy = vi.spyOn(qc, "invalidateQueries");
    const { result } = renderHook(() => useRetrain(), { wrapper });
    await act(() => result.current.mutateAsync({ note: "" }));
    expect(spy).toHaveBeenCalledWith({ queryKey: ["ai-model"] });
  });

  it("shows the plain text of a 409 code in the snackbar", async () => {
    vi.mocked(api.postRollback).mockRejectedValue(conflict({ detail: "Promotion refused.", codes: ["no_previous"] }));
    const { wrapper } = setup();
    const { result } = renderHook(() => useRollback(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync({ note: "x" }).catch(() => undefined);
    });
    expect(await screen.findByText(CODE_TEXT.no_previous)).toBeInTheDocument();
  });
});

describe("labels", () => {
  it("covers every code Plan F returns", () => {
    for (const c of [
      "not_shadow", "too_young", "too_few_results", "unreviewed_flips", "unreviewed_campaigns",
      "recheck_missing", "recheck_failed", "recheck_stale", "profile_window", "job_running",
      "no_previous", "state_changed",
    ]) {
      expect(CODE_TEXT[c], c).toBeTruthy();
    }
  });
  it("maps codes, falls back to the detail, then by context", () => {
    expect(refusalMessage(conflict({ detail: "d", codes: ["no_previous", "weird"] }), "action")).toBe(
      `${CODE_TEXT.no_previous} weird`,
    );
    expect(refusalMessage(conflict({ detail: "The change was refused in the current state." }), "breaker")).toBe(
      "The change was refused in the current state.",
    );
    expect(refusalMessage(conflict({ detail: "x" }), "retrain")).toMatch(/retrain/i);
    expect(refusalMessage(new Error("boom"), "retrain")).toMatch(/could not/i);
  });
});
