import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/api/client";
import { getDashboardScopes, getDashboardSummary } from "../api";

vi.mock("@/api/client", () => ({ api: { get: vi.fn() } }));

describe("dashboard api", () => {
  beforeEach(() => vi.mocked(api.get).mockReset());

  it("requests the summary with month, year and scope", async () => {
    vi.mocked(api.get).mockResolvedValue({ data: {} });
    await getDashboardSummary({ month: 10, year: 2026, scope: "COUNTRY:AU" });
    expect(api.get).toHaveBeenCalledWith("/dashboard/summary/", {
      params: { month: 10, year: 2026, scope: "COUNTRY:AU" },
    });
  });

  it("normalises a sparse summary: numbers default to 0, top_reporters stays null", async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: {
        month: 10,
        year: 2026,
        scope: { key: "OWN_COUNTRY", label: "My country (AU)" },
        reports: 12,
        outcomes: { safe: 3 },
        trend: [{ week_start: "2026-09-28", reports: 2 }, { week_start: 5 }],
        top_reporters: null,
      },
    });
    const s = await getDashboardSummary({ month: 10, year: 2026 });
    expect(s.scope).toEqual({ key: "OWN_COUNTRY", label: "My country (AU)" });
    expect(s.reports).toBe(12);
    expect(s.outcomes).toEqual({ safe: 3, inconclusive: 0, suspicious: 0, dangerous: 0, failure: 0 });
    expect(s.in_progress).toBe(0);
    expect(s.by_type).toEqual({ MAIL: 0, FILE: 0, URL: 0, IP: 0, HASH: 0, IOC: 0, UNKNOWN: 0 });
    expect(s.previous).toEqual({
      reports: 0,
      outcomes: { safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0, failure: 0 },
    });
    expect(s.trend).toEqual([{ week_start: "2026-09-28", reports: 2 }]);
    expect(s.top_reporters).toBeNull();
  });

  it("keeps top_reporters for elevated payloads", async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: { top_reporters: [{ label: "elena.voss", value: 4 }, { label: "", value: 1 }] },
    });
    const s = await getDashboardSummary({ month: 10, year: 2026 });
    expect(s.top_reporters).toEqual([{ label: "elena.voss", value: 4 }]);
    expect(s.scope).toEqual({ key: "ALL", label: "Overall" });
  });

  it("normalises the scopes list and falls back to Overall", async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: { default: "OWN_COUNTRY", options: [{ key: "OWN_COUNTRY", label: "My country (AU)" }, { key: "ALL", label: "Overall" }, { nope: 1 }] },
    });
    expect(await getDashboardScopes()).toEqual({
      default: "OWN_COUNTRY",
      options: [{ key: "OWN_COUNTRY", label: "My country (AU)" }, { key: "ALL", label: "Overall" }],
    });
    expect(api.get).toHaveBeenCalledWith("/dashboard/scopes/");

    vi.mocked(api.get).mockResolvedValue({ data: {} });
    expect(await getDashboardScopes()).toEqual({ default: "ALL", options: [{ key: "ALL", label: "Overall" }] });
  });
});
