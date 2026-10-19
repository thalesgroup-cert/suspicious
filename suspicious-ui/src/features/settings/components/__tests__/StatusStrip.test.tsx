import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen, within } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
import type { FeederHealth } from "@/features/settings/api";
import { StatusStrip } from "../StatusStrip";

vi.mock("@/features/settings/api", () => ({
  getFeederStatus: vi.fn(),
  getFeederHealth: vi.fn(),
  listAnalyzers: vi.fn(),
}));
vi.mock("../connectors", () => ({ listConnectors: vi.fn() }));

import { getFeederHealth, getFeederStatus, listAnalyzers } from "@/features/settings/api";
import { listConnectors } from "../connectors";

const conn = (name: string, enabled: boolean, ok: boolean | null) => ({
  name,
  enabled,
  last_health_ok: ok,
});

describe("StatusStrip", () => {
  beforeEach(() => {
    vi.mocked(getFeederHealth).mockClear();
    vi.mocked(getFeederStatus).mockResolvedValue({ enabled: true });
    vi.mocked(getFeederHealth).mockResolvedValue({ online: true, last_successful_poll: null, emails_processed_total: 0, errors_total: 0, stale_seconds: 0, stale: false, checked_at: 0, error: null });
    vi.mocked(listConnectors).mockResolvedValue({
      connectors: [conn("a", true, true), conn("b", true, false), conn("c", false, null)],
      load_errors: {},
    } as never);
    vi.mocked(listAnalyzers).mockResolvedValue([
      { id: 1, name: "x", weight: 1, analyzer_cortex_id: "x", is_active: true },
      { id: 2, name: "y", weight: 1, analyzer_cortex_id: "y", is_active: false },
      { id: 3, name: "z", weight: 1, analyzer_cortex_id: "z", is_active: true },
    ]);
  });

  it("renders the three facts, each linking to its section", async () => {
    renderWithProviders(<StatusStrip />);
    expect(await screen.findByText("Enabled")).toBeInTheDocument();
    expect(await screen.findByText("2 of 3 enabled, 1 unhealthy")).toBeInTheDocument();
    expect(await screen.findByText("2 of 3 active")).toBeInTheDocument();
    const hrefs = screen.getAllByRole("link").map((a) => a.getAttribute("href"));
    expect(hrefs).toEqual(["/settings/email_feeder", "/settings/connectors", "/settings/scoring"]);
  });

  it("says disabled when the feeder is disabled", async () => {
    vi.mocked(getFeederStatus).mockResolvedValue({ enabled: false });
    renderWithProviders(<StatusStrip />);
    expect(await screen.findByText("Disabled")).toBeInTheDocument();
  });

  it("shows 'unavailable' for one failed cell while the others render", async () => {
    vi.mocked(listConnectors).mockRejectedValue(new Error("403"));
    renderWithProviders(<StatusStrip />);
    expect(await screen.findByText("2 of 3 active")).toBeInTheDocument();
    const cell = screen.getByRole("link", { name: /connectors/i });
    expect(await within(cell).findByText("unavailable")).toBeInTheDocument();
    expect(screen.getAllByText("unavailable")).toHaveLength(1);
  });

  const base: FeederHealth = { online: true, last_successful_poll: null, emails_processed_total: 0, errors_total: 0, stale_seconds: 0, stale: false, checked_at: 0, error: null };
  it.each([
    ["Online", "ok", base],
    ["Stale", "warning", { ...base, stale: true }],
    ["Offline", "danger", { ...base, online: false, error: "http_500" }],
  ] as const)("shows health %s as an icon and word with tone %s, not a chip", async (word, tone, payload) => {
    vi.mocked(getFeederHealth).mockResolvedValue({ ...payload });
    renderWithProviders(<StatusStrip />);
    const label = await screen.findByText(word);
    expect(label.closest(".MuiChip-root")).toBeNull();
    expect(label.parentElement!.querySelector("svg")).toHaveAttribute("data-tone", tone);
    expect(screen.getByText("Enabled")).toBeInTheDocument();
  });

  it("says Checking while the health loads and keeps the cell alive when it fails", async () => {
    vi.mocked(getFeederHealth).mockRejectedValue(new Error("boom"));
    renderWithProviders(<StatusStrip />);
    expect(await screen.findByText("Status unavailable")).toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
    expect(screen.queryByText("unavailable")).toBeNull();
  });

  it("makes one health request", async () => {
    renderWithProviders(<StatusStrip />);
    await screen.findByText("Online");
    expect(getFeederHealth).toHaveBeenCalledTimes(1);
  });
});
