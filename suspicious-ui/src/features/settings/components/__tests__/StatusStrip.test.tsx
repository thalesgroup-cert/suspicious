import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen, within } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
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
    expect(await screen.findByText("Running")).toBeInTheDocument();
    expect(await screen.findByText("2 of 3 enabled, 1 unhealthy")).toBeInTheDocument();
    expect(await screen.findByText("2 of 3 active")).toBeInTheDocument();
    const hrefs = screen.getAllByRole("link").map((a) => a.getAttribute("href"));
    expect(hrefs).toEqual(["/settings/email_feeder", "/settings/connectors", "/settings/scoring"]);
  });

  it("says stopped when the feeder is disabled", async () => {
    vi.mocked(getFeederStatus).mockResolvedValue({ enabled: false });
    renderWithProviders(<StatusStrip />);
    expect(await screen.findByText("Stopped")).toBeInTheDocument();
  });

  it("shows 'unavailable' for one failed cell while the others render", async () => {
    vi.mocked(listConnectors).mockRejectedValue(new Error("403"));
    renderWithProviders(<StatusStrip />);
    expect(await screen.findByText("2 of 3 active")).toBeInTheDocument();
    const cell = screen.getByRole("link", { name: /connectors/i });
    expect(await within(cell).findByText("unavailable")).toBeInTheDocument();
    expect(screen.getAllByText("unavailable")).toHaveLength(1);
  });
});
