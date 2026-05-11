import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";

// ---------------------------------------------------------------------------
// Module mocks (hoisted)
// ---------------------------------------------------------------------------

vi.mock("@/features/settings/api", () => ({
  getFeederHealth: vi.fn(),
}));

import { getFeederHealth } from "@/features/settings/api";
import FeederHealthBadge from "@/shared/components/FeederHealthBadge";

const mockHealth = vi.mocked(getFeederHealth);

const baseChecks = {
  imap: { ok: true, configured: 2, healthy: 2, last_ok: { m1: 1, m2: 1 } },
  minio: { ok: true, last_ok: 1 },
} as const;

describe("FeederHealthBadge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns null when disabled (non-Admin/CERT user)", () => {
    const { container } = renderWithProviders(<FeederHealthBadge enabled={false} />);
    expect(container).toBeEmptyDOMElement();
    expect(mockHealth).not.toHaveBeenCalled();
  });

  it("renders Online chip when feeder is healthy", async () => {
    mockHealth.mockResolvedValue({
      online: true,
      stale: false,
      stale_seconds: 30,
      last_successful_poll: Math.floor(Date.now() / 1000),
      emails_processed_total: 12,
      errors_total: 0,
      checks: baseChecks,
      checked_at: Math.floor(Date.now() / 1000),
      error: null,
    });

    renderWithProviders(<FeederHealthBadge />);

    await waitFor(() => {
      expect(screen.getByText(/Feeder: Online/i)).toBeInTheDocument();
    });
  });

  it("renders Stale chip when feeder responds but has not polled recently", async () => {
    mockHealth.mockResolvedValue({
      online: true,
      stale: true,
      stale_seconds: 600,
      last_successful_poll: Math.floor(Date.now() / 1000) - 600,
      emails_processed_total: 0,
      errors_total: 0,
      checks: baseChecks,
      checked_at: Math.floor(Date.now() / 1000),
      error: null,
    });

    renderWithProviders(<FeederHealthBadge />);

    await waitFor(() => {
      expect(screen.getByText(/Feeder: Stale/i)).toBeInTheDocument();
    });
  });

  it("renders Offline chip when /health is unreachable", async () => {
    mockHealth.mockResolvedValue({
      online: false,
      stale: false,
      stale_seconds: 0,
      last_successful_poll: null,
      emails_processed_total: 0,
      errors_total: 0,
      checks: undefined,
      error: "connection refused",
      checked_at: Math.floor(Date.now() / 1000),
    });

    renderWithProviders(<FeederHealthBadge />);

    await waitFor(() => {
      expect(screen.getByText(/Feeder: Offline/i)).toBeInTheDocument();
    });
  });

  it("renders Loading… chip before the first response", () => {
    mockHealth.mockImplementation(() => new Promise(() => {}));

    renderWithProviders(<FeederHealthBadge />);

    expect(screen.getByText(/Feeder: Loading/i)).toBeInTheDocument();
  });
});
