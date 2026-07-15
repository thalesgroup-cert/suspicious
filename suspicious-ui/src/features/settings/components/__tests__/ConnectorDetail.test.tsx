import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { renderWithProviders } from "@/test/utils";
import { ConnectorDetail } from "../ConnectorDetail";
import type { Connector } from "../connectors";

vi.mock("../connectors", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../connectors")>();
  return {
    ...actual,
    getConnectorConfig: vi.fn().mockResolvedValue({ api_key: "" }),
    putConnectorConfig: vi.fn(),
    testConnector: vi.fn().mockResolvedValue({ ok: true, detail: "reachable" }),
    listDeliveries: vi.fn().mockResolvedValue([
      {
        id: 1,
        event: "case_finalised",
        case_id: 42,
        status: "success",
        error: "",
        duration_ms: 120,
        attempt: 1,
        created_at: "2026-07-01T10:00:00Z",
      },
    ]),
  };
});

const CONNECTOR: Connector = {
  name: "misp",
  version: "1.0.0",
  description: "Push to MISP",
  author: "Thales CERT",
  docs_url: "",
  category: "Threat Intelligence",
  events: [],
  schedules: [],
  config_schema: [{ key: "api_key", type: "secret", required: false, default: null, help: "" }],
  enabled: true,
  enabled_by_default: false,
  status: "connected",
  last_health_ok: true,
  last_health_detail: "ok",
  last_health_at: null,
};

describe("ConnectorDetail", () => {
  it("renders connector identity and config fields", async () => {
    renderWithProviders(<ConnectorDetail connector={CONNECTOR} />);
    expect(screen.getByText("misp")).toBeInTheDocument();
    expect(await screen.findByLabelText("api_key")).toBeInTheDocument();
  });

  it("renders recent deliveries", async () => {
    renderWithProviders(<ConnectorDetail connector={CONNECTOR} />);
    expect(await screen.findByText(/case_finalised/)).toBeInTheDocument();
    expect(screen.getByText(/case #42/)).toBeInTheDocument();
  });

  it("shows the empty deliveries message when there are none", async () => {
    const { listDeliveries } = await import("../connectors");
    vi.mocked(listDeliveries).mockResolvedValueOnce([]);
    renderWithProviders(<ConnectorDetail connector={CONNECTOR} />);
    expect(await screen.findByText("No deliveries yet.")).toBeInTheDocument();
  });

  it("shows error alert when deliveries query fails", async () => {
    const { listDeliveries } = await import("../connectors");
    vi.mocked(listDeliveries).mockRejectedValueOnce(new Error("network error"));
    renderWithProviders(<ConnectorDetail connector={CONNECTOR} />);
    expect(await screen.findByText("Failed to load recent deliveries.")).toBeInTheDocument();
    expect(screen.queryByText("No deliveries yet.")).not.toBeInTheDocument();
  });

  it("shows a back button only when onBack is provided", () => {
    renderWithProviders(<ConnectorDetail connector={CONNECTOR} onBack={vi.fn()} />);
    expect(screen.getByLabelText("Back to connector list")).toBeInTheDocument();
  });

  it("omits the back button when onBack is not provided", () => {
    renderWithProviders(<ConnectorDetail connector={CONNECTOR} />);
    expect(screen.queryByLabelText("Back to connector list")).not.toBeInTheDocument();
  });

  it("enables Save only after a field is edited", async () => {
    renderWithProviders(<ConnectorDetail connector={CONNECTOR} />);
    const input = await screen.findByLabelText("api_key");
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    await userEvent.type(input, "secret-value");
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });
});
