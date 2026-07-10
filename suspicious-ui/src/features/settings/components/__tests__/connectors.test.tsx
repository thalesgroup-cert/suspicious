import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ConnectorsPanel } from "../ConnectorsPanel";

vi.mock("../connectors", () => ({
  listConnectors: vi.fn().mockResolvedValue({
    connectors: [
      {
        name: "misp", version: "1.0.0", description: "Push to MISP",
        author: "Thales CERT", docs_url: "", category: "Threat Intelligence",
        events: ["case_finalised"],
        schedules: [], config_schema: [
          { key: "instances.primary.url", type: "url", required: true, default: null, help: "" },
          { key: "api_key", type: "secret", required: false, default: null, help: "" },
        ],
        enabled: true, enabled_by_default: false, status: "connected",
        last_health_ok: true, last_health_detail: "ok", last_health_at: null,
      },
    ],
    load_errors: {},
  }),
  setConnectorEnabled: vi.fn(),
  getConnectorConfig: vi.fn().mockResolvedValue({}),
  putConnectorConfig: vi.fn(),
  testConnector: vi.fn(),
  listDeliveries: vi.fn().mockResolvedValue([]),
}));

describe("ConnectorsPanel", () => {
  it("renders secret fields as editable password inputs", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <ConnectorsPanel />
      </QueryClientProvider>,
    );
    const input = (await screen.findByLabelText("api_key")) as HTMLInputElement;
    expect(input).not.toBeDisabled();
    expect(input.type).toBe("password");
  });

  it("renders discovered connectors with version and toggle", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <ConnectorsPanel />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByText("misp")).toBeInTheDocument());
    expect(screen.getByText(/1\.0\.0/)).toBeInTheDocument();
    expect(screen.getByRole("switch")).toBeChecked();
  });

  it("shows a KPI row with the connected count", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <ConnectorsPanel />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByText("Incomplete")).toBeInTheDocument());
    expect(screen.getByText("Disabled")).toBeInTheDocument();
    expect(screen.getAllByText("Connected")).toHaveLength(2);
    expect(screen.getAllByText("1").length).toBeGreaterThan(0);
  });

  it("groups the connector card under its category heading", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <ConnectorsPanel />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByText("Threat Intelligence")).toBeInTheDocument());
  });
});
