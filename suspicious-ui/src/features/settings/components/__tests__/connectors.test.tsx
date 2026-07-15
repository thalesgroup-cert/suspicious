import { screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { page } from "@vitest/browser/context";

import { renderWithProviders } from "@/test/utils";
import { ConnectorsPanel } from "../ConnectorsPanel";

vi.mock("../connectors", () => ({
  listConnectors: vi.fn().mockResolvedValue({
    connectors: [
      {
        name: "misp",
        version: "1.0.0",
        description: "Push to MISP",
        author: "Thales CERT",
        docs_url: "",
        category: "Threat Intelligence",
        events: ["case_finalised"],
        schedules: [],
        config_schema: [
          { key: "instances.primary.url", type: "url", required: true, default: null, help: "" },
          { key: "api_key", type: "secret", required: false, default: null, help: "" },
        ],
        enabled: true,
        enabled_by_default: false,
        status: "connected",
        last_health_ok: true,
        last_health_detail: "ok",
        last_health_at: null,
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
  // This project's Vitest browser-mode default viewport is mobile-sized
  // (~414px wide), below MUI's md breakpoint — these tests exercise the
  // desktop two-pane path, so force a desktop viewport before each render.
  beforeEach(async () => {
    await page.viewport(1280, 800);
  });

  it("renders discovered connectors in the list with version and toggle", async () => {
    renderWithProviders(<ConnectorsPanel />);
    await waitFor(() => expect(screen.getByText("misp")).toBeInTheDocument());
    // Version chip lives in ConnectorDetail, which mounts only after the
    // auto-select effect fires — an extra render pass after "misp" is
    // already visible in the list, so this needs an async find, not getBy.
    expect(await screen.findByText(/1\.0\.0/)).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Enable misp" })).toBeChecked();
  });

  it("groups the connector under its category heading", async () => {
    renderWithProviders(<ConnectorsPanel />);
    await waitFor(() => expect(screen.getByText("Threat Intelligence")).toBeInTheDocument());
  });

  it("auto-selects the first connector on desktop and shows its editable fields", async () => {
    renderWithProviders(<ConnectorsPanel />);
    const input = (await screen.findByLabelText("api_key")) as HTMLInputElement;
    expect(input).not.toBeDisabled();
    expect(input.type).toBe("password");
  });

  it("does not render KPI count tiles", async () => {
    renderWithProviders(<ConnectorsPanel />);
    await waitFor(() => expect(screen.getByText("misp")).toBeInTheDocument());
    expect(screen.queryByText("Connected")).not.toBeInTheDocument();
    expect(screen.queryByText("Incomplete")).not.toBeInTheDocument();
    expect(screen.queryByText("Disabled")).not.toBeInTheDocument();
  });
});
