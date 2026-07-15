import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { renderWithProviders } from "@/test/utils";
import { ConnectorList } from "../ConnectorList";
import type { Connector } from "../connectors";

vi.mock("../connectors", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../connectors")>();
  return {
    ...actual,
    setConnectorEnabled: vi.fn().mockResolvedValue({ name: "misp", enabled: false }),
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
  config_schema: [],
  enabled: true,
  enabled_by_default: false,
  status: "connected",
  last_health_ok: true,
  last_health_detail: "ok",
  last_health_at: null,
};

function renderList(overrides: Partial<React.ComponentProps<typeof ConnectorList>> = {}) {
  return renderWithProviders(
    <ConnectorList
      connectors={[CONNECTOR]}
      loadErrors={{}}
      selected={null}
      onSelect={vi.fn()}
      {...overrides}
    />,
  );
}

describe("ConnectorList", () => {
  it("renders each connector under its category heading", () => {
    renderList();
    expect(screen.getByText("Threat Intelligence")).toBeInTheDocument();
    expect(screen.getByText("misp")).toBeInTheDocument();
  });

  it("calls onSelect when a connector row is clicked", async () => {
    const onSelect = vi.fn();
    renderList({ onSelect });
    await userEvent.click(screen.getByText("misp"));
    expect(onSelect).toHaveBeenCalledWith("misp");
  });

  it("shows the empty state when there are no connectors", () => {
    renderList({ connectors: [] });
    expect(screen.getByText("No connectors discovered.")).toBeInTheDocument();
  });

  it("toggles a connector's enabled state without navigating into it", async () => {
    const onSelect = vi.fn();
    renderList({ onSelect });
    await userEvent.click(screen.getByRole("switch", { name: "Enable misp" }));
    await waitFor(() => expect(onSelect).not.toHaveBeenCalled());
  });

  it("surfaces a load error as a warning alert", () => {
    renderList({ loadErrors: { watcher: "timeout" } });
    expect(screen.getByText(/Connector watcher failed to load: timeout/)).toBeInTheDocument();
  });

  it("disables the toggle switch while the enable/disable mutation is in flight", async () => {
    const { setConnectorEnabled } = await import("../connectors");
    let resolveMutation!: (value: Connector) => void;
    vi.mocked(setConnectorEnabled).mockReturnValueOnce(
      new Promise((resolve) => {
        resolveMutation = resolve;
      }),
    );
    renderList();
    const toggle = screen.getByRole("switch", { name: "Enable misp" });
    await userEvent.click(toggle);
    await waitFor(() => expect(toggle).toBeDisabled());
    resolveMutation({ ...CONNECTOR, enabled: false });
    await waitFor(() => expect(toggle).not.toBeDisabled());
  });
});
