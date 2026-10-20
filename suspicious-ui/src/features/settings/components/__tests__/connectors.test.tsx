import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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
  // Vitest's browser default viewport is mobile-sized (~414px); the gallery is the same at any width but the drawer is not.
  beforeEach(async () => {
    await page.viewport(1280, 800);
  });

  it("renders a discovered connector as a tile with logo, name, category, status and enable switch", async () => {
    renderWithProviders(<ConnectorsPanel />);
    const heading = await screen.findByRole("heading", { level: 3, name: "misp" });
    const tile = heading.closest("li")!;
    expect(within(tile).getByTestId("connector-logo")).toBeInTheDocument();
    expect(within(tile).getByText("Threat Intelligence")).toBeInTheDocument();
    expect(within(tile).getByText("Connected")).toBeInTheDocument();
    expect(within(tile).getByRole("switch", { name: "Enable misp" })).toBeChecked();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("opens the configuration drawer from Configure and shows the version and the editable fields", async () => {
    renderWithProviders(<ConnectorsPanel />, { initialPath: "/settings/connectors?tab=configuration" });
    await userEvent.click(await screen.findByRole("button", { name: "Configure misp" }));
    const dialog = await screen.findByRole("dialog", { name: "misp" });
    expect(within(dialog).getAllByText("1.0.0").length).toBeGreaterThan(0);
    // The API key is optional in this fixture, so it sits behind the group's disclosure.
    await userEvent.click(await within(dialog).findByRole("button", { name: /Show optional settings/ }));
    const input = (await within(dialog).findByLabelText("API Key")) as HTMLInputElement;
    expect(input).not.toBeDisabled();
    expect(input.type).toBe("password");
  });

  it("filters with status chips, not count tiles: each chip is a toggle button and the counts add up", async () => {
    renderWithProviders(<ConnectorsPanel />);
    await screen.findByRole("heading", { level: 3, name: "misp" });
    expect(screen.getByRole("button", { name: /^All\s*1$/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /^Connected\s*1$/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Incomplete\s*0$/ })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^Disabled/ }));
    await waitFor(() => expect(screen.queryByRole("heading", { level: 3, name: "misp" })).not.toBeInTheDocument());
  });
});
