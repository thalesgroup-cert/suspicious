import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { page } from "@vitest/browser/context";

import { renderWithProviders } from "@/test/utils";
import { ConnectorDrawer } from "../ConnectorDrawer";
import type { ConfigField, Connector } from "../connectors";

vi.mock("../connectors", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../connectors")>();
  return {
    ...actual,
    getConnectorConfig: vi.fn().mockResolvedValue({ url: "", api_key: "********", name: "" }),
    putConnectorConfig: vi.fn(),
    testConnector: vi.fn().mockResolvedValue({ ok: true, detail: "reachable" }),
    listDeliveries: vi.fn().mockResolvedValue([]),
  };
});

const field = (key: string, over: Partial<ConfigField> = {}): ConfigField => ({ key, type: "str", required: false, default: null, help: "", ...over });
const CONNECTOR: Connector = {
  name: "misp",
  version: "1.0.0",
  description: "Push to MISP",
  author: "",
  docs_url: "",
  category: "Threat intelligence",
  events: [],
  schedules: [],
  config_schema: [
    field("url", { type: "url", required: true }),
    field("api_key", { type: "secret", required: true }),
    field("name", { required: true }),
    field("timeout", { type: "int" }),
  ],
  enabled: true,
  enabled_by_default: false,
  status: "partial",
  last_health_ok: null,
  last_health_detail: "",
  last_health_at: null,
};

function open(connector: Connector = CONNECTOR) {
  return renderWithProviders(<ConnectorDrawer connector={connector} onClose={vi.fn()} />, { initialPath: "/settings/connectors?tab=configuration" });
}
const checklist = () => screen.findByRole("group", { name: "Setup checklist" });

beforeEach(async () => {
  await page.viewport(1280, 900);
});

describe("setup checklist", () => {
  it("says how many of the required settings are missing and lists them as buttons, counting a stored secret as present", async () => {
    open();
    const box = await checklist();
    expect(box).toHaveTextContent("2 of 3 required settings missing");
    expect(within(box).getAllByRole("button").map((b) => b.textContent)).toEqual(["URL", "Name"]);
  });

  it("uses the singular for one missing setting", async () => {
    const { getConnectorConfig } = await import("../connectors");
    vi.mocked(getConnectorConfig).mockResolvedValueOnce({ url: "u", api_key: "********", name: "" });
    open();
    expect(await checklist()).toHaveTextContent("1 of 3 required settings missing");
  });

  it("moves focus to the field when an item is pressed", async () => {
    open();
    await userEvent.click(within(await checklist()).getByRole("button", { name: "Name" }));
    expect(screen.getByLabelText(/^Name/)).toHaveFocus();
  });

  it("is hidden when nothing is missing", async () => {
    const { getConnectorConfig } = await import("../connectors");
    vi.mocked(getConnectorConfig).mockResolvedValueOnce({ url: "u", api_key: "********", name: "n" });
    open();
    await screen.findByLabelText(/^URL/);
    expect(screen.queryByRole("group", { name: "Setup checklist" })).not.toBeInTheDocument();
  });

  it("is hidden for a connector with no required settings", async () => {
    open({ ...CONNECTOR, config_schema: [field("timeout")] });
    await screen.findByLabelText("Timeout");
    expect(screen.queryByRole("group", { name: "Setup checklist" })).not.toBeInTheDocument();
  });

  it("is computed from the saved config: typing a value does not hide an item until it is saved", async () => {
    open();
    await userEvent.type(await screen.findByLabelText(/^URL/), "https://x");
    expect(await checklist()).toHaveTextContent("2 of 3 required settings missing");
  });

  it("updates after a successful save", async () => {
    const { putConnectorConfig, getConnectorConfig } = await import("../connectors");
    const after = { url: "https://x", api_key: "********", name: "n" };
    vi.mocked(putConnectorConfig).mockResolvedValueOnce(after);
    // The refetch after saving must see the saved values too.
    vi.mocked(getConnectorConfig).mockResolvedValueOnce({ url: "", api_key: "********", name: "" }).mockResolvedValue(after);
    open();
    await userEvent.type(await screen.findByLabelText(/^URL/), "https://x");
    await userEvent.type(screen.getByLabelText(/^Name/), "n");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(screen.queryByRole("group", { name: "Setup checklist" })).not.toBeInTheDocument());
  });
});

describe("after saving", () => {
  async function save() {
    const { putConnectorConfig } = await import("../connectors");
    vi.mocked(putConnectorConfig).mockResolvedValueOnce({ url: "https://x", api_key: "********", name: "n" });
    open();
    await userEvent.type(await screen.findByLabelText(/^URL/), "https://x");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    return await screen.findByText("Saved. Run a test now?");
  }

  it("offers to run a test, which calls testConnector and then shows the result", async () => {
    const { testConnector } = await import("../connectors");
    vi.mocked(testConnector).mockClear();
    const row = await save();
    await userEvent.click(within(row.closest("[data-saved-row]") as HTMLElement).getByRole("button", { name: "Test now" }));
    expect(testConnector).toHaveBeenCalledWith("misp");
    expect(await screen.findByRole("alert")).toHaveTextContent("OK: reachable");
    expect(screen.queryByText("Saved. Run a test now?")).not.toBeInTheDocument();
  });

  it("can be dismissed", async () => {
    const row = await save();
    await userEvent.click(within(row.closest("[data-saved-row]") as HTMLElement).getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("Saved. Run a test now?")).not.toBeInTheDocument();
  });

  it("goes away when the next edit starts", async () => {
    await save();
    await userEvent.type(screen.getByLabelText(/^URL/), "y");
    expect(screen.queryByText("Saved. Run a test now?")).not.toBeInTheDocument();
  });
});
