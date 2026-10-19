import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { page } from "@vitest/browser/context";

import { renderWithProviders } from "@/test/utils";
import { ConnectorsPanel } from "../ConnectorsPanel";

// vi.mock is hoisted above plain consts, so the fixture must be hoisted with it.
const base = vi.hoisted(() => ({
  version: "1.0.0",
  description: "d",
  author: "a",
  docs_url: "",
  category: "Other",
  events: [],
  schedules: [],
  config_schema: [{ key: "api_key", type: "secret", required: false, default: null, help: "" }],
  enabled: true,
  enabled_by_default: false,
  status: "connected",
  last_health_ok: null,
  last_health_detail: "",
  last_health_at: null,
}));

vi.mock("../connectors", () => ({
  listConnectors: vi.fn().mockResolvedValue({
    connectors: [
      { ...base, name: "misp" },
      { ...base, name: "thehive" },
    ],
    load_errors: {},
  }),
  setConnectorEnabled: vi.fn(),
  getConnectorConfig: vi.fn().mockResolvedValue({ api_key: "" }),
  putConnectorConfig: vi.fn(),
  testConnector: vi.fn(),
  listDeliveries: vi.fn().mockResolvedValue([]),
}));

describe("ConnectorsPanel with an unsaved draft", () => {
  beforeEach(async () => {
    await page.viewport(1280, 800);
  });

  async function draftOnMisp() {
    renderWithProviders(<ConnectorsPanel />);
    const input = (await screen.findByLabelText("API Key")) as HTMLInputElement;
    await userEvent.type(input, "abc");
    return input;
  }

  it("switches straight away when there is no draft", async () => {
    renderWithProviders(<ConnectorsPanel />);
    await screen.findByLabelText("API Key");
    await userEvent.click(screen.getByText("thehive"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 3, name: "thehive" })).toBeInTheDocument();
  });

  it("asks before switching connector and keeps the draft when cancelled", async () => {
    const input = await draftOnMisp();
    await userEvent.click(screen.getByText("thehive"));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Discard unsaved changes to misp?")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(screen.getByRole("heading", { level: 3, name: "misp" })).toBeInTheDocument();
    expect(input.value).toBe("abc");
  });

  it("switches and drops the draft on Discard, without carrying it to the next connector", async () => {
    await draftOnMisp();
    await userEvent.click(screen.getByText("thehive"));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Discard" }));
    expect(await screen.findByRole("heading", { level: 3, name: "thehive" })).toBeInTheDocument();
    expect(((await screen.findByLabelText("API Key")) as HTMLInputElement).value).toBe("");
  });
});
