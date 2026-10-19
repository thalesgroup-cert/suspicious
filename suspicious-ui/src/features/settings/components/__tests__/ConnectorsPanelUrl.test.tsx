import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { page } from "@vitest/browser/context";

import { renderWithProviders } from "@/test/utils";
import { ConnectorsPanel } from "../ConnectorsPanel";

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
      { ...base, name: "chromadb" },
      { ...base, name: "misp" },
    ],
    load_errors: {},
  }),
  setConnectorEnabled: vi.fn(),
  getConnectorConfig: vi.fn().mockResolvedValue({ api_key: "" }),
  putConnectorConfig: vi.fn(),
  testConnector: vi.fn(),
  listDeliveries: vi.fn().mockResolvedValue([]),
}));

function setup(search: string) {
  return renderWithProviders(<ConnectorsPanel />, { routePath: "*", initialPath: `/settings/connectors${search}` });
}

describe("ConnectorsPanel selection in the URL", () => {
  beforeEach(async () => {
    await page.viewport(1280, 800);
  });

  it("opens the connector and tab named by a deep link", async () => {
    setup("?connector=misp&tab=deliveries");
    expect(await screen.findByRole("heading", { level: 3, name: "misp" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Deliveries" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("No deliveries yet.")).toBeInTheDocument();
  });

  it("falls back to the first connector for an unknown or missing name", async () => {
    const unknown = setup("?connector=nope");
    expect(await screen.findByRole("heading", { level: 3, name: "chromadb" })).toBeInTheDocument();
    unknown.unmount();
    setup("");
    expect(await screen.findByRole("heading", { level: 3, name: "chromadb" })).toBeInTheDocument();
  });

  it("writes the chosen connector to the URL, replacing history and keeping the other params", async () => {
    const { router } = setup("?tab=configuration&x=1");
    await screen.findByRole("heading", { level: 3, name: "chromadb" });
    const length = window.history.length;
    await userEvent.click(screen.getByRole("button", { name: /^misp/ }));
    expect(await screen.findByRole("heading", { level: 3, name: "misp" })).toBeInTheDocument();
    const params = new URLSearchParams(router!.state.location.search);
    expect(params.get("connector")).toBe("misp");
    expect(params.get("tab")).toBe("configuration");
    expect(params.get("x")).toBe("1");
    expect(window.history.length).toBe(length);
  });

  it("still asks before switching connector with a draft, and keeps the URL when cancelled", async () => {
    const { router } = setup("?connector=chromadb&tab=configuration");
    await userEvent.type(await screen.findByLabelText("API Key"), "abc");
    await userEvent.click(screen.getByRole("button", { name: /^misp/ }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Discard unsaved changes to chromadb?")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(new URLSearchParams(router!.state.location.search).get("connector")).toBe("chromadb");
    expect(((await screen.findByLabelText("API Key")) as HTMLInputElement).value).toBe("abc");

    await userEvent.click(screen.getByRole("button", { name: /^misp/ }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Discard" }));
    expect(await screen.findByRole("heading", { level: 3, name: "misp" })).toBeInTheDocument();
    expect(new URLSearchParams(router!.state.location.search).get("connector")).toBe("misp");
  });

  it("opens a deep-linked connector on a phone and Back returns to the list without the param", async () => {
    await page.viewport(390, 844);
    const { router } = setup("?connector=misp");
    expect(await screen.findByRole("heading", { level: 3, name: "misp" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Back to connector list" }));
    expect(await screen.findByRole("button", { name: /^chromadb/ })).toBeInTheDocument();
    expect(new URLSearchParams(router!.state.location.search).has("connector")).toBe(false);
  });
});
