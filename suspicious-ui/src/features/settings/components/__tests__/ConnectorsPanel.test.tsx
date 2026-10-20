import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { page } from "@vitest/browser/context";

import { renderWithProviders } from "@/test/utils";
import { stubMatchMedia } from "@/test/matchMedia";
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
  last_health_ok: true,
  last_health_detail: "pong",
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

function setup(search = "") {
  return renderWithProviders(<ConnectorsPanel />, { routePath: "*", initialPath: `/settings/connectors${search}` });
}
const configure = (name: string) => screen.findByRole("button", { name: `Configure ${name}` });
const dialogs = () => screen.queryAllByRole("dialog");
const drawer = (name: string) => screen.findByRole("dialog", { name });
const connectorParam = (router: ReturnType<typeof setup>["router"]) => new URLSearchParams(router!.state.location.search).get("connector");

beforeEach(async () => {
  await page.viewport(1280, 800);
  stubMatchMedia();
});
afterEach(() => vi.unstubAllGlobals());

describe("the drawer follows the URL", () => {
  it("opens the connector and tab named by a deep link", async () => {
    setup("?connector=misp&tab=deliveries");
    const dialog = await drawer("misp");
    expect(within(dialog).getByRole("heading", { level: 2, name: "misp" })).toBeInTheDocument();
    expect(within(dialog).getByRole("tab", { name: "Deliveries" })).toHaveAttribute("aria-selected", "true");
    expect(await within(dialog).findByText("No deliveries yet.")).toBeInTheDocument();
  });

  it.each(["?connector=nope", ""])("opens nothing for an unknown or missing connector (%j)", async (search) => {
    setup(search);
    await configure("misp");
    expect(dialogs()).toHaveLength(0);
  });

  it("opens from Configure, writes the name to the URL, replaces history and keeps the other params", async () => {
    const { router } = setup("?tab=configuration&x=1");
    const length = window.history.length;
    await userEvent.click(await configure("misp"));
    expect(await drawer("misp")).toBeInTheDocument();
    const params = new URLSearchParams(router!.state.location.search);
    expect(params.get("connector")).toBe("misp");
    expect(params.get("tab")).toBe("configuration");
    expect(params.get("x")).toBe("1");
    expect(window.history.length).toBe(length);
  });

  it.each(["button", "escape", "backdrop"])("closing by %s removes the connector from the URL, keeping the rest", async (how) => {
    const { router } = setup("?connector=misp&tab=overview&x=1");
    const dialog = await drawer("misp");
    if (how === "button") await userEvent.click(within(dialog).getByRole("button", { name: "Close misp" }));
    else if (how === "escape") await userEvent.keyboard("{Escape}");
    else await userEvent.click(document.querySelector(".MuiBackdrop-root")!);
    await waitFor(() => expect(connectorParam(router)).toBeNull());
    expect(new URLSearchParams(router!.state.location.search).get("x")).toBe("1");
    await waitFor(() => expect(dialogs()).toHaveLength(0));
  });
});

describe("with an unsaved draft", () => {
  async function draftOnMisp() {
    const { router } = setup("?connector=misp&tab=configuration");
    const input = (await screen.findByLabelText("API Key")) as HTMLInputElement;
    await userEvent.type(input, "abc");
    return { router, input };
  }
  const confirm = () => screen.findByRole("dialog", { name: "Discard unsaved changes to misp?" });

  it.each(["button", "escape", "backdrop"])("asks before closing by %s and keeps the draft and the drawer when cancelled", async (how) => {
    const { router, input } = await draftOnMisp();
    if (how === "button") await userEvent.click(screen.getByRole("button", { name: "Close misp" }));
    else if (how === "escape") await userEvent.keyboard("{Escape}");
    else await userEvent.click(document.querySelector(".MuiBackdrop-root")!);
    const dialog = await confirm();
    expect(within(dialog).getByText("Your edits to this connector have not been saved and will be lost.")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: /Discard/ })).not.toBeInTheDocument());
    expect(connectorParam(router)).toBe("misp");
    expect(input.value).toBe("abc");
  });

  it("closes and drops the draft on Discard", async () => {
    const { router } = await draftOnMisp();
    await userEvent.click(screen.getByRole("button", { name: "Close misp" }));
    await userEvent.click(within(await confirm()).getByRole("button", { name: "Discard" }));
    await waitFor(() => expect(connectorParam(router)).toBeNull());
    await userEvent.click(await configure("misp"));
    expect(((await screen.findByLabelText("API Key")) as HTMLInputElement).value).toBe("");
  });

  it("asks before another connector's Configure replaces the open one, and keeps both URL and draft when cancelled", async () => {
    const { router, input } = await draftOnMisp();
    // The backdrop hides the gallery from users and assistive technology, but a script or a stale focus can still reach it.
    await userEvent.click(screen.getByRole("button", { name: "Configure chromadb", hidden: true }));
    await userEvent.click(within(await confirm()).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: /Discard/ })).not.toBeInTheDocument());
    expect(connectorParam(router)).toBe("misp");
    expect(input.value).toBe("abc");
  });

  it("switches on Discard without carrying the draft over, and keeps the title on the connector being left while it fades out", async () => {
    const { router } = await draftOnMisp();
    await userEvent.click(screen.getByRole("button", { name: "Configure chromadb", hidden: true }));
    await userEvent.click(within(await confirm()).getByRole("button", { name: "Discard" }));
    // No awaiting in between: the title must be right while the dialog is still fading out.
    expect(screen.queryByText("Discard unsaved changes to chromadb?")).not.toBeInTheDocument();
    expect(await drawer("chromadb")).toBeInTheDocument();
    expect(connectorParam(router)).toBe("chromadb");
    expect(((await screen.findByLabelText("API Key")) as HTMLInputElement).value).toBe("");
  });

  it("switches straight away when there is no draft", async () => {
    const { router } = setup("?connector=misp");
    await drawer("misp");
    await userEvent.click(screen.getByRole("button", { name: "Configure chromadb", hidden: true }));
    expect(await drawer("chromadb")).toBeInTheDocument();
    expect(connectorParam(router)).toBe("chromadb");
    expect(screen.queryByRole("dialog", { name: /Discard/ })).not.toBeInTheDocument();
  });
});

describe("focus", () => {
  it("moves into the drawer on open and returns to the Configure button on close", async () => {
    setup();
    const button = await configure("misp");
    await userEvent.click(button);
    const dialog = await drawer("misp");
    await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(dialogs()).toHaveLength(0));
    expect(button).toHaveFocus();
  });

  it("does not take focus when a deep link opens the drawer on first load", async () => {
    setup("?connector=misp");
    await drawer("misp");
    await new Promise((r) => setTimeout(r, 150));
    expect(document.activeElement).toBe(document.body);
  });
});

describe("size", () => {
  it("is 600px wide on a desktop", async () => {
    setup("?connector=misp");
    const dialog = await drawer("misp");
    await waitFor(() => expect(dialog.getBoundingClientRect().width).toBe(600));
  });

  it("fills the screen below md", async () => {
    await page.viewport(390, 800);
    stubMatchMedia({ phone: true });
    setup("?connector=misp");
    const dialog = await drawer("misp");
    await waitFor(() => expect(dialog.getBoundingClientRect().width).toBe(390));
    expect(dialog.getBoundingClientRect().height).toBe(800);
  });
});

describe("header", () => {
  it("shows logo, the name as the dialog title, version, status and when it was last checked", async () => {
    setup("?connector=misp");
    const dialog = await drawer("misp");
    expect(within(dialog).getByTestId("connector-logo")).toBeInTheDocument();
    expect(within(dialog).getByRole("heading", { level: 2, name: "misp" })).toBeInTheDocument();
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(within(dialog).getAllByText("1.0.0").length).toBeGreaterThan(0);
    expect(within(dialog).getAllByText("Connected").length).toBeGreaterThan(0);
    expect(within(dialog).getByText("Not checked yet")).toBeInTheDocument();
  });
});
