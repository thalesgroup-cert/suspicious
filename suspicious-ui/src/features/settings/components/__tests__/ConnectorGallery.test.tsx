import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { page } from "@vitest/browser/context";

import { renderWithProviders } from "@/test/utils";
import { themes } from "@/styles/themes";
import { contrastRatio, flatten } from "@/shared/lib/contrast";
import { ConnectorGallery } from "../ConnectorGallery";
import type { Connector } from "../connectors";

vi.mock("../connectors", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../connectors")>();
  return {
    ...actual,
    setConnectorEnabled: vi.fn().mockResolvedValue({ name: "misp", enabled: false }),
    testConnector: vi.fn().mockResolvedValue({ ok: true, detail: "reachable" }),
  };
});
vi.mock("notistack", async (importOriginal) => {
  const actual = await importOriginal<typeof import("notistack")>();
  const enqueue = vi.fn();
  return { ...actual, useSnackbar: () => ({ enqueueSnackbar: enqueue, closeSnackbar: vi.fn() }), __enqueue: enqueue };
});

const make = (name: string, over: Partial<Connector> = {}): Connector => ({
  name,
  version: "1.0.0",
  description: `${name} pushes things. See docs/specs/x.md.`,
  author: "",
  docs_url: "",
  category: "Threat intelligence",
  events: [],
  schedules: [],
  config_schema: [],
  enabled: true,
  enabled_by_default: false,
  status: "connected",
  last_health_ok: true,
  last_health_detail: "",
  last_health_at: null,
  ...over,
});

const LIST = [
  make("misp"),
  make("thehive", { category: "Incident response", status: "partial", last_health_ok: null }),
  make("chromadb", { category: "Maintenance", last_health_ok: false }),
  make("watcher", { category: "Threat intelligence", status: "disabled", enabled: false }),
  make("smtp_notify", { category: "Notifications" }),
];

function renderGallery(over: Partial<React.ComponentProps<typeof ConnectorGallery>> = {}) {
  const onConfigure = vi.fn();
  const view = renderWithProviders(
    <ConnectorGallery connectors={LIST} loadErrors={{}} loading={false} error={false} onRetry={vi.fn()} onConfigure={onConfigure} {...over} />,
  );
  return { ...view, onConfigure };
}

const tileOf = (name: string) => screen.getByRole("heading", { name }).closest("li")!;

beforeEach(async () => {
  await page.viewport(1280, 900);
});

describe("tiles", () => {
  it("shows logo or fallback, name, category, cleaned description and a status word on every tile", () => {
    renderGallery();
    expect(screen.getAllByTestId("connector-logo")).toHaveLength(5);
    const tile = tileOf("misp");
    expect(within(tile).getByText("Threat intelligence")).toBeInTheDocument();
    expect(within(tile).getByText("misp pushes things.")).toBeInTheDocument();
    expect(within(tile).getByText("Connected")).toBeInTheDocument();
    expect(within(tileOf("thehive")).getByText("Incomplete")).toBeInTheDocument();
    expect(within(tileOf("chromadb")).getByText("Unhealthy")).toBeInTheDocument();
    expect(within(tileOf("watcher")).getByText("Disabled")).toBeInTheDocument();
    expect(screen.queryByText(/docs\/specs/)).not.toBeInTheDocument();
  });

  it("names the tile with an h3 when not grouped", () => {
    renderGallery();
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual(LIST.map((c) => c.name));
  });

  it("gives each tile one Configure, one Test and one enable switch with unique names", () => {
    renderGallery();
    for (const c of LIST) {
      const tile = tileOf(c.name);
      expect(within(tile).getAllByRole("button", { name: `Configure ${c.name}` })).toHaveLength(1);
      expect(within(tile).getAllByRole("button", { name: `Test ${c.name}` })).toHaveLength(1);
      expect(within(tile).getAllByRole("switch", { name: `Enable ${c.name}` })).toHaveLength(1);
    }
    expect(screen.getAllByRole("button", { name: /^Configure / })).toHaveLength(LIST.length);
  });

  it("does not make the tile a click target and nests no control inside another or inside the body", () => {
    const { onConfigure } = renderGallery();
    const tile = tileOf("misp");
    expect(tile.querySelectorAll("button button, button a, a button, button input, a a").length).toBe(0);
    const body = tile.querySelector("[data-tile-body]")!;
    expect(body.querySelectorAll("button, a, input, [role=button], [role=switch]").length).toBe(0);
    return userEvent.click(body).then(() => expect(onConfigure).not.toHaveBeenCalled());
  });

  it("calls onConfigure with the connector name", async () => {
    const { onConfigure } = renderGallery();
    await userEvent.click(screen.getByRole("button", { name: "Configure thehive" }));
    expect(onConfigure).toHaveBeenCalledWith("thehive");
  });

  it("keeps the tile tab order the same as the visual order", async () => {
    renderGallery();
    const user = userEvent.setup();
    screen.getByRole("button", { name: "Configure misp" }).focus();
    await user.tab();
    expect(screen.getByRole("switch", { name: "Enable thehive" })).toHaveFocus();
  });
});

describe("enable switch", () => {
  it("saves at once", async () => {
    const { setConnectorEnabled } = await import("../connectors");
    renderGallery();
    await userEvent.click(screen.getByRole("switch", { name: "Enable misp" }));
    expect(setConnectorEnabled).toHaveBeenCalledWith("misp", false);
  });

  it("is disabled while its request runs and a failure shows the same toast as before", async () => {
    const { setConnectorEnabled } = await import("../connectors");
    const notistack = (await import("notistack")) as unknown as { __enqueue: ReturnType<typeof vi.fn> };
    let reject!: (e: unknown) => void;
    vi.mocked(setConnectorEnabled).mockReturnValueOnce(new Promise((_r, rej) => { reject = rej; }));
    renderGallery();
    const toggle = screen.getByRole("switch", { name: "Enable misp" });
    await userEvent.click(toggle);
    await waitFor(() => expect(toggle).toBeDisabled());
    reject(new Error("x"));
    await waitFor(() => expect(notistack.__enqueue).toHaveBeenCalledWith("Failed to update connector.", { variant: "error" }));
    await waitFor(() => expect(toggle).not.toBeDisabled());
  });
});

describe("Test on a tile", () => {
  // The result sits in one always-mounted polite status per tile, so a screen reader hears it appear.
  const statusOf = (name: string) => within(tileOf(name)).getByRole("status");

  it("shows a spinner while running, then an inline status with the saved-configuration wording", async () => {
    const { testConnector } = await import("../connectors");
    let resolve!: (v: { ok: boolean; detail: string }) => void;
    vi.mocked(testConnector).mockReturnValueOnce(new Promise((r) => { resolve = r; }));
    renderGallery();
    const tile = tileOf("misp");
    expect(statusOf("misp")).toBeEmptyDOMElement();
    await userEvent.click(within(tile).getByRole("button", { name: "Test misp" }));
    const busy = await within(tile).findByRole("button", { name: /^Testing/ });
    expect(busy).toHaveTextContent("Testing...");
    expect(busy.querySelector("[role=progressbar]")).not.toBeNull();
    resolve({ ok: true, detail: "reachable" });
    await waitFor(() => expect(statusOf("misp")).toHaveTextContent("Tested the saved configuration: OK: reachable"));
    expect(statusOf("misp").querySelector("[aria-live], [role=alert], [role=status]")).toBeNull();
    expect(within(tile).getByRole("button", { name: "Test misp" })).toBeInTheDocument();
  });

  it("shows the HTTP status of a rejected request and a server failure", async () => {
    const { testConnector } = await import("../connectors");
    vi.mocked(testConnector).mockRejectedValueOnce({ response: { status: 502, data: {} } });
    renderGallery();
    await userEvent.click(within(tileOf("misp")).getByRole("button", { name: "Test misp" }));
    await waitFor(() => expect(statusOf("misp")).toHaveTextContent("Connection test failed (HTTP 502)."));
    vi.mocked(testConnector).mockResolvedValueOnce({ ok: false, detail: "401 from MISP" });
    await userEvent.click(within(tileOf("misp")).getByRole("button", { name: "Test misp" }));
    expect(await within(tileOf("misp")).findByText(/Failed: 401 from MISP/)).toBeInTheDocument();
    expect(within(tileOf("misp")).queryByText(/HTTP 502/)).not.toBeInTheDocument();
  });

  it("can be dismissed and does not leak to other tiles", async () => {
    renderGallery();
    await userEvent.click(within(tileOf("misp")).getByRole("button", { name: "Test misp" }));
    await waitFor(() => expect(statusOf("misp")).toHaveTextContent("reachable"));
    expect(statusOf("thehive")).toBeEmptyDOMElement();
    await userEvent.click(within(statusOf("misp")).getByRole("button", { name: "Dismiss test result for misp" }));
    expect(statusOf("misp")).toBeEmptyDOMElement();
  });

  it("is kept when the filter or the grouping takes the tile off the screen and brings it back", async () => {
    renderGallery();
    await userEvent.click(screen.getByRole("button", { name: /^Connected/ }));
    await userEvent.click(within(tileOf("misp")).getByRole("button", { name: "Test misp" }));
    await waitFor(() => expect(statusOf("misp")).toHaveTextContent("reachable"));
    // misp leaves the list (the status chip changes), then returns.
    await userEvent.click(screen.getByRole("button", { name: /^Disabled/ }));
    expect(screen.queryByRole("heading", { name: "misp" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^Connected/ }));
    expect(statusOf("misp")).toHaveTextContent("Tested the saved configuration: OK: reachable");
    // Grouping rebuilds the tiles under category headings.
    await userEvent.click(screen.getByRole("switch", { name: "Group by category" }));
    expect(statusOf("misp")).toHaveTextContent("OK: reachable");
    // Dismissing clears it for good.
    await userEvent.click(within(statusOf("misp")).getByRole("button", { name: "Dismiss test result for misp" }));
    await userEvent.click(screen.getByRole("switch", { name: "Group by category" }));
    expect(statusOf("misp")).toBeEmptyDOMElement();
  });

  it("keeps a long result readable: clamped, with a Show full result button that expands it", async () => {
    const { testConnector } = await import("../connectors");
    const long = "HTTPSConnectionPool(host='misp.example', port=443): " + "x".repeat(260);
    vi.mocked(testConnector).mockResolvedValueOnce({ ok: false, detail: long });
    renderGallery();
    await userEvent.click(within(tileOf("misp")).getByRole("button", { name: "Test misp" }));
    const more = await within(tileOf("misp")).findByRole("button", { name: "Show full result for misp" });
    expect(more).toHaveAttribute("aria-expanded", "false");
    const text = within(statusOf("misp")).getByText(/^Tested the saved configuration/);
    expect(getComputedStyle(text).webkitLineClamp).toBe("4");
    await userEvent.click(more);
    expect(within(tileOf("misp")).getByRole("button", { name: "Show full result for misp" })).toHaveAttribute("aria-expanded", "true");
    expect(getComputedStyle(text).webkitLineClamp).toBe("none");
  });

  it("offers no expand button for a short result", async () => {
    renderGallery();
    await userEvent.click(within(tileOf("misp")).getByRole("button", { name: "Test misp" }));
    await waitFor(() => expect(statusOf("misp")).toHaveTextContent("reachable"));
    expect(within(tileOf("misp")).queryByRole("button", { name: /Show full result/ })).not.toBeInTheDocument();
  });
});

describe("filter bar", () => {
  it("shows counts over all connectors and All is pressed by default", () => {
    renderGallery();
    const pressed = (name: RegExp) => screen.getByRole("button", { name });
    expect(pressed(/^All\s*5$/)).toHaveAttribute("aria-pressed", "true");
    expect(pressed(/^Connected\s*2$/)).toHaveAttribute("aria-pressed", "false");
    expect(pressed(/^Incomplete\s*1$/)).toBeInTheDocument();
    expect(pressed(/^Unhealthy\s*1$/)).toBeInTheDocument();
    expect(pressed(/^Disabled\s*1$/)).toBeInTheDocument();
  });

  it("filters by status, sets aria-pressed and toggles back to All", async () => {
    renderGallery();
    await userEvent.click(screen.getByRole("button", { name: /^Unhealthy/ }));
    expect(screen.getByRole("button", { name: /^Unhealthy/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /^All/ })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual(["chromadb"]);
    await userEvent.click(screen.getByRole("button", { name: /^Unhealthy/ }));
    expect(screen.getByRole("button", { name: /^All/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getAllByRole("heading", { level: 3 })).toHaveLength(5);
  });

  it("searches name, category and description, and keeps the counts over all connectors", async () => {
    renderGallery();
    await userEvent.type(screen.getByRole("searchbox", { name: "Search connectors" }), "incident");
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual(["thehive"]);
    expect(screen.getByRole("button", { name: /^All\s*5$/ })).toBeInTheDocument();
  });

  it("is operable from the keyboard", async () => {
    renderGallery();
    const user = userEvent.setup();
    screen.getByRole("button", { name: /^Disabled/ }).focus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("button", { name: /^Disabled/ })).toHaveAttribute("aria-pressed", "true");
    await user.keyboard(" ");
    expect(screen.getByRole("button", { name: /^Disabled/ })).toHaveAttribute("aria-pressed", "false");
  });

  it("shows an empty state with Clear filters that resets the search and the status", async () => {
    renderGallery();
    await userEvent.click(screen.getByRole("button", { name: /^Disabled/ }));
    await userEvent.type(screen.getByRole("searchbox", { name: "Search connectors" }), "zzz");
    expect(screen.getByText("No connectors match these filters.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getAllByRole("heading", { level: 3 })).toHaveLength(5);
    expect(screen.getByRole("searchbox", { name: "Search connectors" })).toHaveValue("");
    expect(screen.getByRole("button", { name: /^All/ })).toHaveAttribute("aria-pressed", "true");
  });
});

describe("group by category", () => {
  it("is off by default and, when on, makes category headings h3 and tile names h4 in first-appearance order", async () => {
    renderGallery();
    const toggle = screen.getByRole("switch", { name: "Group by category" });
    expect(toggle).not.toBeChecked();
    await userEvent.click(toggle);
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual([
      "Threat intelligence",
      "Incident response",
      "Maintenance",
      "Notifications",
    ]);
    expect(screen.getAllByRole("heading", { level: 4 }).map((h) => h.textContent)).toEqual(["misp", "watcher", "thehive", "chromadb", "smtp_notify"]);
    const levels = screen.getAllByRole("heading").map((h) => Number(h.tagName[1]));
    levels.slice(1).forEach((l, i) => expect(l - levels[i]).toBeLessThanOrEqual(1));
  });

  it("composes with the status filter", async () => {
    renderGallery();
    await userEvent.click(screen.getByRole("switch", { name: "Group by category" }));
    await userEvent.click(screen.getByRole("button", { name: /^Disabled/ }));
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual(["Threat intelligence"]);
    expect(screen.getAllByRole("heading", { level: 4 }).map((h) => h.textContent)).toEqual(["watcher"]);
  });
});

describe("loading, error and load errors", () => {
  it("shows six skeleton tiles and no connectors while loading", () => {
    renderGallery({ loading: true, connectors: [] });
    expect(screen.getAllByTestId("tile-skeleton")).toHaveLength(6);
    expect(screen.queryByRole("searchbox")).not.toBeInTheDocument();
  });

  it("keeps the error message and offers Retry", async () => {
    const onRetry = vi.fn();
    renderGallery({ error: true, connectors: [], onRetry });
    expect(screen.getByText("Failed to load connectors.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalled();
  });

  it("says so when no connector was discovered", () => {
    renderGallery({ connectors: [] });
    expect(screen.getByText("No connectors discovered.")).toBeInTheDocument();
  });

  it("surfaces a connector that failed to load as a warning", () => {
    renderGallery({ loadErrors: { watcher: "timeout" } });
    expect(screen.getByText(/Connector watcher failed to load: timeout/)).toBeInTheDocument();
  });
});

describe("selected status chip", () => {
  afterEach(() => localStorage.removeItem("suspicious.theme"));

  // The inverted pill used text.primary over paper; in spring those two are a dark pair, which left the label at 1.6:1.
  it.each(Object.keys(themes) as (keyof typeof themes)[])("keeps its label readable in the %s theme", (name) => {
    localStorage.setItem("suspicious.theme", name);
    renderGallery();
    const chip = screen.getByRole("button", { name: /^All\s*5$/ });
    const fill = flatten(getComputedStyle(chip).backgroundColor, themes[name].palette.background.paper);
    expect(contrastRatio(flatten(getComputedStyle(chip).color, fill), fill)).toBeGreaterThanOrEqual(4.5);
  });
});
