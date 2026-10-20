import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { page } from "@vitest/browser/context";

import { renderWithProviders } from "@/test/utils";
import { themes } from "@/styles/themes";
import { contrastRatio, flatten } from "@/shared/lib/contrast";
import { ConnectorDrawer } from "../ConnectorDrawer";
import { ConnectorDeliveries } from "../ConnectorDeliveries";
import type { ConfigField, Connector, ConnectorDelivery } from "../connectors";

vi.mock("../connectors", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../connectors")>();
  return {
    ...actual,
    getConnectorConfig: vi.fn().mockResolvedValue({}),
    putConnectorConfig: vi.fn(),
    testConnector: vi.fn().mockResolvedValue({ ok: true, detail: "reachable" }),
    listDeliveries: vi.fn().mockResolvedValue([]),
  };
});

const field = (key: string, over: Partial<ConfigField> = {}): ConfigField => ({
  key,
  type: "str",
  required: false,
  default: null,
  help: "",
  ...over,
});

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

const CONNECTOR: Connector = {
  name: "misp",
  version: "1.2.0",
  description: "Push to MISP",
  author: "Thales CERT",
  docs_url: "https://docs.example.test/misp",
  category: "Threat Intelligence",
  events: ["case_finalised", "campaign_detected"],
  schedules: [{ name: "sync", interval_seconds: 900 }],
  config_schema: [field("url", { type: "url", required: true }), field("api_key", { type: "secret", required: true })],
  enabled: true,
  enabled_by_default: false,
  status: "connected",
  last_health_ok: true,
  last_health_detail: "pong",
  last_health_at: minutesAgo(5),
};

type Tab = "overview" | "configuration" | "deliveries";
function renderDetail(tab: Tab | string | null, connector: Connector = CONNECTOR, props = {}) {
  const query = tab === null ? "" : `?tab=${tab}`;
  return renderWithProviders(<ConnectorDrawer connector={connector} onClose={vi.fn()} {...props} />, {
    initialPath: `/settings/connectors${query}`,
    routePath: "*",
  });
}

const delivery = (id: number, over: Partial<ConnectorDelivery> = {}): ConnectorDelivery => ({
  id,
  event: "case_finalised",
  case_id: id,
  status: "success",
  error: "",
  duration_ms: 1,
  attempt: 1,
  created_at: "2026-07-01T10:00:00Z",
  ...over,
});

describe("header", () => {
  it("shows the last check time and detail", () => {
    renderDetail("overview");
    expect(screen.getByText("Last checked 5 min ago: pong")).toBeInTheDocument();
    expect(screen.getAllByText("1.2.0")).toHaveLength(2);
    expect(screen.getByTestId("connector-logo")).toBeInTheDocument();
  });

  it("says so when the connector was never checked, and drops the colon without a detail", () => {
    renderDetail("overview", { ...CONNECTOR, last_health_at: null, last_health_ok: null, last_health_detail: "" });
    // Once in the header and once as the Health fact.
    expect(screen.getAllByText("Not checked yet")).toHaveLength(2);
    expect(screen.queryByText(/Last checked/)).not.toBeInTheDocument();
  });

  it("omits the colon part when the detail is empty", () => {
    renderDetail("overview", { ...CONNECTOR, last_health_detail: "" });
    expect(screen.getByText("Last checked 5 min ago")).toBeInTheDocument();
  });

  it("lets Unhealthy win in the status label", () => {
    renderDetail("overview", { ...CONNECTOR, last_health_ok: false });
    expect(screen.getAllByText("Unhealthy").length).toBeGreaterThan(0);
  });
});

describe("header edge cases", () => {
  it("never writes 'Last checked not checked yet' for an unparsable timestamp", () => {
    renderDetail("overview", { ...CONNECTOR, last_health_at: "garbage" });
    expect(screen.queryByText(/Last checked/)).not.toBeInTheDocument();
    expect(screen.getAllByText("Not checked yet").length).toBeGreaterThan(0);
  });
});

describe("tab panels", () => {
  it("puts a focus stop on the Overview and Deliveries panels, which start with no focusable content", async () => {
    renderDetail("overview");
    expect(screen.getByRole("tabpanel")).toHaveAttribute("tabindex", "0");
    await userEvent.click(screen.getByRole("tab", { name: "Deliveries" }));
    expect(screen.getByRole("tabpanel")).toHaveAttribute("tabindex", "0");
  });

  it("leaves the Configuration panel out of the tab order once its first field can take focus", async () => {
    renderDetail("configuration");
    await screen.findByLabelText(/^URL/);
    expect(screen.getByRole("tabpanel")).not.toHaveAttribute("tabindex");
  });
});

describe("tabs", () => {
  it("wires each tab to its panel and shows Overview by default", () => {
    renderDetail(null);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Overview", "Configuration", "Deliveries"]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    const panel = screen.getByRole("tabpanel");
    expect(panel).toHaveAttribute("id", tabs[0].getAttribute("aria-controls"));
    expect(panel).toHaveAccessibleName("Overview");
  });

  it("restores the tab from the URL", async () => {
    renderDetail("deliveries");
    expect(screen.getByRole("tab", { name: "Deliveries" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("No deliveries yet.")).toBeInTheDocument();
  });

  it("falls back to Overview for an unknown tab", () => {
    renderDetail("nonsense");
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  });

  it("writes the chosen tab to the URL", async () => {
    const { router } = renderDetail("overview");
    await userEvent.click(screen.getByRole("tab", { name: "Configuration" }));
    expect(router!.state.location.search).toBe("?tab=configuration");
  });

  it("moves focus with arrows, Home and End, then activates with Enter", async () => {
    renderDetail("overview");
    screen.getByRole("tab", { name: "Overview" }).focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Configuration" })).toHaveFocus();
    await userEvent.keyboard("{End}");
    expect(screen.getByRole("tab", { name: "Deliveries" })).toHaveFocus();
    await userEvent.keyboard("{Home}");
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveFocus();
    await userEvent.keyboard("{ArrowRight}{Enter}");
    expect(screen.getByRole("tab", { name: "Configuration" })).toHaveAttribute("aria-selected", "true");
  });

  it("keeps the draft when switching tabs and back", async () => {
    renderDetail("configuration");
    await userEvent.type(await screen.findByLabelText(/^URL/), "x");
    await userEvent.click(screen.getByRole("tab", { name: "Overview" }));
    expect(screen.getByText("Unsaved changes in Configuration")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: "Configuration" }));
    expect((screen.getByLabelText(/^URL/) as HTMLInputElement).value).toBe("x");
  });
});

describe("overview", () => {
  it("lists events, schedules, author, version and a safe documentation link", () => {
    renderDetail("overview");
    const panel = screen.getByRole("tabpanel");
    expect(within(panel).getByText("case_finalised, campaign_detected")).toBeInTheDocument();
    expect(within(panel).getByText("sync: every 15 min")).toBeInTheDocument();
    expect(within(panel).getByText("Thales CERT")).toBeInTheDocument();
    expect(within(panel).getByText("1.2.0")).toBeInTheDocument();
    const link = within(panel).getByRole("link", { name: /docs\.example\.test/ });
    expect(link).toHaveAttribute("href", "https://docs.example.test/misp");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("shows health and status as words", () => {
    renderDetail("overview");
    const panel = screen.getByRole("tabpanel");
    expect(within(panel).getByText("Connected")).toBeInTheDocument();
    expect(within(panel).getByText("Healthy")).toBeInTheDocument();
    expect(within(panel).getByText("pong")).toBeInTheDocument();
  });

  it.each(["", "javascript:alert(1)", "ftp://x.test", "not a url"])("does not link a docs_url of %j", (docs) => {
    renderDetail("overview", { ...CONNECTOR, docs_url: docs });
    const panel = screen.getByRole("tabpanel");
    expect(within(panel).queryByRole("link")).not.toBeInTheDocument();
    expect(within(panel).getByText("Not provided")).toBeInTheDocument();
  });

  it("says None for no events or schedules", () => {
    renderDetail("overview", { ...CONNECTOR, events: [], schedules: [] });
    expect(within(screen.getByRole("tabpanel")).getAllByText("None")).toHaveLength(2);
  });
});

describe("configuration", () => {
  // Not named ai_narration: that connector has its own provider switch (ProviderSwitch.test.tsx); this is the generic grouping.
  const AI: Connector = {
    ...CONNECTOR,
    name: "narrator",
    config_schema: [
      field("ollama_url", { type: "url" }),
      field("ollama_model"),
      field("openai_api_key", { type: "secret" }),
      field("openai_model"),
      field("narration_provider"),
    ],
  };

  it("groups fields in fieldsets named by their legend", async () => {
    renderDetail("configuration", AI);
    expect(await screen.findByRole("group", { name: "General" })).toBeInTheDocument();
    const ollama = screen.getByRole("group", { name: "Ollama" });
    expect(within(ollama).getByLabelText("Ollama URL")).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "OpenAI" })).getByLabelText("OpenAI API Key")).toBeInTheDocument();
  });

  const MIXED: Connector = {
    ...CONNECTOR,
    config_schema: [
      field("url", { type: "url", required: true }),
      field("api_key", { type: "secret", required: true }),
      field("verify_tls", { type: "bool" }),
      field("timeout", { type: "int" }),
    ],
  };

  it("hides optional fields behind a disclosure that counts them", async () => {
    renderDetail("configuration", MIXED);
    const toggle = await screen.findByRole("button", { name: "Show optional settings (2)" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByLabelText("Timeout")).not.toBeInTheDocument();
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(document.getElementById(toggle.getAttribute("aria-controls")!)).toContainElement(screen.getByLabelText("Timeout"));
  });

  it("shows a group of only optional fields straight away, without a disclosure", async () => {
    renderDetail("configuration", AI);
    expect(await screen.findByLabelText("Ollama URL")).toBeVisible();
    expect(screen.queryByRole("button", { name: /optional settings/ })).not.toBeInTheDocument();
  });

  it("shows no disclosure for a group without optional fields", async () => {
    renderDetail("configuration", { ...CONNECTOR, config_schema: [field("url", { required: true })] });
    await screen.findByLabelText(/^URL/);
    expect(screen.queryByRole("button", { name: /optional settings/ })).not.toBeInTheDocument();
  });

  it("opens the disclosure when an optional field has a server error, and shows the error on the field", async () => {
    const { putConnectorConfig } = await import("../connectors");
    vi.mocked(putConnectorConfig).mockRejectedValueOnce({ response: { data: { errors: { timeout: "must be positive" } } } });
    renderDetail("configuration", MIXED);
    await userEvent.click(await screen.findByRole("button", { name: "Show optional settings (2)" }));
    await userEvent.type(screen.getByLabelText("Timeout"), "5");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByText("timeout: must be positive")).toBeInTheDocument();
    expect(screen.getByLabelText("Timeout")).toHaveAccessibleDescription(/must be positive/);
  });

  it("starts the disclosure open when an optional field already differs from the saved value", async () => {
    renderDetail("configuration", MIXED);
    await userEvent.click(await screen.findByRole("button", { name: "Show optional settings (2)" }));
    await userEvent.type(screen.getByLabelText("Timeout"), "5");
    await userEvent.click(screen.getByRole("tab", { name: "Overview" }));
    await userEvent.click(screen.getByRole("tab", { name: "Configuration" }));
    expect(screen.getByLabelText("Timeout")).toBeInTheDocument();
  });

  it("keeps a required-field error visible while optional fields are collapsed", async () => {
    const { putConnectorConfig } = await import("../connectors");
    vi.mocked(putConnectorConfig).mockRejectedValueOnce({ response: { data: { errors: { url: "is required" } } } });
    renderDetail("configuration", MIXED);
    await userEvent.type(await screen.findByLabelText(/^URL/), "x");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await screen.findByText("url: is required");
    expect(screen.getByLabelText(/^URL/)).toBeVisible();
    expect(screen.getByLabelText(/^URL/)).toHaveAccessibleDescription(/is required/);
    expect(screen.queryByLabelText("Timeout")).not.toBeInTheDocument();
  });

  it("says Set beside a stored secret and Not set beside an empty one", async () => {
    const { getConnectorConfig } = await import("../connectors");
    vi.mocked(getConnectorConfig).mockResolvedValueOnce({ api_key: "********" });
    renderDetail("configuration", { ...CONNECTOR, config_schema: [field("api_key", { type: "secret" }), field("api_other", { type: "secret" })] });
    expect(await screen.findByText("Set")).toBeInTheDocument();
    expect(screen.getByText("Not set")).toBeInTheDocument();
  });

  it("keeps saying Set while a replacement secret is being typed", async () => {
    const { getConnectorConfig } = await import("../connectors");
    vi.mocked(getConnectorConfig).mockResolvedValueOnce({ api_key: "********" });
    renderDetail("configuration", { ...CONNECTOR, config_schema: [field("api_key", { type: "secret" })] });
    await screen.findByText("Set");
    await userEvent.type(screen.getByLabelText("API Key"), "new");
    await userEvent.clear(screen.getByLabelText("API Key"));
    expect(screen.getByText("Set")).toBeInTheDocument();
    expect(screen.queryByText("Not set")).not.toBeInTheDocument();
  });

  it("puts Save changes and Test connection in the sticky action bar and labels the test result", async () => {
    renderDetail("configuration", MIXED);
    const save = await screen.findByRole("button", { name: "Save changes" });
    const bar = save.closest("[data-panel-actions]")!;
    expect(bar).toContainElement(screen.getByRole("button", { name: "Test connection" }));
    await userEvent.click(screen.getByRole("button", { name: "Test connection" }));
    const result = await screen.findByRole("alert");
    expect(result).toHaveTextContent("Tested the saved configuration");
    expect(result).toHaveTextContent("OK: reachable");
    expect(bar).toContainElement(result);
  });
});

describe("disabled Save changes", () => {
  afterEach(() => localStorage.removeItem("suspicious.theme"));

  it.each(["light", "midnight"] as const)("keeps a visible neutral fill and 4.5:1 text on %s", async (theme) => {
    localStorage.setItem("suspicious.theme", theme);
    renderDetail("configuration");
    const save = await screen.findByRole("button", { name: "Save changes" });
    expect(save).toBeDisabled();
    // The reason stays linked while it is disabled.
    expect(save).toHaveAccessibleDescription("No changes to save");
    const cs = getComputedStyle(save);
    const paper = themes[theme].palette.background.paper;
    const fill = flatten(cs.backgroundColor, paper);
    expect(cs.backgroundColor).not.toBe("rgba(0, 0, 0, 0)");
    expect(cs.backgroundImage).toBe("none");
    expect(fill).not.toBe(flatten("rgba(0,0,0,0)", paper));
    expect(contrastRatio(flatten(cs.color, fill), fill)).toBeGreaterThanOrEqual(4.5);
  });
});

describe("deliveries", () => {
  // Below md the Time column folds into the Event cell, so the five-column table needs a desktop viewport.
  beforeEach(async () => {
    await page.viewport(1280, 800);
  });

  it("filters to failed deliveries with a pressed toggle and shows the error", async () => {
    const { listDeliveries } = await import("../connectors");
    vi.mocked(listDeliveries).mockResolvedValueOnce([
      delivery(1),
      delivery(2, { status: "failed", error: "HTTP 500 from MISP" }),
      delivery(3, { status: "skipped" }),
    ]);
    // The drawer is 600px wide, under the 720px container breakpoint, so it shows the folded layout (below); the five columns need the table on its own.
    renderWithProviders(<ConnectorDeliveries name="misp" />);
    const table = await screen.findByRole("table", { name: /deliveries/i });
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      "Event", "Case", "Status", "Time", "Error",
    ]);
    expect(within(table).getByText("HTTP 500 from MISP")).toBeInTheDocument();
    expect(within(table).getAllByRole("row")).toHaveLength(4);

    const toggle = screen.getByRole("button", { name: "Failed only" });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    expect(within(table).queryByText("Delivered")).not.toBeInTheDocument();
    expect(within(table).getByText("Failed")).toBeInTheDocument();
  });

  it("folds Case and Time into the Event cell inside the 600px drawer", async () => {
    const { listDeliveries } = await import("../connectors");
    vi.mocked(listDeliveries).mockResolvedValueOnce([delivery(1)]);
    renderDetail("deliveries");
    const table = await screen.findByRole("table", { name: /deliveries/i });
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Event", "Status", "Error"]);
    expect(within(within(table).getAllByRole("cell")[0]).getByRole("link", { name: "Case #1" })).toBeVisible();
  });

  it("says when no delivery failed", async () => {
    const { listDeliveries } = await import("../connectors");
    vi.mocked(listDeliveries).mockResolvedValueOnce([delivery(1)]);
    renderDetail("deliveries");
    await userEvent.click(await screen.findByRole("button", { name: "Failed only" }));
    expect(screen.getByText("No failed deliveries among these.")).toBeInTheDocument();
  });

  it("links the case only when there is one and encodes the id", async () => {
    const { listDeliveries } = await import("../connectors");
    vi.mocked(listDeliveries).mockResolvedValueOnce([delivery(1, { case_id: null }), delivery(2)]);
    renderDetail("deliveries");
    await screen.findByRole("link", { name: "Case #2" });
    expect(screen.getAllByRole("link")).toHaveLength(1);
  });

  it("gives a long error its full text in a title", async () => {
    const { listDeliveries } = await import("../connectors");
    const long = "x".repeat(200);
    vi.mocked(listDeliveries).mockResolvedValueOnce([delivery(1, { status: "failed", error: long })]);
    renderDetail("deliveries");
    expect(await screen.findByText(long)).toHaveAttribute("title", long);
  });

  it("does not request deliveries until the tab is opened", async () => {
    const { listDeliveries } = await import("../connectors");
    vi.mocked(listDeliveries).mockClear();
    renderDetail("overview");
    expect(listDeliveries).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("tab", { name: "Deliveries" }));
    await waitFor(() => expect(listDeliveries).toHaveBeenCalledWith("misp", 10));
  });
});
