import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { Link } from "react-router";

import { renderWithProviders } from "@/test/utils";
import { UnsavedProvider, useUnsavedKeys } from "@/features/settings/unsaved";
import { ConnectorDetail } from "../ConnectorDetail";
import type { Connector } from "../connectors";

vi.mock("../connectors", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../connectors")>();
  return {
    ...actual,
    getConnectorConfig: vi.fn().mockResolvedValue({ api_key: "" }),
    putConnectorConfig: vi.fn(),
    testConnector: vi.fn().mockResolvedValue({ ok: true, detail: "reachable" }),
    listDeliveries: vi.fn().mockResolvedValue([
      {
        id: 1,
        event: "case_finalised",
        case_id: 42,
        status: "success",
        error: "",
        duration_ms: 120,
        attempt: 1,
        created_at: "2026-07-01T10:00:00Z",
      },
    ]),
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
  config_schema: [{ key: "api_key", type: "secret", required: false, default: null, help: "" }],
  enabled: true,
  enabled_by_default: false,
  status: "connected",
  last_health_ok: true,
  last_health_detail: "ok",
  last_health_at: null,
};

type Tab = "overview" | "configuration" | "deliveries";

// The active tab lives in the URL, so a test picks its tab by path.
function renderDetail(tab: Tab, props: Partial<React.ComponentProps<typeof ConnectorDetail>> = {}) {
  return renderWithProviders(<ConnectorDetail connector={CONNECTOR} {...props} />, {
    initialPath: `/settings/connectors?tab=${tab}`,
  });
}

describe("ConnectorDetail", () => {
  it("renders connector identity and config fields", async () => {
    renderDetail("configuration");
    expect(screen.getByRole("heading", { level: 3, name: "misp" })).toBeInTheDocument();
    expect(await screen.findByLabelText("API Key")).toBeInTheDocument();
  });

  it("renders recent deliveries", async () => {
    renderDetail("deliveries");
    expect(await screen.findByText(/case_finalised/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Case #42" })).toHaveAttribute("href", "/investigation?open=42");
  });

  it("shows the empty deliveries message when there are none", async () => {
    const { listDeliveries } = await import("../connectors");
    vi.mocked(listDeliveries).mockResolvedValueOnce([]);
    renderDetail("deliveries");
    expect(await screen.findByText("No deliveries yet.")).toBeInTheDocument();
  });

  it("shows error alert when deliveries query fails", async () => {
    const { listDeliveries } = await import("../connectors");
    vi.mocked(listDeliveries).mockRejectedValueOnce(new Error("network error"));
    renderDetail("deliveries");
    expect(await screen.findByText("Failed to load recent deliveries.")).toBeInTheDocument();
    expect(screen.queryByText("No deliveries yet.")).not.toBeInTheDocument();
  });

  it("shows error alert when config query fails, without rendering stale fields", async () => {
    const { getConnectorConfig } = await import("../connectors");
    vi.mocked(getConnectorConfig).mockRejectedValueOnce(new Error("network error"));
    renderDetail("configuration");
    expect(await screen.findByText("Failed to load configuration.")).toBeInTheDocument();
    expect(screen.queryByLabelText("API Key")).not.toBeInTheDocument();
  });

  it("shows a back button only when onBack is provided", () => {
    renderDetail("overview", { onBack: vi.fn() });
    expect(screen.getByLabelText("Back to connector list")).toBeInTheDocument();
  });

  it("omits the back button when onBack is not provided", () => {
    renderDetail("overview");
    expect(screen.queryByLabelText("Back to connector list")).not.toBeInTheDocument();
  });

  it("enables Save only after a field is edited", async () => {
    renderDetail("configuration");
    const input = await screen.findByLabelText("API Key");
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    await userEvent.type(input, "secret-value");
    expect(screen.getByRole("button", { name: "Save changes" })).toBeEnabled();
  });

  it("labels fields readably and keeps the raw key as helper text beside the help", async () => {
    renderDetail("configuration", {
      connector: {
        ...CONNECTOR,
        config_schema: [
          { key: "ollama_url", type: "url", required: false, default: null, help: "Where Ollama listens" },
        ],
      },
    });
    const input = await screen.findByLabelText("Ollama URL");
    expect(input).toHaveAccessibleDescription(/Where Ollama listens/);
    expect(input).toHaveAccessibleDescription(/ollama_url/);
  });

  it("drops the internal docs pointer from the description but keeps the rest", () => {
    renderDetail("overview", {
      connector: {
        ...CONNECTOR,
        description: "Narrates verdicts. See docs/specs/2026-09-21-ai-narration-event-wiring-design.md.",
      },
    });
    expect(screen.getByText("Narrates verdicts.")).toBeInTheDocument();
    expect(screen.queryByText(/docs\/specs/)).not.toBeInTheDocument();
  });

  describe("test connection", () => {
    it("shows the server detail in an error alert when the request is rejected", async () => {
      const { testConnector } = await import("../connectors");
      vi.mocked(testConnector).mockRejectedValueOnce({
        response: { data: { detail: "Connection refused by host" } },
      });
      renderDetail("configuration");
      await userEvent.click(await screen.findByRole("button", { name: "Test connection" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("Connection refused by host");
    });

    it("reads the detail from an `error` field too", async () => {
      const { testConnector } = await import("../connectors");
      vi.mocked(testConnector).mockRejectedValueOnce({ response: { data: { error: "Bad token" } } });
      renderDetail("configuration");
      await userEvent.click(await screen.findByRole("button", { name: "Test connection" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("Bad token");
    });

    it("falls back to a generic message when a thrown error carries no detail", async () => {
      const { testConnector } = await import("../connectors");
      vi.mocked(testConnector).mockRejectedValueOnce(new Error("Network Error"));
      renderDetail("configuration");
      await userEvent.click(await screen.findByRole("button", { name: "Test connection" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("Connection test failed.");
    });

    it("adds the HTTP status to the generic failure message when there is one", async () => {
      const { testConnector } = await import("../connectors");
      vi.mocked(testConnector).mockRejectedValueOnce({ response: { status: 502, data: {} } });
      renderDetail("configuration");
      await userEvent.click(await screen.findByRole("button", { name: "Test connection" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("Connection test failed (HTTP 502).");
    });

    it("says the test checks the saved configuration while a draft exists", async () => {
      renderDetail("configuration");
      const input = await screen.findByLabelText("API Key");
      const hint = "Test connection checks the saved configuration, not your unsaved changes.";
      expect(screen.queryByText(hint)).not.toBeInTheDocument();
      await userEvent.type(input, "x");
      expect(screen.getByText(hint)).toBeVisible();
      expect(screen.getByRole("button", { name: "Test connection" })).toHaveAccessibleDescription(hint);
    });

    it("clears the previous result as soon as a new test starts", async () => {
      const { testConnector } = await import("../connectors");
      vi.mocked(testConnector).mockRejectedValueOnce(new Error("x"));
      renderDetail("configuration");
      const button = await screen.findByRole("button", { name: "Test connection" });
      await userEvent.click(button);
      await screen.findByText("Connection test failed.");
      vi.mocked(testConnector).mockReturnValueOnce(new Promise(() => undefined));
      await userEvent.click(button);
      await waitFor(() => expect(screen.queryByText("Connection test failed.")).not.toBeInTheDocument());
    });

    it("keeps showing OK and Failed results from the server", async () => {
      const { testConnector } = await import("../connectors");
      vi.mocked(testConnector).mockResolvedValueOnce({ ok: false, detail: "401 from MISP" });
      renderDetail("configuration");
      await userEvent.click(await screen.findByRole("button", { name: "Test connection" }));
      expect(await screen.findByRole("alert")).toHaveTextContent("Failed: 401 from MISP");
    });

    it("clears an earlier failure when the next test succeeds", async () => {
      const { testConnector } = await import("../connectors");
      vi.mocked(testConnector).mockRejectedValueOnce(new Error("x"));
      renderDetail("configuration");
      const button = await screen.findByRole("button", { name: "Test connection" });
      await userEvent.click(button);
      await screen.findByText("Connection test failed.");
      await userEvent.click(button);
      expect(await screen.findByText("OK: reachable")).toBeInTheDocument();
      expect(screen.queryByText("Connection test failed.")).not.toBeInTheDocument();
    });
  });

  describe("save", () => {
    it("keeps the draft and the typed value when saving fails", async () => {
      const { putConnectorConfig } = await import("../connectors");
      vi.mocked(putConnectorConfig).mockRejectedValueOnce({
        response: { data: { errors: { api_key: "too short" } } },
      });
      renderDetail("configuration");
      const input = (await screen.findByLabelText("API Key")) as HTMLInputElement;
      await userEvent.type(input, "abc");
      await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
      expect(await screen.findByText("api_key: too short")).toBeInTheDocument();
      expect(input.value).toBe("abc");
      expect(screen.getByRole("button", { name: "Save changes" })).toBeEnabled();
    });

    it("shows the saved value at once instead of falling back to the old one", async () => {
      const { putConnectorConfig, getConnectorConfig } = await import("../connectors");
      vi.mocked(putConnectorConfig).mockResolvedValueOnce({ api_key: "saved-value" });
      vi.mocked(getConnectorConfig)
        .mockResolvedValueOnce({ api_key: "" })
        // The refetch after save never lands, so only the cache write can supply the value.
        .mockReturnValueOnce(new Promise(() => undefined));
      renderDetail("configuration");
      await userEvent.type(await screen.findByLabelText("API Key"), "x");
      await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
      await waitFor(() =>
        expect((screen.getByLabelText("API Key") as HTMLInputElement).value).toBe("saved-value"),
      );
    });

    it("states why Save is disabled until something changes", async () => {
      renderDetail("configuration");
      const save = await screen.findByRole("button", { name: "Save changes" });
      expect(save).toBeDisabled();
      expect(save).toHaveAccessibleDescription("No changes to save");
      expect(screen.getByText("No changes to save")).toBeVisible();
      await userEvent.type(screen.getByLabelText("API Key"), "x");
      expect(save).toBeEnabled();
      expect(screen.queryByText("No changes to save")).not.toBeInTheDocument();
    });
  });

  describe("recent deliveries", () => {
    const delivery = (id: number, status: "success" | "failed" | "skipped") => ({
      id,
      event: "case_finalised",
      case_id: id,
      status,
      error: "",
      duration_ms: 1,
      attempt: 1,
      created_at: "2026-07-01T10:00:00Z",
    });

    it("asks for the last 10 deliveries", async () => {
      const { listDeliveries } = await import("../connectors");
      renderDetail("deliveries");
      await screen.findByText(/case_finalised/);
      expect(listDeliveries).toHaveBeenLastCalledWith("misp", 10);
    });

    it("writes the status as a word beside the dot", async () => {
      const { listDeliveries } = await import("../connectors");
      vi.mocked(listDeliveries).mockResolvedValueOnce([
        delivery(1, "success"),
        delivery(2, "failed"),
        delivery(3, "skipped"),
      ]);
      renderDetail("deliveries");
      expect(await screen.findByText("Delivered")).toBeInTheDocument();
      expect(screen.getByText("Failed")).toBeInTheDocument();
      expect(screen.getByText("Skipped")).toBeInTheDocument();
    });

    it("notes the cap only when exactly 10 come back", async () => {
      const { listDeliveries } = await import("../connectors");
      vi.mocked(listDeliveries).mockResolvedValueOnce(
        Array.from({ length: 10 }, (_, i) => delivery(i + 1, "success")),
      );
      const first = renderDetail("deliveries");
      expect(await screen.findByText("Showing the last 10")).toBeInTheDocument();
      first.unmount();

      renderDetail("deliveries");
      await screen.findByRole("link", { name: "Case #42" });
      expect(screen.queryByText("Showing the last 10")).not.toBeInTheDocument();
    });
  });

  it("has a heading outline without skipped levels: the connector name is the only h3, groups are legends", async () => {
    renderWithProviders(
      <>
        <h2>Connectors</h2>
        <ConnectorDetail
          connector={{
            ...CONNECTOR,
            config_schema: [
              { key: "ollama_url", type: "url", required: false, default: null, help: "" },
              { key: "ollama_model", type: "str", required: false, default: null, help: "" },
            ],
          }}
        />
      </>,
      { initialPath: "/settings/connectors?tab=configuration" },
    );
    await screen.findByLabelText("Ollama URL");
    const levels = screen.getAllByRole("heading").map((h) => [Number(h.tagName[1]), h.textContent]);
    expect(levels).toEqual([
      [2, "Connectors"],
      [3, "misp"],
    ]);
    expect(screen.getByRole("group", { name: "Ollama" })).toBeInTheDocument();
  });

  describe("unsaved draft", () => {
    function Keys() {
      return <output data-testid="keys">{[...useUnsavedKeys()].join(",")}</output>;
    }
    function setup() {
      return renderWithProviders(
        <UnsavedProvider>
          <Keys />
          <Link to="/elsewhere">Leave</Link>
          <ConnectorDetail connector={CONNECTOR} />
        </UnsavedProvider>,
        { routePath: "*", initialPath: "/settings/connectors?tab=configuration" },
      );
    }

    it("reports the connectors section dirty only while a draft exists", async () => {
      setup();
      const input = await screen.findByLabelText("API Key");
      expect(screen.getByTestId("keys")).toHaveTextContent("");
      await userEvent.type(input, "x");
      await waitFor(() => expect(screen.getByTestId("keys")).toHaveTextContent("connectors"));
    });

    it("clears the marker after a successful save", async () => {
      const { putConnectorConfig } = await import("../connectors");
      vi.mocked(putConnectorConfig).mockResolvedValueOnce({ api_key: "x" });
      setup();
      await userEvent.type(await screen.findByLabelText("API Key"), "x");
      await waitFor(() => expect(screen.getByTestId("keys")).toHaveTextContent("connectors"));
      await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
      await waitFor(() => expect(screen.getByTestId("keys")).toHaveTextContent(/^$/));
    });

    it("asks before leaving with a draft and stays when cancelled", async () => {
      const { router } = setup();
      await userEvent.type(await screen.findByLabelText("API Key"), "x");
      await userEvent.click(screen.getByRole("link", { name: "Leave" }));
      const dialog = await screen.findByRole("dialog");
      expect(within(dialog).getByText("Discard unsaved changes?")).toBeInTheDocument();
      await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
      expect(router!.state.location.pathname).toBe("/settings/connectors");
    });
  });
});
