import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError } from "axios";
import { describe, expect, it, vi } from "vitest";

import { renderWithProviders } from "@/test/utils";
import { ConnectorTile } from "../ConnectorTile";
import type { Connector } from "../connectors";

const getMe = vi.hoisted(() => vi.fn());
const setEnabled = vi.hoisted(() => vi.fn());
vi.mock("../connectors", async (orig) => ({ ...(await orig<typeof import("../connectors")>()), setConnectorEnabled: setEnabled }));
vi.mock("@/api/auth", () => ({ getMe }));

const make = (name: string): Connector => ({
  name,
  version: "1.0.0",
  description: "d",
  author: "",
  docs_url: "",
  category: "Maintenance",
  events: [],
  schedules: [],
  config_schema: [],
  enabled: true,
  enabled_by_default: false,
  status: "connected",
  last_health_ok: true,
  last_health_detail: "",
  last_health_at: null,
});

const LINE = "Models, retraining and shadow are managed in the AI model card";

function renderTile(name: string, groups: string[]) {
  getMe.mockResolvedValue({ id: 1, username: "a", email: "a@x.test", groups });
  return renderWithProviders(
    <ul>
      <ConnectorTile connector={make(name)} testResult={null} onTestResult={vi.fn()} onConfigure={vi.fn()} />
    </ul>,
  );
}

describe("ai_model tile line", () => {
  it("links to the card for an Admin", async () => {
    renderTile("ai_model", ["Admin"]);
    const link = await screen.findByRole("link", { name: /AI model card/ });
    expect(link).toHaveAttribute("href", "/settings/ai_model");
  });

  it("shows the line without a link for a CERT user", async () => {
    renderTile("ai_model", ["CERT"]);
    expect(await screen.findByText(LINE)).toBeInTheDocument();
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("leaves other tiles unchanged", async () => {
    renderTile("misp", ["Admin"]);
    await screen.findByRole("heading", { name: "misp" });
    expect(screen.queryByText(LINE)).toBeNull();
    expect(screen.queryByRole("link")).toBeNull();
  });
});

describe("disabling the last analysis connector", () => {
  const conflict = (code: string) =>
    Object.assign(new AxiosError("conflict"), { response: { status: 409, data: { detail: "last one", code } } });

  it("confirms, then resends with force", async () => {
    setEnabled.mockRejectedValueOnce(conflict("last_analysis_connector")).mockResolvedValueOnce({ name: "cortex", enabled: false });
    renderTile("cortex", ["Admin"]);
    await userEvent.click(await screen.findByRole("switch"));
    expect(await screen.findByText("last one")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Disable" }));
    await waitFor(() => expect(setEnabled).toHaveBeenLastCalledWith("cortex", false, true));
  });

  it("sends no second request on cancel", async () => {
    setEnabled.mockReset();
    setEnabled.mockRejectedValueOnce(conflict("last_analysis_connector"));
    renderTile("cortex", ["Admin"]);
    await userEvent.click(await screen.findByRole("switch"));
    await userEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(setEnabled).toHaveBeenCalledTimes(1);
  });

  it("shows the normal error for another 409", async () => {
    setEnabled.mockReset();
    setEnabled.mockRejectedValueOnce(conflict("other"));
    renderTile("cortex", ["Admin"]);
    await userEvent.click(await screen.findByRole("switch"));
    await waitFor(() => expect(setEnabled).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole("button", { name: "Disable" })).toBeNull();
  });
});
