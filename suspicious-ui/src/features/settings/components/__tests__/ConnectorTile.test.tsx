import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { renderWithProviders } from "@/test/utils";
import { ConnectorTile } from "../ConnectorTile";
import type { Connector } from "../connectors";

const getMe = vi.hoisted(() => vi.fn());
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
