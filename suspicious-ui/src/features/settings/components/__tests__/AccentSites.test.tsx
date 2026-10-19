import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { renderWithProviders } from "@/test/utils";
import { themes } from "@/styles/themes";
import { composite, contrastRatio, flatten } from "@/shared/lib/contrast";

vi.mock("@/features/settings/api", async (original) => ({
  ...(await original<typeof import("@/features/settings/api")>()),
  listItems: vi.fn().mockResolvedValue([{ id: "1", value: "evil.com" }]),
  listAnalyzers: vi.fn().mockResolvedValue([{ id: 1, name: "Alpha", weight: 0.5, analyzer_cortex_id: "a_1", is_active: true }]),
}));
vi.mock("../connectors", () => ({
  getConnectorConfig: vi.fn().mockResolvedValue({}),
  putConnectorConfig: vi.fn(),
  testConnector: vi.fn(),
  listDeliveries: vi.fn().mockResolvedValue([
    { id: 1, event: "case_finalised", case_id: 7, status: "success", error: "", duration_ms: 12, attempt: 1, created_at: "2026-10-19T08:00:00Z" },
  ]),
}));
import { ConfirmDialog } from "../ConfirmDialog";
import { ConnectorDetail } from "../ConnectorDetail";
import { EditableListPanel } from "../EditableListPanel";
import { ScoringTable } from "../ScoringTable";
import type { Connector } from "../connectors";

const conn: Connector = {
  name: "misp", version: "1", description: "d", author: "a", docs_url: "https://docs.example/misp", category: "TI",
  events: [], schedules: [], config_schema: [{ key: "url", type: "url", required: true, default: null, help: "" }],
  enabled: true, enabled_by_default: false, status: "connected", last_health_ok: true, last_health_detail: "", last_health_at: null,
};
const NAMES = Object.keys(themes) as (keyof typeof themes)[];
afterEach(() => localStorage.removeItem("suspicious.theme"));

// Primary is a fill colour; wherever the page uses it as text or as a mark it has to be pushed, whatever the theme's accent is.
describe.each(NAMES)("accent used as text or mark in the %s theme", (name) => {
  const setTheme = () => {
    localStorage.setItem("suspicious.theme", name);
    return themes[name].palette;
  };

  it("connector tabs: selected label 4.5:1, indicator 3:1, unselected label 4.5:1", async () => {
    const palette = setTheme();
    renderWithProviders(<ConnectorDetail connector={conn} />, { initialPath: "/settings/connectors?tab=overview" });
    const paper = palette.background.paper;
    const selected = screen.getByRole("tab", { name: "Overview" });
    const other = screen.getByRole("tab", { name: "Deliveries" });
    expect(contrastRatio(getComputedStyle(selected).color, paper), "selected label").toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(getComputedStyle(other).color, paper), "unselected label").toBeGreaterThanOrEqual(4.5);
    const indicator = document.querySelector(".MuiTabs-indicator") as HTMLElement;
    expect(contrastRatio(getComputedStyle(indicator).backgroundColor, paper), "indicator").toBeGreaterThanOrEqual(3);
  });

  it("documentation and case links are readable as text", async () => {
    const palette = setTheme();
    renderWithProviders(<ConnectorDetail connector={conn} />, { initialPath: "/settings/connectors?tab=overview" });
    const docs = await screen.findByRole("link", { name: /docs\.example/ });
    expect(contrastRatio(getComputedStyle(docs).color, palette.background.paper)).toBeGreaterThanOrEqual(4.5);
  });

  it("checked checkbox 3:1 on its selected row", async () => {
    const palette = setTheme();
    renderWithProviders(<EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="x" />);
    await userEvent.click(await screen.findByRole("checkbox", { name: "Select evil.com" }));
    const box = screen.getByRole("checkbox", { name: "Select evil.com" }).closest(".MuiCheckbox-root")!;
    const primary = flatten(palette.primary.main, palette.background.paper);
    const row = composite(primary, 0.08, palette.background.paper);
    expect(contrastRatio(getComputedStyle(box).color, row)).toBeGreaterThanOrEqual(3);
  });

  it("text and outlined buttons are readable: dialog Cancel, Import file, Test connection", async () => {
    const palette = setTheme();
    const paper = palette.background.paper;
    const { unmount } = renderWithProviders(<ConfirmDialog open title="t" body="b" confirmLabel="Go" onConfirm={vi.fn()} onCancel={vi.fn()} />);
    expect(contrastRatio(getComputedStyle(await screen.findByRole("button", { name: "Cancel" })).color, paper), "Cancel").toBeGreaterThanOrEqual(4.5);
    unmount();
    const list = renderWithProviders(<EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="x" />);
    expect(contrastRatio(getComputedStyle(await screen.findByRole("button", { name: "Import file" })).color, paper), "Import file").toBeGreaterThanOrEqual(4.5);
    list.unmount();
    renderWithProviders(<ConnectorDetail connector={conn} />, { initialPath: "/settings/connectors?tab=configuration" });
    expect(contrastRatio(getComputedStyle(await screen.findByRole("button", { name: "Test connection" })).color, paper), "Test connection").toBeGreaterThanOrEqual(4.5);
  });

  it("the deliveries table header is readable on the theme's header tint", async () => {
    const palette = setTheme();
    renderWithProviders(<ConnectorDetail connector={conn} />, { initialPath: "/settings/connectors?tab=deliveries" });
    const head = await screen.findByRole("columnheader", { name: "Status" });
    const tint = composite(palette.text.primary, palette.mode === "dark" ? 0.03 : 0.025, palette.background.paper);
    expect(contrastRatio(getComputedStyle(head).color, tint)).toBeGreaterThanOrEqual(4.5);
  });

  it("slider track and thumb 3:1 on the card", async () => {
    const palette = setTheme();
    renderWithProviders(<ScoringTable />);
    await waitFor(() => expect(document.querySelector(".MuiSlider-thumb")).not.toBeNull());
    for (const part of [".MuiSlider-track", ".MuiSlider-thumb"]) {
      const el = document.querySelector(part) as HTMLElement;
      expect(contrastRatio(getComputedStyle(el).backgroundColor, palette.background.paper), part).toBeGreaterThanOrEqual(3);
    }
  });
});
