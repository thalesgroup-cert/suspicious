import { describe, expect, it, vi } from "vitest";
import { screen, within } from "@testing-library/react";
import { page } from "vitest/browser";

import { renderWithProviders } from "@/test/utils";
import { SettingsNav } from "../SettingsNav";

const unsaved = new Set(["scoring"] as const);

describe("SettingsNav unsaved marker", () => {
  it("shows an aria-hidden dot and hidden text on the rail item", async () => {
    await page.viewport(1280, 900);
    renderWithProviders(<SettingsNav active="domains_allow" unsaved={unsaved} onNavigate={vi.fn()} />);
    const link = within(screen.getByRole("navigation", { name: "Settings sections" })).getByRole("link", {
      name: "Analyzer scoring unsaved changes",
    });
    expect(within(link).getByText("unsaved changes")).toBeInTheDocument();
    expect(link.querySelector('[aria-hidden="true"]')).not.toBeNull();
    // Other items carry no marker.
    expect(screen.getAllByText("unsaved changes")).toHaveLength(1);
  });

  it("suffixes the option in the phone picker", async () => {
    await page.viewport(390, 800);
    renderWithProviders(<SettingsNav active="domains_allow" unsaved={unsaved} onNavigate={vi.fn()} />);
    expect(screen.getByRole("option", { name: "Analyzer scoring (unsaved changes)" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Connectors" })).toBeInTheDocument();
  });

  it("leaves out the sections named in hidden", async () => {
    await page.viewport(1280, 900);
    renderWithProviders(
      <SettingsNav active="domains_allow" unsaved={unsaved} onNavigate={vi.fn()} hidden={new Set(["ai_model"])} />,
    );
    const nav = screen.getByRole("navigation", { name: "Settings sections" });
    expect(within(nav).queryByRole("link", { name: "AI model" })).toBeNull();
    expect(within(nav).getByRole("link", { name: "Connectors" })).toBeInTheDocument();
  });
  it("lists AI model by default", async () => {
    await page.viewport(1280, 900);
    renderWithProviders(<SettingsNav active="domains_allow" unsaved={unsaved} onNavigate={vi.fn()} />);
    expect(screen.getByRole("link", { name: "AI model" })).toBeInTheDocument();
  });
});
