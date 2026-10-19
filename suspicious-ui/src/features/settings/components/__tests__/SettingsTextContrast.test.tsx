import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { page } from "vitest/browser";

import { renderWithProviders } from "@/test/utils";
import { themes } from "@/styles/themes";
import { composite, contrastRatio, flatten } from "@/shared/lib/contrast";
import { SettingsNav } from "../SettingsNav";

vi.mock("@/features/settings/api", async (original) => ({
  ...(await original<typeof import("@/features/settings/api")>()),
  listItems: vi.fn().mockResolvedValue([{ id: "1", value: "evil.com" }]),
}));
import { EditableListPanel } from "../EditableListPanel";

const NAMES = Object.keys(themes) as (keyof typeof themes)[];
afterEach(() => localStorage.removeItem("suspicious.theme"));

describe("text a theme accent would make unreadable", () => {
  it.each(NAMES)("the selected nav item is readable on its tint in the %s theme", async (theme) => {
    localStorage.setItem("suspicious.theme", theme);
    await page.viewport(1280, 900);
    const { palette } = themes[theme];
    renderWithProviders(<SettingsNav active="scoring" unsaved={new Set()} onNavigate={vi.fn()} />);
    const label = within(screen.getByRole("navigation", { name: "Settings sections" })).getByText("Analyzer scoring");
    const tint = composite(flatten(palette.primary.main, palette.background.paper), 0.1, palette.background.paper);
    expect(contrastRatio(getComputedStyle(label).color, tint)).toBeGreaterThanOrEqual(4.5);
  });

  it.each(NAMES)("the bulk bar's Clear and Delete buttons are readable on the bar in the %s theme", async (theme) => {
    localStorage.setItem("suspicious.theme", theme);
    const { palette } = themes[theme];
    renderWithProviders(<EditableListPanel section="domains_allow" title="Domains allowlist" placeholder="x" />);
    await userEvent.click(await screen.findByRole("checkbox", { name: "Select evil.com" }));
    const bar = flatten(palette.action.hover, palette.background.paper);
    for (const name of ["Clear", "Delete 1"]) {
      expect(contrastRatio(getComputedStyle(screen.getByRole("button", { name })).color, bar), name).toBeGreaterThanOrEqual(4.5);
    }
  });
});
