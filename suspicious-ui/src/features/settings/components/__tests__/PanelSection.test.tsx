import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
import { PanelSection } from "../PanelSection";

describe("PanelSection", () => {
  it("renders one h2 title, the purpose, the toolbar, the content and the actions slot", () => {
    renderWithProviders(
      <PanelSection title="Domains" purpose="Domains that skip analysis." toolbar={<button>Add</button>} actions={<button>Save</button>}>
        <p>content</p>
      </PanelSection>,
    );
    expect(screen.getAllByRole("heading")).toHaveLength(1);
    expect(screen.getByRole("heading", { level: 2, name: "Domains" })).toBeInTheDocument();
    expect(screen.getByText("Domains that skip analysis.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add" })).toBeInTheDocument();
    expect(screen.getByText("content")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
  });

  it("makes the action bar sticky at the bottom with a paper background and a top divider", () => {
    renderWithProviders(<PanelSection title="T" actions={<button>Save</button>}>x</PanelSection>);
    const bar = screen.getByRole("button", { name: "Save" }).parentElement!;
    const cs = getComputedStyle(bar);
    expect(cs.position).toBe("sticky");
    expect(cs.bottom).toBe("0px");
    expect(cs.borderTopWidth).toBe("1px");
    expect(cs.backgroundColor).not.toBe("rgba(0, 0, 0, 0)");
  });

  it("renders no action bar, purpose or toolbar when they are not provided", () => {
    const { container } = renderWithProviders(<PanelSection title="T">x</PanelSection>);
    expect(container.querySelectorAll("[data-panel-actions]")).toHaveLength(0);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("keeps the title weight at 700 or below with no letter spacing", () => {
    renderWithProviders(<PanelSection title="Weighted">x</PanelSection>);
    const cs = getComputedStyle(screen.getByRole("heading", { name: "Weighted" }));
    expect(Number(cs.fontWeight)).toBeLessThanOrEqual(700);
    expect(["normal", "0px"]).toContain(cs.letterSpacing);
  });

  it("labels the section by its heading", () => {
    renderWithProviders(<PanelSection title="Scoring">x</PanelSection>);
    expect(screen.getByRole("region", { name: "Scoring" })).toBeInTheDocument();
  });
});
