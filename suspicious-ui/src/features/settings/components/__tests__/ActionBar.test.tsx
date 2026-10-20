import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";

import { renderWithProviders } from "@/test/utils";
import { ActionBar } from "../ActionBar";

describe("ActionBar", () => {
  it("is a sticky bottom bar with a paper background and a top divider", () => {
    renderWithProviders(<ActionBar><button>Save</button></ActionBar>);
    const bar = screen.getByRole("button", { name: "Save" }).parentElement!;
    const cs = getComputedStyle(bar);
    expect(bar).toHaveAttribute("data-panel-actions");
    expect(cs.position).toBe("sticky");
    expect(cs.bottom).toBe("0px");
    expect(cs.borderTopWidth).toBe("1px");
    expect(cs.backgroundColor).not.toBe("rgba(0, 0, 0, 0)");
  });
});
