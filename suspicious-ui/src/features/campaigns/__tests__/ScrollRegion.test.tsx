import { describe, it, expect } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import ScrollRegion from "../components/ScrollRegion";

const shadow = () => getComputedStyle(screen.getByRole("region", { name: "Review lists" })).boxShadow;
const lines = (n: number) => Array.from({ length: n }, (_, i) => <p key={i} style={{ margin: 0, height: 20 }}>Line {i}</p>);

describe("ScrollRegion", () => {
  it("is a focusable, named region", () => {
    renderWithProviders(<ScrollRegion label="Review lists">{lines(2)}</ScrollRegion>);
    expect(screen.getByRole("region", { name: "Review lists" })).toHaveAttribute("tabindex", "0");
  });

  it("shows a cue only while content continues below, and none when it fits", async () => {
    const { unmount } = renderWithProviders(
      <ScrollRegion label="Review lists" sx={{ height: 60, overflowY: "auto" }}>
        {lines(10)}
      </ScrollRegion>
    );
    await waitFor(() => expect(shadow()).not.toBe("none"));

    const region = screen.getByRole("region", { name: "Review lists" });
    region.scrollTop = region.scrollHeight;
    await waitFor(() => expect(shadow()).toBe("none"));
    unmount();

    renderWithProviders(
      <ScrollRegion label="Review lists" sx={{ height: 200, overflowY: "auto" }}>
        {lines(2)}
      </ScrollRegion>
    );
    await new Promise((r) => setTimeout(r, 50));
    expect(shadow()).toBe("none");
  });
});
