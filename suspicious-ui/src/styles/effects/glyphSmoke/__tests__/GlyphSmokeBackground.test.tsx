import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { GlyphSmokeBackground } from "../GlyphSmokeBackground";
import type { GlyphSmoke } from "../engine";

type WithHook = HTMLCanvasElement & { __glyphSmoke?: GlyphSmoke };
const hook = () => (screen.getByTestId("glyph-smoke") as WithHook).__glyphSmoke!;

function fire(type: "pointermove" | "pointerdown", x: number, y: number) {
  window.dispatchEvent(new PointerEvent(type, { clientX: x, clientY: y, bubbles: true }));
}

afterEach(() => vi.restoreAllMocks());

describe("GlyphSmokeBackground", () => {
  it("renders an inert canvas behind the app", () => {
    render(<GlyphSmokeBackground />);
    const c = screen.getByTestId("glyph-smoke");
    expect(c).toHaveAttribute("aria-hidden", "true");
    expect(c.style.pointerEvents).toBe("none");
    expect(c.style.zIndex).toBe("-1");
  });

  it("lights glyphs under the pointer", () => {
    render(<GlyphSmokeBackground />);
    const s = hook();
    fire("pointermove", 400, 300);
    s.renderOnce(1);
    expect(s.stats.hoverCells).toBeGreaterThan(50);
  });

  it("a click starts a ripple", () => {
    render(<GlyphSmokeBackground />);
    const s = hook();
    fire("pointerdown", 500, 300);
    s.renderOnce(1);
    expect(s.stats.ripples).toBe(1);
  });

  it("once the logo has loaded, a ripple lights cells in the logo's shape", async () => {
    render(<GlyphSmokeBackground />);
    const s = hook();
    await waitFor(() => expect(s.stats.logoReady).toBe(true), { timeout: 5000 });
    s.debug.freeze = true;
    s.debug.spawn(innerWidth / 2, innerHeight / 2, 0.6);
    s.renderOnce(1);
    expect(s.stats.rippleCells).toBeGreaterThan(40);
  });

  it("a ripple past its lifetime lights nothing", async () => {
    render(<GlyphSmokeBackground />);
    const s = hook();
    await waitFor(() => expect(s.stats.logoReady).toBe(true), { timeout: 5000 });
    s.debug.freeze = true;
    s.debug.spawn(innerWidth / 2, innerHeight / 2, 3);
    s.renderOnce(1);
    expect(s.stats.rippleCells).toBe(0);
  });

  it("stops listening after unmount", () => {
    const { unmount } = render(<GlyphSmokeBackground />);
    const s = hook();
    const spy = vi.spyOn(s, "ripple");
    unmount();
    fire("pointerdown", 10, 10);
    expect(spy).not.toHaveBeenCalled();
  });

  it("draws one still frame and ignores the pointer under prefers-reduced-motion", () => {
    vi.spyOn(window, "matchMedia").mockImplementation((q: string) => ({ matches: q.includes("reduce"), media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false, onchange: null }) as MediaQueryList);
    render(<GlyphSmokeBackground />);
    const s = hook();
    expect(s.stats.frames).toBe(1);
    fire("pointermove", 400, 300);
    fire("pointerdown", 400, 300);
    s.renderOnce(1);
    expect(s.stats.hoverCells).toBe(0);
    expect(s.stats.ripples).toBe(0);
  });
});
