import { vi } from "vitest";

/**
 * Tests run in a real browser whose default viewport is narrow: pin the MUI breakpoint (and
 * prefers-reduced-motion) explicitly. Undo with `vi.unstubAllGlobals()`.
 */
export function stubMatchMedia({ phone = false, reducedMotion = false } = {}) {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: query.includes("reduced-motion")
      ? reducedMotion
      : phone
        ? query.includes("max-width")
        : query.includes("min-width"),
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    onchange: null,
    dispatchEvent: () => false,
  }));
}
