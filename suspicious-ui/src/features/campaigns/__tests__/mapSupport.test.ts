import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ROTATE_STEP, ZOOM_STEP, detectWebGL, handleMapKey, resetWebGLDetection, type MapControlsApi } from "../mapSupport";

function fakeControls() {
  return { rotate: vi.fn(), zoom: vi.fn(), reset: vi.fn(), clearSelection: vi.fn() } satisfies MapControlsApi;
}
const key = (k: string, mods: Partial<{ ctrlKey: boolean; metaKey: boolean; altKey: boolean }> = {}) => ({ key: k, preventDefault: vi.fn(), ...mods });

describe("handleMapKey", () => {
  it.each([
    ["ArrowLeft", [ROTATE_STEP, 0]],
    ["ArrowRight", [-ROTATE_STEP, 0]],
    ["ArrowUp", [0, ROTATE_STEP]],
    ["ArrowDown", [0, -ROTATE_STEP]],
  ])("%s rotates the view by one step", (k, args) => {
    const api = fakeControls();
    const e = key(k);
    expect(handleMapKey(e, api)).toBe(true);
    expect(api.rotate).toHaveBeenCalledExactlyOnceWith(...args);
    expect(e.preventDefault).toHaveBeenCalled();
  });

  it.each([["+"], ["="]])("%s zooms in", (k) => {
    const api = fakeControls();
    expect(handleMapKey(key(k), api)).toBe(true);
    expect(api.zoom).toHaveBeenCalledExactlyOnceWith(1 / ZOOM_STEP);
  });

  it.each([["-"], ["_"]])("%s zooms out", (k) => {
    const api = fakeControls();
    expect(handleMapKey(key(k), api)).toBe(true);
    expect(api.zoom).toHaveBeenCalledExactlyOnceWith(ZOOM_STEP);
  });

  it("0 resets the view and Escape clears the selection", () => {
    const api = fakeControls();
    expect(handleMapKey(key("0"), api)).toBe(true);
    expect(api.reset).toHaveBeenCalledOnce();
    expect(handleMapKey(key("Escape"), api)).toBe(true);
    expect(api.clearSelection).toHaveBeenCalledOnce();
  });

  it("leaves every other key, and the browser's own Ctrl/Cmd/Alt shortcuts, alone", () => {
    const api = fakeControls();
    for (const e of [key("Tab"), key("a"), key("Enter"), key("+", { ctrlKey: true }), key("-", { metaKey: true }), key("0", { ctrlKey: true }), key("ArrowLeft", { altKey: true })]) {
      expect(handleMapKey(e, api)).toBe(false);
      expect(e.preventDefault).not.toHaveBeenCalled();
    }
    for (const fn of Object.values(api)) expect(fn).not.toHaveBeenCalled();
  });
});

describe("detectWebGL", () => {
  const realCreate = document.createElement.bind(document);
  let created = 0;

  function stubCanvas(getContext: (type: string) => unknown) {
    created = 0;
    vi.spyOn(document, "createElement").mockImplementation(((tag: string) => {
      if (tag !== "canvas") return realCreate(tag);
      created++;
      return { getContext } as unknown as HTMLCanvasElement;
    }) as typeof document.createElement);
  }

  beforeEach(() => resetWebGLDetection());
  afterEach(() => vi.restoreAllMocks());

  it("is true when webgl2 is available, and asks for nothing else", () => {
    const asked: string[] = [];
    stubCanvas((t) => {
      asked.push(t);
      return t === "webgl2" ? { getExtension: () => null } : null;
    });
    expect(detectWebGL()).toBe(true);
    expect(asked).toEqual(["webgl2"]);
  });

  it("is false with only WebGL 1: three.js 0.186 draws with WebGL 2, so 3D would fail where this said yes", () => {
    const asked: string[] = [];
    stubCanvas((t) => {
      asked.push(t);
      return t === "webgl" ? { getExtension: () => null } : null;
    });
    expect(detectWebGL()).toBe(false);
    expect(asked).not.toContain("webgl");
  });

  it("is false when no context can be made", () => {
    stubCanvas(() => null);
    expect(detectWebGL()).toBe(false);
  });

  it("is false when asking for a context throws", () => {
    stubCanvas(() => {
      throw new Error("blocked");
    });
    expect(detectWebGL()).toBe(false);
  });

  it("gives the test context back and asks only once", () => {
    const lose = vi.fn();
    stubCanvas(() => ({ getExtension: (n: string) => (n === "WEBGL_lose_context" ? { loseContext: lose } : null) }));
    expect(detectWebGL()).toBe(true);
    expect(detectWebGL()).toBe(true);
    expect(created).toBe(1);
    expect(lose).toHaveBeenCalledOnce();
  });
});
