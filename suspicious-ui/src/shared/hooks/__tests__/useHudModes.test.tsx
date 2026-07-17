import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useHudModes } from "@/shared/hooks/useHudModes";

const KEY_PIXEL = "ui.hud.pixel";
const KEY_ALERT = "ui.hud.alert";

describe("useHudModes", () => {
  beforeEach(() => {
    localStorage.clear();
    delete document.body.dataset.pixel;
    delete document.body.dataset.alert;
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("defaults both modes to off when nothing is persisted", () => {
    const { result } = renderHook(() => useHudModes());
    expect(result.current.pixel).toBe(false);
    expect(result.current.alert).toBe(false);
  });

  it("hydrates initial state from localStorage", () => {
    localStorage.setItem(KEY_PIXEL, "1");
    localStorage.setItem(KEY_ALERT, "0");

    const { result } = renderHook(() => useHudModes());
    expect(result.current.pixel).toBe(true);
    expect(result.current.alert).toBe(false);
  });

  it("persists toggled state and reflects it on document.body datasets", () => {
    const { result } = renderHook(() => useHudModes());

    act(() => {
      result.current.setPixel(true);
    });

    expect(result.current.pixel).toBe(true);
    expect(localStorage.getItem(KEY_PIXEL)).toBe("1");
    expect(document.body.dataset.pixel).toBe("on");

    act(() => {
      result.current.setPixel(false);
    });

    expect(localStorage.getItem(KEY_PIXEL)).toBe("0");
    expect(document.body.dataset.pixel).toBe("off");
  });

  it("tracks pixel and alert independently", () => {
    const { result } = renderHook(() => useHudModes());

    act(() => {
      result.current.setAlert(true);
    });

    expect(result.current.alert).toBe(true);
    expect(result.current.pixel).toBe(false);
    expect(localStorage.getItem(KEY_ALERT)).toBe("1");
    expect(document.body.dataset.alert).toBe("on");
    expect(document.body.dataset.pixel).toBe("off");
  });
});
