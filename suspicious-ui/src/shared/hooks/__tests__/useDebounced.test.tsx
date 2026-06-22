import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useDebounced } from "@/shared/hooks/useDebounced";

describe("useDebounced", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns the initial value synchronously", () => {
    const { result } = renderHook(() => useDebounced("a"));
    expect(result.current).toBe("a");
  });

  it("defers updates until the delay elapses", () => {
    const { result, rerender } = renderHook(({ value }) => useDebounced(value, 200), {
      initialProps: { value: "a" },
    });

    rerender({ value: "b" });
    // Still the old value before the timer fires.
    expect(result.current).toBe("a");

    act(() => {
      vi.advanceTimersByTime(199);
    });
    expect(result.current).toBe("a");

    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(result.current).toBe("b");
  });

  it("resets the timer when the value changes again before it fires (debounce)", () => {
    const { result, rerender } = renderHook(({ value }) => useDebounced(value, 200), {
      initialProps: { value: "a" },
    });

    rerender({ value: "b" });
    act(() => {
      vi.advanceTimersByTime(150);
    });
    // A second change restarts the countdown — "b" must never surface.
    rerender({ value: "c" });
    act(() => {
      vi.advanceTimersByTime(150);
    });
    expect(result.current).toBe("a");

    act(() => {
      vi.advanceTimersByTime(50);
    });
    expect(result.current).toBe("c");
  });

  it("honours a custom delay", () => {
    const { result, rerender } = renderHook(({ value }) => useDebounced(value, 1000), {
      initialProps: { value: 1 },
    });

    rerender({ value: 2 });
    act(() => {
      vi.advanceTimersByTime(999);
    });
    expect(result.current).toBe(1);

    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(result.current).toBe(2);
  });
});
