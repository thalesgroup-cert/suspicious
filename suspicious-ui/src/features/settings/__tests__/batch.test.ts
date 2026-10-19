import { describe, expect, it, vi } from "vitest";
import { runBatch, summarise } from "../batch";

describe("runBatch", () => {
  it("returns every item as ok when all succeed", async () => {
    const res = await runBatch([1, 2, 3], async () => "x");
    expect(res.ok).toEqual([1, 2, 3]);
    expect(res.failed).toEqual([]);
  });

  it("keeps going after a middle failure and records the error", async () => {
    const boom = new Error("boom");
    const op = vi.fn(async (n: number) => {
      if (n === 2) throw boom;
    });
    const res = await runBatch([1, 2, 3], op);
    expect(op).toHaveBeenCalledTimes(3);
    expect(res.ok).toEqual([1, 3]);
    expect(res.failed).toEqual([{ item: 2, error: boom }]);
  });

  it("reports everything failed without rejecting", async () => {
    const res = await runBatch(["a", "b"], async () => {
      throw new Error("no");
    });
    expect(res.ok).toEqual([]);
    expect(res.failed.map((f) => f.item)).toEqual(["a", "b"]);
  });

  it("handles an empty list", async () => {
    expect(await runBatch([], async () => 1)).toEqual({ ok: [], failed: [] });
  });

  it("never rejects, even for a synchronous throw", async () => {
    const res = await runBatch([1], (() => {
      throw new Error("sync");
    }) as never);
    expect(res.failed).toHaveLength(1);
  });

  it("runs sequentially, preserving order", async () => {
    const log: string[] = [];
    await runBatch([1, 2, 3], async (n) => {
      log.push(`start${n}`);
      await new Promise((r) => setTimeout(r, 5 - n));
      log.push(`end${n}`);
    });
    expect(log).toEqual(["start1", "end1", "start2", "end2", "start3", "end3"]);
  });
});

describe("summarise", () => {
  it("states real counts with failures", () => {
    expect(summarise([1, 2, 3], [{ item: 4, error: 0 }, { item: 5, error: 0 }], "deleted")).toBe(
      "3 of 5 deleted, 2 failed",
    );
  });

  it("omits the failure clause when nothing failed", () => {
    expect(summarise([1, 2], [], "saved")).toBe("2 of 2 saved");
  });
});
