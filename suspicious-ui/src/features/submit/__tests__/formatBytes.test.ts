import { describe, it, expect } from "vitest";
import { formatBytes } from "@/features/submit/formatBytes";

describe("formatBytes", () => {
  it.each([
    [0, "0 B"],
    [1, "1 B"],
    [1023, "1023 B"],
    [1024, "1 KB"],
    [1536, "1.5 KB"],
    [5242880, "5 MB"],
    [1073741824, "1 GB"],
  ])("%i -> %s", (n, out) => expect(formatBytes(n)).toBe(out));
});
