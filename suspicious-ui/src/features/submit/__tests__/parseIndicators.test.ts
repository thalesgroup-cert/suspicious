import { describe, it, expect } from "vitest";
import { parseIndicators } from "../parseIndicators";

describe("parseIndicators", () => {
  it("splits, refangs, types, dedupes", () => {
    const out = parseIndicators("hxxp://evil[.]com\n8.8.8.8, 8.8.8.8\n" + "a".repeat(64));
    expect(out.map((p) => [p.value, p.type])).toEqual([
      ["http://evil.com", "url"],
      ["8.8.8.8", "ip"],
      ["a".repeat(64), "hash"],
    ]);
  });
  it("flags junk with null type", () => {
    expect(parseIndicators("!!!")[0].type).toBeNull();
  });
});
