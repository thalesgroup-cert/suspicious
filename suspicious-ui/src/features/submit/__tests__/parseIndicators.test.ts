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
  const rows = (t: string) => parseIndicators(t).map((p) => [p.value, p.type]);
  it("collapses prose into one null row between classified tokens", () => {
    const out = parseIndicators("not a thing  mail.example.org 999.1.1.1");
    expect(out.map((p) => [p.raw, p.value, p.type])).toEqual([
      ["not a thing", "not a thing", null],
      ["mail.example.org", "mail.example.org", "domain"],
      ["999.1.1.1", "999.1.1.1", null],
    ]);
  });
  it("refangs the audit paste", () => {
    expect(rows("hxxp://evil[.]example/login?x=1, 198.51.100.7")).toEqual([
      ["http://evil.example/login?x=1", "url"],
      ["198.51.100.7", "ip"],
    ]);
  });
  it("drops case-insensitive duplicates", () => {
    expect(rows("Evil.Example evil.example")).toEqual([["Evil.Example", "domain"]]);
  });
  it("keeps two unrecognised runs separated by a valid token as two rows", () => {
    expect(rows("foo bar 8.8.8.8 baz qux")).toEqual([
      ["foo bar", null],
      ["8.8.8.8", "ip"],
      ["baz qux", null],
    ]);
  });
  it("gives [] for empty and whitespace-only input", () => {
    expect(parseIndicators("")).toEqual([]);
    expect(parseIndicators(" \n\t ")).toEqual([]);
  });
});
