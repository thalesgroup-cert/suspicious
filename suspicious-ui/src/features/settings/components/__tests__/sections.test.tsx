import { describe, expect, it } from "vitest";
import { GROUPS, SECTIONS, parseSection } from "../sections";

describe("parseSection", () => {
  it("accepts every known key", () => {
    for (const s of SECTIONS) expect(parseSection(s.key)).toBe(s.key);
  });
  it("rejects unknown and missing values", () => {
    expect(parseSection("nope")).toBeNull();
    expect(parseSection(undefined)).toBeNull();
    expect(parseSection("")).toBeNull();
  });
  it("tolerates a trailing slash", () => {
    expect(parseSection("scoring/")).toBe("scoring");
  });
});

describe("GROUPS", () => {
  it("lists the five labelled groups covering every section once", () => {
    expect(GROUPS.map((g) => g.label)).toEqual([
      "Detection lists",
      "Access",
      "Ingestion",
      "Scoring",
      "Integrations",
    ]);
    expect(GROUPS.flatMap((g) => g.sections.map((s) => s.key)).sort()).toEqual(
      SECTIONS.map((s) => s.key).sort(),
    );
  });
});
