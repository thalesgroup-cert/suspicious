import { describe, expect, it } from "vitest";
import { GROUPS, SECTIONS, isSectionVisible, parseSection } from "../sections";

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

describe("ai_model section", () => {
  const meta = SECTIONS.find((s) => s.key === "ai_model");
  it("is an integrations section", () => {
    expect(meta?.group).toBe("integrations");
    expect(parseSection("ai_model")).toBe("ai_model");
  });
  it("is visible only to an Admin while the connector is enabled", () => {
    const m = meta!;
    expect(isSectionVisible(m, ["Admin"], ["ai_model"])).toBe(true);
    expect(isSectionVisible(m, ["CERT"], ["ai_model"])).toBe(false);
    expect(isSectionVisible(m, ["Admin"], [])).toBe(false);
    expect(isSectionVisible(SECTIONS[0], ["CERT"], [])).toBe(true);
  });
});
