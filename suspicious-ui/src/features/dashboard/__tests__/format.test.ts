import { describe, it, expect } from "vitest";
import { fieldLabelSx, percents, scopeLabel, scopeName } from "../format";
import { themes } from "@/styles/themes";
import { contrastRatio } from "@/shared/lib/contrast";

describe("scope labels", () => {
  it("maps country codes only for own-country and country scopes", () => {
    expect(scopeLabel("My country (AU)", "OWN_COUNTRY")).toBe("My country (Australia)");
    expect(scopeLabel("NZ", "COUNTRY:NZ")).toBe("New Zealand");
    expect(scopeLabel("ZZ", "COUNTRY:ZZ")).toBe("ZZ");
    expect(scopeLabel("HR | Off GBU", "OWN_SCOPE")).toBe("HR | Off GBU");
    expect(scopeLabel("EU", "REGION:EU")).toBe("EU");
    expect(scopeLabel("APAC", "REGION:APAC")).toBe("APAC");
    expect(scopeLabel("Overall", "ALL")).toBe("Overall");
  });

  it("names the scope for the subtitle", () => {
    expect(scopeName({ key: "OWN_COUNTRY", label: "My country (AU)" })).toBe("Australia");
    expect(scopeName({ key: "COUNTRY:NZ", label: "NZ" })).toBe("New Zealand");
    expect(scopeName({ key: "OWN_SCOPE", label: "IT | Off GBU" })).toBe("IT | Off GBU");
    expect(scopeName({ key: "REGION:APAC", label: "APAC" })).toBe("APAC");
    expect(scopeName({ key: "ALL", label: "Overall" })).toBe("Overall");
  });
});

describe("percents", () => {
  it("adds up to exactly 100 and is all zeros for no data", () => {
    expect(percents([200, 80, 150, 60, 1])).toEqual([41, 16, 31, 12, 0]);
    expect(percents([1, 1, 1])).toEqual([34, 33, 33]);
    expect(percents([0, 0])).toEqual([0, 0]);
  });
});

describe("fieldLabelSx", () => {
  it("gives the header field labels at least 5:1 at rest and focused, on paper and page background, in every theme", () => {
    for (const [name, theme] of Object.entries(themes)) {
      const sx = fieldLabelSx(theme.palette);
      for (const color of [sx.color, sx["&.Mui-focused"].color]) {
        for (const bg of [theme.palette.background.paper, theme.palette.background.default]) {
          expect(contrastRatio(color, bg), `${name} ${color} on ${bg}`).toBeGreaterThanOrEqual(5);
        }
      }
    }
  });
});
