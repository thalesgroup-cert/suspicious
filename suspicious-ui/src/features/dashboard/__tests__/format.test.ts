import { describe, it, expect } from "vitest";
import { scopeLabel, scopeName } from "../format";

describe("scope labels", () => {
  it("maps country codes to names and leaves the rest alone", () => {
    expect(scopeLabel("My country (AU)")).toBe("My country (Australia)");
    expect(scopeLabel("AU | Off GBU")).toBe("Australia | Off GBU");
    expect(scopeLabel("APAC")).toBe("APAC");
    expect(scopeLabel("Overall")).toBe("Overall");
    expect(scopeLabel("ZZ")).toBe("ZZ");
  });

  it("names the scope for the subtitle", () => {
    expect(scopeName({ key: "OWN_COUNTRY", label: "My country (AU)" })).toBe("Australia");
    expect(scopeName({ key: "COUNTRY:NZ", label: "NZ" })).toBe("New Zealand");
    expect(scopeName({ key: "REGION:APAC", label: "APAC" })).toBe("APAC");
    expect(scopeName({ key: "ALL", label: "Overall" })).toBe("Overall");
  });
});
