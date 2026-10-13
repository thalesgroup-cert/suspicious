import { describe, it, expect } from "vitest";
import { scopeLabel, scopeName } from "../format";

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
