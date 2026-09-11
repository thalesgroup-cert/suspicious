import { describe, it, expect } from "vitest";
import { parseEnrichment } from "../enrichment";

describe("parseEnrichment", () => {
  it("parses a full VT enrichment", () => {
    const e = parseEnrichment({
      source: "virustotal", malicious_count: 42, total: 70,
      as_owner: "Google LLC", country: "US",
      vendors: [{ name: "K", category: "malicious", result: "Trojan" }],
    });
    expect(e?.as_owner).toBe("Google LLC");
    expect(e?.vendors?.[0].category).toBe("malicious");
  });
  it("returns undefined for null / garbage", () => {
    expect(parseEnrichment(null)).toBeUndefined();
    expect(parseEnrichment({ nope: 1 })).toBeUndefined();
  });
  it("accepts a sparse enrichment", () => {
    expect(parseEnrichment({ source: "virustotal" })?.source).toBe("virustotal");
  });
});
