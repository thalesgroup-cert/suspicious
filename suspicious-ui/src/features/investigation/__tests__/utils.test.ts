import { describe, it, expect } from "vitest";
import type { InvestigationDetails } from "@/features/investigation/api";
import {
  groupReportsByArtifact,
  kindLabel,
  pickClassification,
  pickConfidence,
  pickScore,
  readType,
  short,
} from "@/features/investigation/utils";

const details = (over: any) => over as unknown as InvestigationDetails;

describe("short", () => {
  it("returns the trimmed string when within the limit", () => {
    expect(short("  hello  ")).toBe("hello");
    expect(short("abc", 5)).toBe("abc");
  });

  it("truncates with an ellipsis past the limit", () => {
    expect(short("abcdef", 4)).toBe("abc…");
    expect(short("abcdef", 4)).toHaveLength(4);
  });

  it("tolerates nullish input", () => {
    expect(short(undefined as unknown as string)).toBe("");
  });
});

describe("pickScore / pickConfidence / pickClassification", () => {
  it("reads nested case_infos values", () => {
    const d = details({ case_infos: { score: 7, confidence: 0.9, classification: "DANGEROUS" } });
    expect(pickScore(d)).toBe(7);
    expect(pickConfidence(d)).toBe(0.9);
    expect(pickClassification(d)).toBe("DANGEROUS");
  });

  it("falls back when data is missing", () => {
    expect(pickScore(undefined)).toBeNull();
    expect(pickConfidence(details({}))).toBeNull();
    expect(pickClassification(details({}))).toBe("UNKNOWN");
  });
});

describe("readType", () => {
  it("is case-insensitive on the type token", () => {
    expect(readType("FILE")).toBe("File check");
    expect(readType("url")).toBe("Link check");
    expect(readType("Mail")).toBe("Email check");
    expect(readType("weird")).toBe("weird");
  });
});

describe("kindLabel", () => {
  it("maps known kinds case-insensitively and passes through unknown", () => {
    expect(kindLabel("file")).toBe("File");
    expect(kindLabel("MAIL_HEADER")).toBe("Mail header");
    expect(kindLabel("custom")).toBe("custom");
  });
});

describe("groupReportsByArtifact", () => {
  it("groups by kind+value preserving order", () => {
    const groups = groupReportsByArtifact([
      { target: { kind: "URL", value: "a.com" } },
      { target: { kind: "URL", value: "a.com" } },
      { target: { kind: "FILE", value: "x" } },
    ]);
    expect(groups.map((g) => g.key)).toEqual(["URL::a.com", "FILE::x"]);
    expect(groups[0].reports).toHaveLength(2);
  });
});
