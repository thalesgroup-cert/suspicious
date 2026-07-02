import { describe, it, expect } from "vitest";
import {
  clamp,
  getConfidenceTone,
  getRiskTone,
  groupReportsByArtifact,
  kindLabel,
  normalizeConfidence,
  normalizeScore,
  prettySummary,
  readType,
  summarizeForReading,
} from "@/shared/lib/scoreUtils";

describe("scoreUtils numeric normalization", () => {
  it("normalizes scores from either 0..10 or 0..100 scales", () => {
    expect(normalizeScore(5)).toBe(50);
    expect(normalizeScore(73)).toBe(73);
    expect(normalizeScore(undefined)).toBe(0);
    expect(clamp(-1)).toBe(0);
    expect(clamp(999)).toBe(100);
  });

  it("normalizes confidence from fraction, 0..10 or percent", () => {
    expect(normalizeConfidence(0.8)).toBe(80);
    expect(normalizeConfidence(7)).toBe(70);
    expect(normalizeConfidence(55)).toBe(55);
  });

  it("labels risk and confidence by threshold", () => {
    expect(getRiskTone(9).label).toBe("High risk");
    expect(getRiskTone(6).label).toBe("Needs attention");
    expect(getRiskTone(1).label).toBe("Low risk");
    expect(getConfidenceTone(0.9).label).toBe("High confidence");
    expect(getConfidenceTone(0.2).label).toBe("Low confidence");
  });
});

describe("scoreUtils labels (unified, case-insensitive)", () => {
  it("readType accepts upper- or lower-case tokens alike", () => {
    expect(readType("FILE")).toBe("File check");
    expect(readType("file")).toBe("File check");
    expect(readType("URL")).toBe("Link check");
    expect(readType("nope")).toBe("nope");
  });

  it("kindLabel is case-insensitive", () => {
    expect(kindLabel("file")).toBe("File");
    expect(kindLabel("MAIL_BODY")).toBe("Mail body");
    expect(kindLabel("xyz")).toBe("xyz");
  });
});

describe("prettySummary", () => {
  it("handles strings, arrays, objects and empties", () => {
    expect(prettySummary("hi")).toBe("hi");
    expect(prettySummary(["a", "b"])).toBe("a\nb");
    expect(prettySummary({ verdict: "clean" })).toBe("clean");
    expect(prettySummary(null)).toBeNull();
  });
});

describe("summarizeForReading", () => {
  it("composes a human sentence from a ReportLike", () => {
    const text = summarizeForReading({
      analyzer_name: "YARA",
      score: 9,
      confidence: 0.9,
      target: { value: "evil.exe" },
      categories: ["malware"],
    });
    expect(text).toContain("YARA marked this item as high risk.");
    expect(text).toContain("Checked item: evil.exe.");
    expect(text).toContain("Detected type: malware.");
  });
});

describe("groupReportsByArtifact (generic)", () => {
  it("groups by kind+value and preserves the caller's element type", () => {
    const reports = [
      { id: 1, target: { kind: "URL", value: "a.com" } },
      { id: 2, target: { kind: "URL", value: "a.com" } },
      { id: 3, target: { kind: "FILE", value: "x" } },
    ];
    const groups = groupReportsByArtifact(reports);
    expect(groups.map((g) => g.key)).toEqual(["URL::a.com", "FILE::x"]);
    // Element type is preserved (T = the input object), so `.id` is accessible.
    expect(groups[0].reports[0].id).toBe(1);
    expect(groups[0].reports).toHaveLength(2);
  });
});
