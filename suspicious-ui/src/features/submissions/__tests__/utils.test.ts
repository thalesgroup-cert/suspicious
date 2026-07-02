import { describe, it, expect } from "vitest";
import type { SubmissionAnalyzerReport } from "@/features/submissions/api";
import {
  clamp,
  getConfidenceTone,
  getRiskTone,
  groupReportsByArtifact,
  kindLabel,
  normalizeConfidence,
  normalizeScore,
  prettyResult,
  prettySummary,
  readStatus,
  readType,
  toBackendOrdering,
  withinDates,
} from "@/features/submissions/utils";

const report = (over: Partial<SubmissionAnalyzerReport>) =>
  over as unknown as SubmissionAnalyzerReport;

describe("clamp", () => {
  it("bounds within the default 0..100 range", () => {
    expect(clamp(-5)).toBe(0);
    expect(clamp(150)).toBe(100);
    expect(clamp(42)).toBe(42);
  });

  it("honours custom bounds", () => {
    expect(clamp(5, 1, 3)).toBe(3);
    expect(clamp(0, 1, 3)).toBe(1);
  });
});

describe("normalizeScore", () => {
  it("returns 0 for non-numbers", () => {
    expect(normalizeScore(undefined)).toBe(0);
    expect(normalizeScore(null)).toBe(0);
    expect(normalizeScore(NaN)).toBe(0);
  });

  it("scales a 0..10 score up to 0..100", () => {
    expect(normalizeScore(5)).toBe(50);
    expect(normalizeScore(10)).toBe(100);
  });

  it("treats values above 10 as already 0..100 and clamps", () => {
    expect(normalizeScore(73)).toBe(73);
    expect(normalizeScore(250)).toBe(100);
  });
});

describe("normalizeConfidence", () => {
  it("returns 0 for non-numbers", () => {
    expect(normalizeConfidence(undefined)).toBe(0);
  });

  it("scales a 0..1 fraction to a percentage", () => {
    expect(normalizeConfidence(0.8)).toBe(80);
  });

  it("scales a 0..10 value to a percentage", () => {
    expect(normalizeConfidence(7)).toBe(70);
  });

  it("treats larger values as a percentage and clamps", () => {
    expect(normalizeConfidence(55)).toBe(55);
    expect(normalizeConfidence(200)).toBe(100);
  });
});

describe("getRiskTone", () => {
  it("labels by normalized score thresholds", () => {
    expect(getRiskTone(8).label).toBe("High risk");
    expect(getRiskTone(5.5).label).toBe("Needs attention");
    expect(getRiskTone(3).label).toBe("Low risk");
  });
});

describe("getConfidenceTone", () => {
  it("labels by normalized confidence thresholds", () => {
    expect(getConfidenceTone(0.8).label).toBe("High confidence");
    expect(getConfidenceTone(0.5).label).toBe("Medium confidence");
    expect(getConfidenceTone(0.2).label).toBe("Low confidence");
  });
});

describe("readStatus / readType / prettyResult", () => {
  it("maps known statuses and passes through unknown", () => {
    expect(readStatus("DONE")).toBe("Finished");
    expect(readStatus("in_progress")).toBe("Running");
    expect(readStatus("WAT")).toBe("WAT");
    expect(readStatus()).toBe("Unknown");
  });

  it("maps known types", () => {
    expect(readType("FILE")).toBe("File check");
    expect(readType("url")).toBe("Link check");
  });

  it("prettifies results", () => {
    expect(prettyResult("SAFE")).toBe("Safe");
    expect(prettyResult("DANGEROUS")).toBe("Dangerous");
    expect(prettyResult(undefined)).toBe("Unknown");
  });
});

describe("prettySummary", () => {
  it("returns null for empty input", () => {
    expect(prettySummary(null)).toBeNull();
    expect(prettySummary(undefined)).toBeNull();
  });

  it("passes strings through and joins arrays", () => {
    expect(prettySummary("hello")).toBe("hello");
    expect(prettySummary(["a", "b"])).toBe("a\nb");
  });

  it("extracts a known field from an object", () => {
    expect(prettySummary({ summary: "done" })).toBe("done");
    expect(prettySummary({ verdict: "clean" })).toBe("clean");
    expect(prettySummary({ unrelated: 1 })).toBeNull();
  });
});

describe("withinDates", () => {
  it("is inclusive of the day bounds and true when unbounded", () => {
    expect(withinDates("2026-06-10T12:00:00Z")).toBe(true);
    expect(withinDates("2026-06-10T12:00:00", "2026-06-01", "2026-06-30")).toBe(true);
    expect(withinDates("2026-07-10T12:00:00", "2026-06-01", "2026-06-30")).toBe(false);
    expect(withinDates("2026-05-10T12:00:00", "2026-06-01")).toBe(false);
  });
});

describe("toBackendOrdering", () => {
  it("maps UI sort keys to backend ordering", () => {
    expect(toBackendOrdering("date_desc")).toBe("-created_at");
    expect(toBackendOrdering("date_asc")).toBe("created_at");
    expect(toBackendOrdering("id_desc")).toBe("-id");
    expect(toBackendOrdering("id_asc")).toBe("id");
  });
});

describe("kindLabel", () => {
  it("maps known kinds and passes through unknown", () => {
    expect(kindLabel("FILE")).toBe("File");
    expect(kindLabel("MAIL_BODY")).toBe("Mail body");
    expect(kindLabel("WEIRD")).toBe("WEIRD");
  });
});

describe("groupReportsByArtifact", () => {
  it("groups reports by target kind+value, preserving first-seen order", () => {
    const groups = groupReportsByArtifact([
      report({ target: { kind: "URL", id: null, value: "a.com" } }),
      report({ target: { kind: "FILE", id: null, value: "x.zip" } }),
      report({ target: { kind: "URL", id: null, value: "a.com" } }),
    ]);

    expect(groups.map((g) => g.key)).toEqual(["URL::a.com", "FILE::x.zip"]);
    expect(groups[0].reports).toHaveLength(2);
    expect(groups[1].reports).toHaveLength(1);
  });

  it("falls back to UNKNOWN / em-dash when target is missing", () => {
    const [g] = groupReportsByArtifact([report({})]);
    expect(g.kind).toBe("UNKNOWN");
    expect(g.value).toBe("—");
  });
});
