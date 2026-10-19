import { describe, it, expect } from "vitest";
import type { PcaPoint } from "@/features/campaigns/api";
import { contrastRatio } from "@/shared/lib/contrast";
import { ageColour, ageEnds, campaignPalette, mapCaption, mapDescription, pointColours, uniqueDates, visibleMask, type ColourContext } from "../mapModel";

const pt = (label: string, id: string | null, date: string | null): PcaPoint => ({
  x: 0, y: 0, z: 0, label, suspicious_case_id: id, mail_subject: null, sourceRefs: [], date,
});

describe("uniqueDates", () => {
  it("lists the distinct days present, oldest first, skipping missing ones", () => {
    expect(uniqueDates([pt("SAFE", "1", "2026-10-12"), pt("SAFE", "2", null), pt("SAFE", "3", "2026-10-03"), pt("SAFE", "4", "2026-10-12")])).toEqual(["2026-10-03", "2026-10-12"]);
    expect(uniqueDates([])).toEqual([]);
    expect(uniqueDates([pt("SAFE", "1", null)])).toEqual([]);
  });
});

describe("visibleMask", () => {
  const pts = [pt("SAFE", "1", "2026-10-01"), pt("DANGEROUS", "2", "2026-10-05"), pt("DANGEROUS", "3", "2026-10-09"), pt("UNKNOWN", "4", null)];

  it("shows everything, including messages without a date, when nothing is filtered", () => {
    expect(visibleMask(pts, new Set(), null)).toEqual([true, true, true, true]);
  });

  it("hides the classes switched off", () => {
    expect(visibleMask(pts, new Set(["DANGEROUS"]), null)).toEqual([true, false, false, true]);
    expect(visibleMask(pts, new Set(["UNKNOWN"]), null)).toEqual([true, true, true, false]);
  });

  it("keeps the days in the range, both ends included, and hides messages without a date", () => {
    expect(visibleMask(pts, new Set(), { from: "2026-10-05", to: "2026-10-09" })).toEqual([false, true, true, false]);
    expect(visibleMask(pts, new Set(["DANGEROUS"]), { from: "2026-10-01", to: "2026-10-09" })).toEqual([true, false, false, false]);
  });
});

describe("ageColour", () => {
  it("runs from the old colour to the new one", () => {
    expect(ageColour(0, "#000000", "#ff8040")).toBe("#000000");
    expect(ageColour(1, "#000000", "#ff8040")).toBe("#ff8040");
    expect(ageColour(0.5, "#000000", "#ff8040")).toBe("#804020");
  });
});

describe("ageEnds", () => {
  it.each([
    ["light", "#ffffff", "#475569", "#2563eb"],
    ["dark", "#0b1220", "#a8b3c4", "#60a5fa"],
    ["paper", "#f4efe4", "#5c5546", "#9a3412"],
  ])("makes the ramp visible against the %s canvas, with ends easy to tell apart", (_n, bg, muted, primary) => {
    const { old, newest } = ageEnds(bg, muted, primary);
    // the old end is as faint as a mark may be (3:1), the new end clearly strong
    expect(contrastRatio(old, bg)).toBeGreaterThanOrEqual(3);
    expect(contrastRatio(old, bg)).toBeLessThan(3.5);
    expect(contrastRatio(newest, bg)).toBeGreaterThanOrEqual(7);
    expect(contrastRatio(old, newest)).toBeGreaterThanOrEqual(2);
  });

  it("keeps a muted colour that is already at or below 3:1 as it is", () => {
    expect(ageEnds("#ffffff", "#aaaaaa", "#2563eb").old).toBe("#aaaaaa");
  });
});

describe("pointColours", () => {
  const ctx: ColourContext = {
    classColors: { SAFE: "#11aa11", UNWANTED: "#aaaa11", SUSPICIOUS: "#dd8811", DANGEROUS: "#cc1111", UNKNOWN: "#777777" },
    campaignOf: new Map([["1", 0], ["2", 1], ["9", 7]]),
    campaignColours: ["#e69f00", "#56b4e9"],
    neutral: "#888888",
    age: { min: "2026-10-01", max: "2026-10-11", old: "#000000", newest: "#ffffff", none: "#c0c0c0" },
  };
  const pts = [pt("SAFE", "1", "2026-10-01"), pt("DANGEROUS", "2", "2026-10-11"), pt("weird", "3", null), pt("SAFE", null, "2026-10-06"), pt("SAFE", "9", "2026-10-06")];

  it("colours by class, with unknown labels as Unclassified", () => {
    expect(pointColours(pts, "category", ctx)).toEqual(["#11aa11", "#cc1111", "#777777", "#11aa11", "#11aa11"]);
  });

  it("colours campaign members, and leaves everything else grey", () => {
    // case 3 is in no campaign, the 4th has no case id, case 9 maps past the colours that exist
    expect(pointColours(pts, "campaign", ctx)).toEqual(["#e69f00", "#56b4e9", "#888888", "#888888", "#888888"]);
  });

  it("colours by age, with its own colour for a missing date", () => {
    expect(pointColours(pts, "age", ctx)).toEqual(["#000000", "#ffffff", "#c0c0c0", "#808080", "#808080"]);
  });

  it("gives an empty list for no points", () => {
    expect(pointColours([], "age", ctx)).toEqual([]);
  });
});

describe("campaignPalette", () => {
  it.each([["#ffffff"], ["#0b1220"], ["#f4efe4"], ["#000000"]])("gives six distinct colours that stand out from %s", (bg) => {
    const colours = campaignPalette(bg);
    expect(colours).toHaveLength(6);
    expect(new Set(colours).size).toBe(6);
    for (const c of colours) {
      expect(c).toMatch(/^#[0-9a-f]{6}$/i);
      expect(contrastRatio(c, bg)).toBeGreaterThanOrEqual(3);
    }
  });
});

describe("mapCaption", () => {
  it("3D: names the three components and the sample", () => {
    expect(mapCaption([0.241, 0.15, 0.09], "3d", 1500)).toBe(
      `PC1 24% + PC2 15% + PC3 9% of the variance. Sample of up to ${(1500).toLocaleString()} messages from the whole store, not limited to the selected period. Closeness is not proof of a campaign.`
    );
  });

  it("2D: names the two plotted components, and says PC3 is not shown when there is one", () => {
    expect(mapCaption([0.25, 0.1, 0.05], "2d", 1500)).toBe(
      `PC1 25% + PC2 10% of the variance (PC3 not shown). Sample of up to ${(1500).toLocaleString()} messages from the whole store, not limited to the selected period. Closeness is not proof of a campaign.`
    );
    expect(mapCaption([0.3, 0.2], "2d", 1500)).toMatch(/^PC1 30% \+ PC2 20% of the variance\. Sample/);
    expect(mapCaption([0.3, 0.2], "2d", 1500)).not.toMatch(/PC3/);
  });

  it("leaves out the variance it was not given and the sample size it does not know", () => {
    expect(mapCaption([], "3d")).toBe("Closeness is not proof of a campaign.");
    expect(mapCaption([0.3], "2d", 10)).toBe("Sample of up to 10 messages from the whole store, not limited to the selected period. Closeness is not proof of a campaign.");
  });
});

describe("mapDescription", () => {
  it("counts the messages per class (only classes present) and tells the keys", () => {
    expect(mapDescription([pt("SAFE", "1", null), pt("SAFE", "2", null), pt("DANGEROUS", "3", null), pt("x", null, null)])).toBe(
      "4 messages: Safe 2, Dangerous 1, Unclassified 1. Rotate with the arrow keys, zoom with + and -, reset with 0."
    );
    expect(mapDescription([pt("SAFE", "1", null)])).toBe("1 message: Safe 1. Rotate with the arrow keys, zoom with + and -, reset with 0.");
  });
});
