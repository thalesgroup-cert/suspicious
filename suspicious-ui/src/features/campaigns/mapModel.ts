// The map's data rules without any rendering: which points show, what colour each one gets, what the text says.
// Pure, so the colour modes and the date filter are tested without WebGL.
import { decomposeColor, rgbToHex } from "@mui/material/styles";

import type { PcaPoint } from "@/features/campaigns/api";
import { plural } from "@/features/dashboard/format";
import { ensureContrast } from "@/shared/lib/contrast";
import { NO_DATE, recencyRamp } from "./geometry";
import { SERIES, classKey, classLabel, type SeriesKey } from "./utils";

export type ColourMode = "category" | "campaign" | "age";

/** The sorted distinct days (YYYY-MM-DD) present in the sample. */
export function uniqueDates(points: PcaPoint[]): string[] {
  return [...new Set(points.map((p) => p.date).filter((d): d is string => !!d))].sort();
}

/**
 * Which points are shown. `range` null = no date filter, so messages without a date stay;
 * with a range, a message without a date cannot be placed in it and is hidden.
 */
export function visibleMask(points: PcaPoint[], hidden: ReadonlySet<SeriesKey>, range: { from: string; to: string } | null): boolean[] {
  return points.map((p) => {
    if (hidden.has(classKey(p.label))) return false;
    if (!range) return true;
    return !!p.date && p.date >= range.from && p.date <= range.to;
  });
}

const channels = (c: string) => decomposeColor(c).values.slice(0, 3);

/** A colour `t` (0..1) of the way from `old` to `newest`, in sRGB. */
export function ageColour(t: number, old: string, newest: string): string {
  const [a, b] = [channels(old), channels(newest)];
  return rgbToHex(`rgb(${a.map((v, i) => Math.round(v + (b[i] - v) * t)).join(",")})`);
}

export type ColourContext = {
  classColors: Record<SeriesKey, string>;
  /** case id -> index into `campaignColours`. */
  campaignOf: ReadonlyMap<string, number>;
  campaignColours: string[];
  /** Messages in no coloured campaign. */
  neutral: string;
  age: { min: string; max: string; old: string; newest: string; none: string };
};

/** One colour per point for the chosen mode. */
export function pointColours(points: PcaPoint[], mode: ColourMode, ctx: ColourContext): string[] {
  return points.map((p) => {
    if (mode === "category") return ctx.classColors[classKey(p.label)];
    if (mode === "campaign") {
      const i = p.suspicious_case_id ? ctx.campaignOf.get(p.suspicious_case_id) : undefined;
      return i === undefined ? ctx.neutral : (ctx.campaignColours[i] ?? ctx.neutral);
    }
    const t = recencyRamp(p.date, ctx.age.min, ctx.age.max);
    return t === NO_DATE ? ctx.age.none : ageColour(t, ctx.age.old, ctx.age.newest);
  });
}

// Okabe and Ito's colour-blind-safe set, without black and yellow (yellow darkened to 3:1 on a light page is olive, next to the green).
const OKABE_ITO = ["#0072B2", "#E69F00", "#009E73", "#CC79A7", "#56B4E9", "#D55E00"];

/** The six campaign colours, each moved far enough from the canvas background to be seen (3:1 for marks). */
export function campaignPalette(background: string): string[] {
  return OKABE_ITO.map((c) => ensureContrast(c, background, 3));
}

const pct = (v: number) => `${Math.round(v * 100)}%`;

/** The line under the map's title: the variance of the components drawn, what the sample is, and the caveat. */
export function mapCaption(variance: number[], mode: "3d" | "2d", sampleLimit?: number): string {
  const parts: string[] = [];
  if (mode === "3d") {
    if (variance.length >= 3) parts.push(`PC1 ${pct(variance[0])} + PC2 ${pct(variance[1])} + PC3 ${pct(variance[2])} of the variance.`);
  } else if (variance.length >= 2) {
    parts.push(`PC1 ${pct(variance[0])} + PC2 ${pct(variance[1])} of the variance${variance.length > 2 ? " (PC3 not shown)" : ""}.`);
  }
  if (sampleLimit !== undefined) parts.push(`Sample of up to ${sampleLimit.toLocaleString()} messages from the whole store, not limited to the selected period.`);
  parts.push("Closeness is not proof of a campaign.");
  return parts.join(" ");
}

/** The text a screen reader gets for the canvas: the counts per class present, and the keys. */
export function mapDescription(points: PcaPoint[]): string {
  const counts = new Map<SeriesKey, number>();
  for (const p of points) counts.set(classKey(p.label), (counts.get(classKey(p.label)) ?? 0) + 1);
  const by = SERIES.filter(([k]) => counts.has(k)).map(([k]) => `${classLabel(k)} ${counts.get(k)}`);
  const head = points.length ? `${plural(points.length, "message")}: ${by.join(", ")}.` : "0 messages.";
  return `${head} Rotate with the arrow keys, zoom with + and -, reset with 0.`;
}
