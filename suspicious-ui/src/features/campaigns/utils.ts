import * as React from "react";
import { useTheme } from "@mui/material/styles";
import { onCard } from "@/features/dashboard/format";
import { useResultColors, useStatusColors } from "@/styles/colorStore";

/** The four classifications the message store holds, in severity order, with their display names. */
export const CLASSES = [
  ["SAFE", "Safe"],
  ["UNWANTED", "Unwanted"],
  ["SUSPICIOUS", "Suspicious"],
  ["DANGEROUS", "Dangerous"],
] as const;

export type ClassKey = (typeof CLASSES)[number][0];
/** The four classes plus UNKNOWN: a message the store holds without one of them. */
export type SeriesKey = ClassKey | "UNKNOWN";

export const SERIES: readonly (readonly [SeriesKey, string])[] = [...CLASSES, ["UNKNOWN", "Unclassified"]];

export function normalizeLabel(label: string) {
  return (label || "UNKNOWN").toUpperCase();
}

/** The series a label belongs to: one of the four classes, else UNKNOWN (like the summary's "unclassified"). */
export function classKey(label: string): SeriesKey {
  const k = normalizeLabel(label);
  return CLASSES.some(([c]) => c === k) ? (k as ClassKey) : "UNKNOWN";
}

export function classLabel(label: string): string {
  const key = classKey(label);
  return SERIES.find(([k]) => k === key)![1];
}

/**
 * Class -> mark colour (3:1 on the card). Mapping: Safe=safe, Unwanted=inconclusive,
 * Suspicious=suspicious, Dangerous=dangerous; useResultHex folds Unwanted into suspicious,
 * which would draw two adjacent segments in one colour, so Unwanted takes the neutral verdict colour.
 */
export function useClassColors(): Record<SeriesKey, string> {
  const theme = useTheme();
  const result = useResultColors();
  const status = useStatusColors();
  const c = (hex: string) => onCard(hex, theme.palette, 3);
  return {
    SAFE: c(result.safe.main),
    UNWANTED: c(result.inconclusive.main),
    SUSPICIOUS: c(result.suspicious.main),
    DANGEROUS: c(result.dangerous.main),
    UNKNOWN: c(status.unknown.main),
  };
}

/** "12 Oct" for a date or a datetime, read in UTC like the backend's days. */
export function formatDay(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
}

/** "12 Oct, 09:00 UTC". */
export function formatSeen(iso: string): string {
  const d = new Date(iso);
  if (!iso || Number.isNaN(d.getTime())) return "—";
  const time = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" });
  return `${formatDay(iso)}, ${time} UTC`;
}

export type SortDir = "asc" | "desc";

/** A sorted copy; null/undefined keys always last. Strings compare case-insensitively, digits by value. */
export function sortRows<T>(rows: T[], key: (row: T) => string | number | null | undefined, dir: SortDir): T[] {
  const sign = dir === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    const x = key(a);
    const y = key(b);
    if (x == null || y == null) return x == null ? (y == null ? 0 : 1) : -1;
    const cmp = typeof x === "string" && typeof y === "string" ? x.localeCompare(y, undefined, { sensitivity: "base", numeric: true }) : Number(x) - Number(y);
    return cmp * sign;
  });
}

/** Column sort state: a new column starts at `firstDir(key)`, the same column flips. */
export function useSort<K extends string>(initial: { key: K; dir: SortDir }, firstDir: (key: K) => SortDir) {
  const [sort, setSort] = React.useState(initial);
  const onSort = (key: K) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: firstDir(key) }));
  return { sort, onSort };
}
