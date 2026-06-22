export function short(text: string | undefined, max = 64) {
  const t = (text ?? "").trim();
  if (!t) return "";
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export function fmtDate(iso: string | undefined) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

export function sum(values: number[]) {
  return values.reduce((a, b) => a + b, 0);
}

export const DANGER_ORDER = ["Safe", "Inconclusive", "Suspicious", "Dangerous"] as const;
export type DangerLabel = (typeof DANGER_ORDER)[number];

export const DANGER_COLORS: Record<DangerLabel, string> = {
  Safe: "#22C55E",
  Inconclusive: "#A3A3A3",
  Suspicious: "#F59E0B",
  Dangerous: "#EF4444",
};
