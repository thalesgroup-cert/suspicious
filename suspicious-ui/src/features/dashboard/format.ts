import type { ScopeOption } from "@/features/dashboard/api";
import { ensureContrast } from "@/shared/lib/contrast";

export function monthName(m: number) {
  return new Date(2000, m - 1, 1).toLocaleString("en", { month: "long" });
}

const regionNames = new Intl.DisplayNames(["en"], { type: "region" });

/** "AU" -> "Australia"; anything Intl does not know stays as the code. */
export function countryName(code: string): string {
  try {
    const name = regionNames.of(code);
    return name && name !== code && name !== "Unknown Region" ? name : code;
  } catch {
    return code;
  }
}

/**
 * Own-country and country labels carry a country code ("My country (AU)",
 * "AU"): show the name. Other scopes (CISO scope, regions) are free text
 * where a two-letter token may be a GBU ("HR", "IT"), so they stay as sent.
 */
export function scopeLabel(label: string, key: string): string {
  return key === "OWN_COUNTRY" || key.startsWith("COUNTRY:") ? label.replace(/\b[A-Z]{2}\b/g, countryName) : label;
}

/** The scope as the subtitle names it: "Australia", "Overall", "APAC". */
export function scopeName(scope: ScopeOption): string {
  const own = /^My country \((.+)\)$/.exec(scope.label);
  return scopeLabel(own && scope.key === "OWN_COUNTRY" ? own[1] : scope.label, scope.key);
}

/**
 * `fg` raised to `min`:1 against both card surfaces: the paper colour, and the
 * page background that shows through the dark-mode card gradient.
 */
export function onCard(fg: string, palette: { background: { paper: string; default: string } }, min = 4.5): string {
  return [palette.background.paper, palette.background.default].reduce((c, bg) => ensureContrast(c, bg, min), fg);
}

/** Integer percentages of `counts` that add up to exactly 100 (largest remainder). */
export function percents(counts: number[]): number[] {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return counts.map(() => 0);
  const raw = counts.map((c) => (c * 100) / total);
  const out = raw.map(Math.floor);
  const order = raw.map((r, i) => [r - out[i], i]).sort((a, b) => b[0] - a[0]);
  const missing = 100 - out.reduce((a, b) => a + b, 0);
  for (let k = 0; k < missing; k++) out[order[k][1]] += 1;
  return out;
}

/** "1 case", "3 cases"; `many` defaults to `one` + "s". */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}
