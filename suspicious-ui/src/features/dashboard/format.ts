import type { ScopeOption } from "@/features/dashboard/api";

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
