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

/** Backend labels carry country codes ("My country (AU)", "AU | Off GBU"): show names. */
export function scopeLabel(label: string): string {
  return label.replace(/\b[A-Z]{2}\b/g, countryName);
}

/** The scope as the subtitle names it: "Australia", "Overall", "APAC". */
export function scopeName(scope: ScopeOption): string {
  const own = /^My country \((.+)\)$/.exec(scope.label);
  return scopeLabel(own ? own[1] : scope.label);
}
