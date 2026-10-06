export type IndicatorType = "url" | "ip" | "hash" | "domain" | null;
export interface ParsedIndicator { raw: string; value: string; type: IndicatorType; }

const HASH = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

const refang = (s: string) =>
  s.replace(/hxxps?:\/\//g, (m) => m.replace("hxxp", "http"))
   .replace(/\[\.\]|\(\.\)|\[dot\]/g, ".")
   .replace(/\[:\]/g, ":")
   .trim().replace(/^[<"']+|[>"']+$/g, "");

const classify = (v: string): IndicatorType => {
  if (HASH.test(v)) return "hash";
  if (IPV4.test(v) && v.split(".").every((o) => +o <= 255)) return "ip";
  if (/^https?:\/\//.test(v)) return "url";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) && !v.includes("/")) return "domain";
  return null;
};

export function parseIndicators(text: string): ParsedIndicator[] {
  const seen = new Set<string>();
  const out: ParsedIndicator[] = [];
  for (const tok of (text || "").split(/[\s,;]+/)) {
    if (!tok) continue;
    const value = refang(tok);
    if (!value || seen.has(value.toLowerCase())) continue;
    seen.add(value.toLowerCase());
    out.push({ raw: tok, value, type: classify(value) });
  }
  return out;
}
