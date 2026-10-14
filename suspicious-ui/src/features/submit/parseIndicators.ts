export type IndicatorType = "url" | "ip" | "hash" | "domain" | null;
export interface ParsedIndicator { raw: string; value: string; type: IndicatorType; }

const HASH = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const IPV4 = /^((0|[1-9]\d{0,2})\.){3}(0|[1-9]\d{0,2})$/;

const refang = (s: string) =>
  s.replace(/hxxps?:\/\//g, (m) => m.replace("hxxp", "http"))
   .replace(/\[\.\]|\(\.\)|\[dot\]/g, ".")
   .replace(/\[:\]/g, ":")
   .trim().replace(/^[<"']+|[>"']+$/g, "");

// Bare IPv6 literal only (no brackets, port or path); the URL parser does the validation.
const isIPv6 = (v: string) => {
  if (!v.includes(":") || v.includes("/")) return false;
  try { new URL(`http://[${v}]/`); return true; } catch { return false; }
};

const classify = (v: string): IndicatorType => {
  if (HASH.test(v)) return "hash";
  if (IPV4.test(v) && v.split(".").every((o) => +o <= 255)) return "ip";
  if (/^https?:\/\//.test(v)) return "url";
  if (isIPv6(v)) return "ip";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) && !v.includes("/")) return "domain";
  return null;
};

export function parseIndicators(text: string): ParsedIndicator[] {
  const seen = new Set<string>();
  const out: ParsedIndicator[] = [];
  let prose: string[] = [];
  const flush = () => {
    if (!prose.length) return;
    const v = prose.join(" ");
    out.push({ raw: v, value: v, type: null });
    prose = [];
  };
  for (const tok of (text || "").split(/[\s,;]+/)) {
    if (!tok) continue;
    const value = refang(tok);
    if (!value) continue;
    const type = classify(value);
    if (!type) {
      prose.push(value);
      continue;
    }
    flush();
    if (seen.has(value.toLowerCase())) continue;
    seen.add(value.toLowerCase());
    out.push({ raw: tok, value, type });
  }
  flush();
  return out;
}
