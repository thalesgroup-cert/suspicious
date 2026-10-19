import { fieldLabel } from "./labels";
import type { ConfigField } from "./components/connectors";

export type FieldGroup = { key: string; label: string; required: ConfigField[]; optional: ConfigField[] };

const GENERAL = "general";

const prefixOf = (key: string) => key.split(/[._]/)[0];

/**
 * A group is the leading token of the key when at least two fields share it, so a lone `narration_provider`
 * does not get a group of its own. General comes first; the others keep first-appearance order.
 */
export function groupFields(schema: ConfigField[]): FieldGroup[] {
  const counts = new Map<string, number>();
  for (const f of schema) counts.set(prefixOf(f.key), (counts.get(prefixOf(f.key)) ?? 0) + 1);

  const groups = new Map<string, FieldGroup>();
  const add = (key: string, label: string, field: ConfigField) => {
    const g = groups.get(key) ?? { key, label, required: [], optional: [] };
    (field.required ? g.required : g.optional).push(field);
    groups.set(key, g);
  };
  for (const f of schema) {
    const token = prefixOf(f.key);
    if ((counts.get(token) ?? 0) >= 2) add(token, fieldLabel({ key: token }), f);
    else add(GENERAL, "General", f);
  }
  const general = groups.get(GENERAL);
  groups.delete(GENERAL);
  return [...(general ? [general] : []), ...groups.values()];
}

export function scheduleText(intervalSeconds: number): string {
  if (!(intervalSeconds > 0)) return "not scheduled";
  if (intervalSeconds % 3600 === 0) return `every ${intervalSeconds / 3600} h`;
  if (intervalSeconds % 60 === 0) return `every ${intervalSeconds / 60} min`;
  return `every ${intervalSeconds} s`;
}

/** `now` is a parameter so the wording is testable; a clock slightly ahead of the server reads "just now", not a negative age. */
export function relativeTime(iso: string | null, now: Date): string {
  const then = iso ? Date.parse(iso) : NaN;
  if (Number.isNaN(then)) return "not checked yet";
  const seconds = Math.floor((now.getTime() - then) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}
