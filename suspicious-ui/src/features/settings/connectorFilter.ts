import { connectorStatus } from "./components/StatusLabel";
import type { Connector } from "./components/connectors";

export type StatusFilter = "all" | "connected" | "incomplete" | "unhealthy" | "disabled";
type StatusKey = Exclude<StatusFilter, "all">;

/** The same decision the StatusLabel makes, so a chip count always matches the words on the tiles. */
function statusKey(c: Connector): StatusKey {
  const { tone, label } = connectorStatus(c);
  if (tone === "neutral") return "disabled";
  if (label === "Unhealthy") return "unhealthy";
  return tone === "ok" ? "connected" : "incomplete";
}

export function filterConnectors(list: Connector[], f: { q: string; status: StatusFilter }): Connector[] {
  const q = f.q.trim().toLowerCase();
  return list.filter((c) => {
    if (f.status !== "all" && statusKey(c) !== f.status) return false;
    return !q || [c.name, c.category, c.description].some((s) => (s ?? "").toLowerCase().includes(q));
  });
}

export function statusCounts(list: Connector[]): Record<StatusFilter, number> {
  const counts: Record<StatusFilter, number> = { all: list.length, connected: 0, incomplete: 0, unhealthy: 0, disabled: 0 };
  for (const c of list) counts[statusKey(c)] += 1;
  return counts;
}

export function groupByCategory(list: Connector[]): { category: string; items: Connector[] }[] {
  const groups = new Map<string, Connector[]>();
  for (const c of list) {
    const key = c.category || "Other";
    groups.set(key, [...(groups.get(key) ?? []), c]);
  }
  return [...groups].map(([category, items]) => ({ category, items }));
}
