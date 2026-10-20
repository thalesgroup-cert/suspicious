import { describe, expect, it } from "vitest";

import type { Connector } from "../components/connectors";
import { filterConnectors, groupByCategory, statusCounts } from "../connectorFilter";

const make = (name: string, over: Partial<Connector> = {}): Connector => ({
  name,
  version: "1.0.0",
  description: `${name} description`,
  author: "",
  docs_url: "",
  category: "Intel",
  events: [],
  schedules: [],
  config_schema: [],
  enabled: true,
  enabled_by_default: false,
  status: "connected",
  last_health_ok: true,
  last_health_detail: "",
  last_health_at: null,
  ...over,
});

const LIST = [
  make("misp", { category: "Threat Intelligence", description: "Push finalised cases to MISP" }),
  make("thehive", { category: "Incident response", status: "partial", last_health_ok: null }),
  make("chromadb", { category: "Maintenance", last_health_ok: false }),
  make("watcher", { category: "Threat Intelligence", status: "disabled", enabled: false, last_health_ok: false }),
];
const all = { q: "", status: "all" } as const;

describe("filterConnectors", () => {
  it("returns everything for an empty query and All", () => {
    expect(filterConnectors(LIST, all)).toHaveLength(4);
  });

  it.each([
    ["name", "HIVE", ["thehive"]],
    ["category", "maintenance", ["chromadb"]],
    ["description", "finalised cases", ["misp"]],
  ])("searches the %s, ignoring case", (_where, q, names) => {
    expect(filterConnectors(LIST, { ...all, q }).map((c) => c.name)).toEqual(names);
  });

  it("trims the query", () => {
    expect(filterConnectors(LIST, { ...all, q: "  misp  " }).map((c) => c.name)).toEqual(["misp"]);
  });

  it.each([
    ["connected", ["misp"]],
    ["incomplete", ["thehive"]],
    ["unhealthy", ["chromadb"]],
    ["disabled", ["watcher"]],
  ] as const)("keeps only %s connectors", (status, names) => {
    expect(filterConnectors(LIST, { q: "", status }).map((c) => c.name)).toEqual(names);
  });

  it("counts a disabled connector with a failed check as disabled, not unhealthy", () => {
    expect(filterConnectors(LIST, { q: "", status: "unhealthy" }).map((c) => c.name)).not.toContain("watcher");
  });

  it("combines the query and the status", () => {
    expect(filterConnectors(LIST, { q: "intelligence", status: "disabled" }).map((c) => c.name)).toEqual(["watcher"]);
    expect(filterConnectors(LIST, { q: "intelligence", status: "incomplete" })).toEqual([]);
  });

  it("searches a missing description without throwing", () => {
    expect(filterConnectors([make("x", { description: undefined as unknown as string })], { ...all, q: "x" })).toHaveLength(1);
  });
});

describe("statusCounts", () => {
  it("puts every connector in exactly one status", () => {
    const c = statusCounts(LIST);
    expect(c).toEqual({ all: 4, connected: 1, incomplete: 1, unhealthy: 1, disabled: 1 });
    expect(c.connected + c.incomplete + c.unhealthy + c.disabled).toBe(c.all);
  });

  it("is all zeros for an empty list", () => {
    expect(statusCounts([])).toEqual({ all: 0, connected: 0, incomplete: 0, unhealthy: 0, disabled: 0 });
  });
});

describe("groupByCategory", () => {
  it("keeps categories in first-appearance order and items in list order", () => {
    expect(groupByCategory(LIST).map((g) => [g.category, g.items.map((c) => c.name)])).toEqual([
      ["Threat Intelligence", ["misp", "watcher"]],
      ["Incident response", ["thehive"]],
      ["Maintenance", ["chromadb"]],
    ]);
  });

  it("calls an empty category Other", () => {
    expect(groupByCategory([make("a", { category: "" }), make("b", { category: "" })])).toEqual([
      { category: "Other", items: [expect.objectContaining({ name: "a" }), expect.objectContaining({ name: "b" })] },
    ]);
  });
});
