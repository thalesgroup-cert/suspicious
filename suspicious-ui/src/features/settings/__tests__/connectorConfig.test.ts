import { describe, expect, it } from "vitest";

import type { ConfigField } from "../components/connectors";
import { groupFields, missingRequired, relativeTime, scheduleText } from "../connectorConfig";

const f = (key: string, required = false, type: ConfigField["type"] = "str"): ConfigField => ({
  key,
  type,
  required,
  default: null,
  help: "",
});

describe("groupFields", () => {
  it("groups an ai_narration-like schema by provider prefix and sends a lone prefix to General", () => {
    const groups = groupFields([
      f("ollama_url", false, "url"),
      f("ollama_model"),
      f("openai_api_key", false, "secret"),
      f("openai_model"),
      f("anthropic_api_key", false, "secret"),
      f("anthropic_model"),
      f("gemini_api_key", false, "secret"),
      f("gemini_model"),
      f("narration_provider"),
    ]);
    expect(groups.map((g) => g.label)).toEqual(["General", "Ollama", "OpenAI", "Anthropic", "Gemini"]);
    expect(groups[0].optional.map((x) => x.key)).toEqual(["narration_provider"]);
  });

  it("puts General first even when its field comes last, and orders other groups by first appearance", () => {
    const groups = groupFields([f("b_one"), f("a_one"), f("b_two"), f("a_two"), f("lone")]);
    expect(groups.map((g) => g.key)).toEqual(["general", "b", "a"]);
  });

  it("lists required fields before optional ones and keeps schema order inside each", () => {
    const [group] = groupFields([f("x_a"), f("x_b", true), f("x_c"), f("x_d", true)]);
    expect(group.required.map((x) => x.key)).toEqual(["x_b", "x_d"]);
    expect(group.optional.map((x) => x.key)).toEqual(["x_a", "x_c"]);
  });

  it("groups dotted keys by their leading token", () => {
    const groups = groupFields([f("instances.primary.url", true, "url"), f("instances.primary.api_key", true, "secret"), f("verify")]);
    expect(groups.map((g) => g.label)).toEqual(["General", "Instances"]);
    expect(groups[1].required).toHaveLength(2);
  });

  it("uses brand and acronym casing for the group label", () => {
    const labels = groupFields([f("misp_a"), f("misp_b"), f("smtp_a"), f("smtp_b"), f("thehive_a"), f("thehive_b"), f("api_a"), f("api_b")]).map((g) => g.label);
    expect(labels).toEqual(["MISP", "SMTP", "TheHive", "API"]);
  });

  it("returns no groups for an empty schema", () => {
    expect(groupFields([])).toEqual([]);
  });
});

describe("scheduleText", () => {
  it.each([
    [45, "every 45 s"],
    [60, "every 1 min"],
    [300, "every 5 min"],
    [5400, "every 90 min"],
    [7200, "every 2 h"],
    [90, "every 90 s"],
  ])("%i seconds reads %s", (seconds, text) => {
    expect(scheduleText(seconds)).toBe(text);
  });

  it("does not claim a cadence for a non-positive interval", () => {
    expect(scheduleText(0)).toBe("not scheduled");
  });
});

describe("relativeTime", () => {
  const now = new Date("2026-10-19T12:00:00Z");
  const ago = (ms: number) => new Date(now.getTime() - ms).toISOString();

  it.each([
    [10_000, "just now"],
    [5 * 60_000, "5 min ago"],
    [3 * 3_600_000, "3 h ago"],
    [2 * 86_400_000, "2 d ago"],
  ])("%i ms ago reads %s", (ms, text) => {
    expect(relativeTime(ago(ms), now)).toBe(text);
  });

  it("treats a time slightly in the future as just now", () => {
    expect(relativeTime(ago(-30_000), now)).toBe("just now");
  });

  it("says not checked yet for null or an unparsable value", () => {
    expect(relativeTime(null, now)).toBe("not checked yet");
    expect(relativeTime("nope", now)).toBe("not checked yet");
  });
});

describe("missingRequired", () => {
  const schema = [f("url", true, "url"), f("api_key", true, "secret"), f("timeout", false), f("name", true)];

  it("lists required fields whose saved value is empty or absent, in schema order", () => {
    expect(missingRequired(schema, { url: "", api_key: "********" }).map((x) => x.key)).toEqual(["url", "name"]);
  });

  it("treats whitespace as empty", () => {
    expect(missingRequired(schema, { url: "   ", api_key: "********", name: "x" }).map((x) => x.key)).toEqual(["url"]);
  });

  it("counts a stored secret (the mask) as present and an empty secret as missing", () => {
    expect(missingRequired(schema, { url: "u", name: "n", api_key: "********" })).toEqual([]);
    expect(missingRequired(schema, { url: "u", name: "n", api_key: "" }).map((x) => x.key)).toEqual(["api_key"]);
  });

  it("treats an absent key as missing and never lists optional fields", () => {
    expect(missingRequired(schema, {}).map((x) => x.key)).toEqual(["url", "api_key", "name"]);
  });

  it("keeps zero and false as present values", () => {
    expect(missingRequired([f("n", true, "int"), f("b", true, "bool")], { n: 0, b: false })).toEqual([]);
  });

  it("reads dotted keys", () => {
    expect(missingRequired([f("smtp.host", true)], { smtp: { host: "h" } })).toEqual([]);
    expect(missingRequired([f("smtp.host", true)], { smtp: {} }).map((x) => x.key)).toEqual(["smtp.host"]);
  });
});
