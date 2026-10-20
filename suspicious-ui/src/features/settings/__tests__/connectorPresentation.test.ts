import { describe, expect, it } from "vitest";

import type { ConfigField } from "../components/connectors";
import { PROVIDER_SWITCH, resolveProvider, splitSchema } from "../connectorPresentation";

const f = (key: string, type: ConfigField["type"] = "str"): ConfigField => ({ key, type, required: false, default: null, help: "" });
const AI_SCHEMA = [
  f("narration_provider"),
  f("ollama_url", "url"),
  f("ollama_model"),
  f("openai_compatible_base_url", "url"),
  f("openai_compatible_api_key", "secret"),
  f("openai_compatible_model"),
  f("openai_api_key", "secret"),
  f("openai_model"),
  f("anthropic_api_key", "secret"),
  f("anthropic_model"),
  f("gemini_api_key", "secret"),
  f("gemini_model"),
];
const spec = PROVIDER_SWITCH.ai_narration;

describe("PROVIDER_SWITCH", () => {
  it("describes ai_narration only: the automatic path allows Ollama and OpenAI-compatible", () => {
    expect(Object.keys(PROVIDER_SWITCH)).toEqual(["ai_narration"]);
    expect(spec.key).toBe("narration_provider");
    expect(spec.label).toBe("Provider used when narration runs automatically");
    expect(spec.options.map((o) => [o.value, o.label])).toEqual([
      ["ollama", "Ollama"],
      ["openai_compatible", "OpenAI-compatible"],
    ]);
    expect(spec.fallback).toBe("ollama");
    expect(spec.manual.label).toBe("Manual-run providers (OpenAI, Anthropic, Gemini)");
    expect(spec.manual.note).toBe("These keys are used only by manual runs (manage.py test_ai_narration), not when a case is finalised.");
  });
});

describe("resolveProvider", () => {
  it("selects a saved provider", () => {
    expect(resolveProvider(spec, "openai_compatible")).toEqual({ selected: "openai_compatible", state: "set", raw: "openai_compatible" });
  });

  it.each([undefined, null, "", "   "])("falls back to Ollama for an unset value (%j)", (value) => {
    expect(resolveProvider(spec, value)).toMatchObject({ selected: "ollama", state: "unset" });
  });

  it("falls back to Ollama for an unknown value and keeps it", () => {
    expect(resolveProvider(spec, "anthropic")).toEqual({ selected: "ollama", state: "unknown", raw: "anthropic" });
  });
});

describe("splitSchema", () => {
  it("splits the ai_narration schema into the switch, two provider groups, six manual fields and nothing else", () => {
    const s = splitSchema(AI_SCHEMA, spec);
    expect(s.switchField?.key).toBe("narration_provider");
    expect(s.byOption.ollama.map((x) => x.key)).toEqual(["ollama_url", "ollama_model"]);
    expect(s.byOption.openai_compatible.map((x) => x.key)).toEqual([
      "openai_compatible_base_url",
      "openai_compatible_api_key",
      "openai_compatible_model",
    ]);
    expect(s.manual.map((x) => x.key)).toEqual(["openai_api_key", "openai_model", "anthropic_api_key", "anthropic_model", "gemini_api_key", "gemini_model"]);
    expect(s.rest).toEqual([]);
  });

  it("leaves fields the spec does not name in rest", () => {
    const s = splitSchema([...AI_SCHEMA, f("temperature")], spec);
    expect(s.rest.map((x) => x.key)).toEqual(["temperature"]);
  });

  it("tolerates a schema without the switch field", () => {
    expect(splitSchema([f("ollama_url")], spec).switchField).toBeUndefined();
  });
});
