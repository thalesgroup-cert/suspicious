import type { ConfigField } from "./components/connectors";

export type ProviderSwitchSpec = {
  /** The config key the segmented control writes. */
  key: string;
  label: string;
  options: { value: string; label: string; fields: string[] }[];
  /** What the backend uses when the saved value is empty. */
  fallback: string;
  manual: { label: string; note: string; fields: string[] };
};

/**
 * Presentation only, keyed by connector name; every other connector keeps the generic grouped form.
 * The facts come from the backend: the automatic case_finalised path allows only ollama and openai_compatible
 * (connectors/contrib/ai_narration select.py AUTO_PROVIDERS) and an empty value means ollama; the other keys are used by manual runs.
 */
export const PROVIDER_SWITCH: Record<string, ProviderSwitchSpec> = {
  ai_narration: {
    key: "narration_provider",
    label: "Provider used when narration runs automatically",
    options: [
      { value: "ollama", label: "Ollama", fields: ["ollama_url", "ollama_model"] },
      {
        value: "openai_compatible",
        label: "OpenAI-compatible",
        fields: ["openai_compatible_base_url", "openai_compatible_api_key", "openai_compatible_model"],
      },
    ],
    fallback: "ollama",
    manual: {
      label: "Manual-run providers (OpenAI, Anthropic, Gemini)",
      note: "These keys are used only by manual runs (manage.py test_ai_narration), not when a case is finalised.",
      fields: ["openai_api_key", "openai_model", "anthropic_api_key", "anthropic_model", "gemini_api_key", "gemini_model"],
    },
  },
};

/** `raw` is what is saved, so the UI can name an unknown value instead of silently replacing it. */
export function resolveProvider(
  spec: ProviderSwitchSpec,
  value: unknown,
): { selected: string; state: "set" | "unset" | "unknown"; raw: string } {
  const raw = typeof value === "string" ? value.trim() : "";
  if (!raw) return { selected: spec.fallback, state: "unset", raw };
  if (spec.options.some((o) => o.value === raw)) return { selected: raw, state: "set", raw };
  return { selected: spec.fallback, state: "unknown", raw };
}

export function splitSchema(schema: ConfigField[], spec: ProviderSwitchSpec) {
  const byKey = new Map(schema.map((f) => [f.key, f]));
  const pick = (keys: string[]) => keys.flatMap((k) => byKey.get(k) ?? []);
  const named = new Set([spec.key, ...spec.options.flatMap((o) => o.fields), ...spec.manual.fields]);
  return {
    switchField: byKey.get(spec.key),
    byOption: Object.fromEntries(spec.options.map((o) => [o.value, pick(o.fields)])) as Record<string, ConfigField[]>,
    manual: pick(spec.manual.fields),
    rest: schema.filter((f) => !named.has(f.key)),
  };
}
