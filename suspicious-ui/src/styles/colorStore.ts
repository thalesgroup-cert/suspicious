//
// Central store for semantic status / result colors.
//
// Persistence strategy:
//   1. Zustand persist writes to localStorage immediately (offline-first).
//   2. When the user is authenticated, changes are also synced to the
//      backend at PATCH /api/profile/colors/ so they survive across
//      devices and browser clears.
//   3. On app boot, ProfilePage already fetches the full profile via
//      React Query ["profile"]. The store subscribes to that data and
//      hydrates itself — so the backend value always wins on first load.
//
// See: src/features/profile/api.ts  for the API call implementations.

import { create } from "zustand";
import { persist } from "zustand/middleware";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ResultKey = "safe" | "suspicious" | "dangerous" | "inconclusive";
export type StatusKey = "done" | "in_progress" | "new" | "failure" | "challenged" | "unknown";

type SemanticColor = { main: string };
export type ResultColors  = Record<ResultKey, SemanticColor>;
export type StatusColors  = Record<StatusKey, SemanticColor>;
export type PresetName    = "default" | "colorblind" | "mono" | "custom";

// ---------------------------------------------------------------------------
// Human-readable labels
// ---------------------------------------------------------------------------

export const RESULT_LABELS: Record<ResultKey, string> = {
  safe:         "Safe",
  suspicious:   "Suspicious",
  dangerous:    "Dangerous",
  inconclusive: "Inconclusive",
};

export const STATUS_LABELS: Record<StatusKey, string> = {
  done:        "Done",
  in_progress: "In progress",
  new:         "New / Todo",
  failure:     "Failure",
  challenged:  "Challenged",
  unknown:     "Unknown",
};

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

export const PRESET_DEFAULT: { result: ResultColors; status: StatusColors } = {
  result: {
    safe:         { main: "#22C55E" },
    suspicious:   { main: "#F59E0B" },
    dangerous:    { main: "#EF4444" },
    inconclusive: { main: "#94A3B8" },
  },
  status: {
    done:        { main: "#22C55E" },
    in_progress: { main: "#3B82F6" },
    new:         { main: "#94A3B8" },
    failure:     { main: "#EF4444" },
    challenged:  { main: "#A855F7" },
    unknown:     { main: "#64748B" },
  },
};

// Okabe-Ito (2008) — universally distinguishable across all colorblindness types.
// Mapping: safe → bluish-green, suspicious → orange, dangerous → vermilion,
//          inconclusive → sky-blue. Blue+orange are the safest pair.
export const PRESET_COLORBLIND: { result: ResultColors; status: StatusColors } = {
  result: {
    safe:         { main: "#009E73" }, // bluish-green
    suspicious:   { main: "#E69F00" }, // orange
    dangerous:    { main: "#D55E00" }, // vermilion
    inconclusive: { main: "#56B4E9" }, // sky-blue
  },
  status: {
    done:        { main: "#009E73" },
    in_progress: { main: "#0072B2" }, // blue
    new:         { main: "#56B4E9" }, // sky-blue
    failure:     { main: "#D55E00" }, // vermilion
    challenged:  { main: "#CC79A7" }, // reddish-purple
    unknown:     { main: "#888888" },
  },
};

export const PRESET_MONO: { result: ResultColors; status: StatusColors } = {
  result: {
    safe:         { main: "#D1D5DB" },
    suspicious:   { main: "#9CA3AF" },
    dangerous:    { main: "#334155" },
    inconclusive: { main: "#64748B" },
  },
  status: {
    done:        { main: "#D1D5DB" },
    in_progress: { main: "#9CA3AF" },
    new:         { main: "#64748B" },
    failure:     { main: "#334155" },
    challenged:  { main: "#475569" },
    unknown:     { main: "#64748B" },
  },
};

export const PRESETS: Record<Exclude<PresetName, "custom">, typeof PRESET_DEFAULT> = {
  default:    PRESET_DEFAULT,
  colorblind: PRESET_COLORBLIND,
  mono:       PRESET_MONO,
};

export const PRESET_META: Record<PresetName, { label: string; description: string }> = {
  default: {
    label: "Standard",
    description: "Red / green / amber — familiar, not accessible for all users.",
  },
  colorblind: {
    label: "Colorblind-safe",
    description: "Okabe-Ito palette. Safe for protanopia, deuteranopia, and tritanopia.",
  },
  mono: {
    label: "Monochrome",
    description: "Luminance-only. Works for greyscale displays and print.",
  },
  custom: {
    label: "Custom",
    description: "Your own color choices.",
  },
};

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

type ColorStore = {
  result: ResultColors;
  status: StatusColors;
  preset: PresetName;

  // Mutators
  setResultColor: (key: ResultKey, hex: string) => void;
  setStatusColor: (key: StatusKey, hex: string) => void;
  applyPreset:    (name: Exclude<PresetName, "custom">) => void;
  reset:          () => void;

  // Called by ProfilePage after fetching the backend profile so the server
  // value always takes precedence over the localStorage snapshot on boot.
  hydrateFromProfile: (colors: { result: ResultColors; status: StatusColors }) => void;
};

export const useColorStore = create<ColorStore>()(
  persist(
    (set) => ({
      result: PRESET_DEFAULT.result,
      status: PRESET_DEFAULT.status,
      preset: "default" as PresetName,

      setResultColor: (key, hex) =>
        set((s) => ({
          result: { ...s.result, [key]: { main: hex } },
          preset: "custom",
        })),

      setStatusColor: (key, hex) =>
        set((s) => ({
          status: { ...s.status, [key]: { main: hex } },
          preset: "custom",
        })),

      applyPreset: (name) =>
        set({
          result: PRESETS[name].result,
          status: PRESETS[name].status,
          preset: name,
        }),

      reset: () =>
        set({
          result: PRESET_DEFAULT.result,
          status: PRESET_DEFAULT.status,
          preset: "default",
        }),

      hydrateFromProfile: (colors) =>
        set((s) => {
          // Only hydrate if the incoming data looks structurally valid.
          if (!colors?.result || !colors?.status) return s;
          return {
            result: { ...PRESET_DEFAULT.result, ...colors.result },
            status: { ...PRESET_DEFAULT.status, ...colors.status },
            // Keep preset label as-is — server doesn't store it, and we
            // want to show "Custom" if the user had diverged from a preset.
          };
        }),
    }),
    {
      name: "suspicious.semantic-colors",
      version: 1,
      // Migrate v0 → v1: ensure both groups exist.
      migrate: (persisted: any, version) => {
        if (version === 0) {
          return {
            ...persisted,
            result: { ...PRESET_DEFAULT.result, ...(persisted?.result ?? {}) },
            status: { ...PRESET_DEFAULT.status, ...(persisted?.status ?? {}) },
          };
        }
        return persisted;
      },
    }
  )
);

// ---------------------------------------------------------------------------
// Selectors
// ---------------------------------------------------------------------------

export const useResultColors = () => useColorStore((s) => s.result);
export const useStatusColors  = () => useColorStore((s) => s.status);

// ---------------------------------------------------------------------------
// Colour math helpers
// ---------------------------------------------------------------------------

/** Derive a soft background tint (rgba) from a hex string. */
export function hexToBg(hex: string, isDark: boolean): string {
  const c = hex.replace("#", "");
  const r = parseInt(c.slice(0, 2), 16);
  const g = parseInt(c.slice(2, 4), 16);
  const b = parseInt(c.slice(4, 6), 16);
  if (isNaN(r) || isNaN(g) || isNaN(b)) return "transparent";
  return `rgba(${r},${g},${b},${isDark ? 0.14 : 0.1})`;
}

/** WCAG luminance-based text contrast: returns black or white. */
export function contrastText(hex: string): "#000000" | "#ffffff" {
  const c = hex.replace("#", "");
  const r = parseInt(c.slice(0, 2), 16) / 255;
  const g = parseInt(c.slice(2, 4), 16) / 255;
  const b = parseInt(c.slice(4, 6), 16) / 255;
  const lin = (x: number) =>
    x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
  const L = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  return L > 0.179 ? "#000000" : "#ffffff";
}