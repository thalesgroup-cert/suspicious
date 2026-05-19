// src/styles/ThemeStore.tsx
import * as React from "react";
import { CssBaseline, ThemeProvider } from "@mui/material";
import { themes, type ThemeName, getSeasonalThemeName } from "./themes";

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

const STORAGE_KEY      = "suspicious.theme";
const STORAGE_KEY_AUTO = "suspicious.theme.auto"; // "1" | "0"
const DEFAULT_THEME: ThemeName = "light";

// Custom event dispatched by hydrateThemeFromServer() so AppThemeProvider
// can react immediately without a page reload.
const THEME_HYDRATE_EVENT = "suspicious:theme-hydrate";

// ---------------------------------------------------------------------------
// Theme capabilities
//
// Each theme may define utility CSS classes, CSS custom properties, and named
// visual effects beyond the standard MUI palette. This record documents them
// so consuming components can apply them without hardcoding theme names.
//
// Usage:
//   const { capabilities } = useThemeMode();
//   <div className={capabilities.utilityClasses.includes("fennec") ? "fennec" : ""} />
//   if (capabilities.effects.hasGlitchEffect) { ... }
// ---------------------------------------------------------------------------

/** Named feature flags — each describes a visual capability a theme provides. */
type ThemeEffects = {
  /** Glass-morphism surfaces (backdrop-filter: blur). */
  hasGlassEffect?: boolean;
  /** Neon glow and CRT scanlines (cyber). */
  hasNeonEffect?: boolean;
  /** Periodic glitch / flicker animation. */
  hasGlitchEffect?: boolean;
  /** Temporal portal flash effect (future / Le Visiteur du Futur). */
  hasPortalEffect?: boolean;
  /** Contamination / irradiation pulse (future). */
  hasContaminationEffect?: boolean;
  /** Cold blue Brigade scan sweep (future). */
  hasBrigadeScanEffect?: boolean;
  /** MGS stealth utilities: cardboard box, camo overlay, HUD alert states. */
  hasStealthMode?: boolean;
  /** MGS alert / caution state — colours shift on `.hud-alertable` elements. */
  hasAlertStates?: boolean;
  /** Christmas lights garland animation (winter). */
  hasSeasonalLights?: boolean;
  /** Botanical bloom and dew-pulse animations (spring). */
  hasBloomEffect?: boolean;
  /** Heat shimmer overlay (summer). */
  hasHeatEffect?: boolean;
  /** Hearth-flicker / leaf-sway animations (autumn). */
  hasEmberEffect?: boolean;
  /** Solar radiance and gold-shimmer crown glow (the_one / Escanor). */
  hasSolarEffect?: boolean;
  /** High-contrast / WCAG AAA mode with forced-colors passthrough. */
  isAccessibilityTheme?: boolean;
};

export type ThemeCapabilities = {
  /** Human-readable display label. */
  label: string;
  /** Short description of the theme's visual character. */
  description: string;
  /** Narrative / lore context (optional — present for "character" themes). */
  lore?: string;
  /** Whether the resolved palette is dark mode. */
  isDark: boolean;
  /** Season this theme belongs to (only for the four seasonal themes). */
  season?: "spring" | "summer" | "autumn" | "winter";
  /**
   * CSS utility class names injected by this theme's CssBaseline.
   * Apply them directly to DOM elements — no extra stylesheet needed.
   */
  utilityClasses: readonly string[];
  /**
   * CSS custom property names exposed on :root by this theme.
   * Read them via getComputedStyle or use them in inline styles.
   */
  cssVars: readonly string[];
  /** Named feature flags. */
  effects: ThemeEffects;
};

export const THEME_CAPABILITIES: Record<ThemeName, ThemeCapabilities> = {
  // ── Base themes ────────────────────────────────────────────────────────────

  graphite: {
    label:       "Graphite",
    description: "Dark default — carbon surface, neutral accents.",
    isDark: true,
    utilityClasses: [],
    cssVars:        [],
    effects:        {},
  },

  slate: {
    label:       "Slate",
    description: "Cool blue-grey dark — material inspired.",
    isDark: true,
    utilityClasses: [],
    cssVars:        [],
    effects:        {},
  },

  light: {
    label:       "Light",
    description: "Clean light theme — high readability, minimal chrome.",
    isDark: false,
    utilityClasses: [],
    cssVars:        [],
    effects:        {},
  },

  paper: {
    label:       "Paper",
    description: "Warm off-white with grain texture — analogue writing feel.",
    isDark: false,
    utilityClasses: [],
    cssVars:        [],
    effects:        {},
  },

  high_contrast: {
    label:       "High Contrast",
    description: "WCAG AAA — maximum legibility, forced-colors passthrough.",
    isDark: true,
    utilityClasses: [],
    cssVars:        [],
    effects:        { isAccessibilityTheme: true },
  },

  // ── Atmospheric themes ─────────────────────────────────────────────────────

  midnight: {
    label:       "Midnight",
    description: "Deep space glass — deep navy, starfield specks, blur surfaces.",
    isDark: true,
    utilityClasses: [],
    cssVars:        [],
    effects:        { hasGlassEffect: true },
  },

  sunrise: {
    label:       "Sunrise",
    description: "Miami beach glass — coral & gold on bleached linen.",
    isDark: false,
    utilityClasses: [],
    cssVars:        [],
    effects:        { hasGlassEffect: true },
  },

  valentine: {
    label:       "Valentine",
    description: "Rose crystal glass — crimson hearts, bloom petals.",
    isDark: true,
    utilityClasses: [],
    cssVars:        [],
    effects:        { hasGlassEffect: true },
  },

  // ── Seasonal themes ────────────────────────────────────────────────────────

  spring: {
    label:       "Spring",
    description: "Botanical dot-grid, cherry blossoms, dewy glass cards.",
    isDark: false,
    season:      "spring",
    utilityClasses: ["bloom", "dew-pulse"],
    cssVars:        [],
    effects:        { hasBloomEffect: true },
  },

  summer: {
    label:       "Summer",
    description: "Bleached bone-white, blazing amber sun corona, heat shimmer.",
    isDark: false,
    season:      "summer",
    utilityClasses: ["heat-shimmer", "sun-orb"],
    cssVars:        [],
    effects:        { hasHeatEffect: true },
  },

  autumn: {
    label:       "Autumn",
    description: "Burnt char, dying embers, woodsmoke, fallen leaf palette.",
    isDark: true,
    season:      "autumn",
    utilityClasses: ["hearth-glow", "leaf-sway"],
    cssVars:        [],
    effects:        { hasEmberEffect: true },
  },

  winter: {
    label:       "Winter",
    description: "Santa, chimney glow, Christmas garland lights, snowflakes.",
    isDark: true,
    season:      "winter",
    utilityClasses: ["christmas-lights", "twinkle"],
    cssVars:        [],
    effects:        { hasSeasonalLights: true },
  },

  // ── Character themes ───────────────────────────────────────────────────────

  cyber: {
    label:       "Cyber",
    description: "Neon cyan/magenta on void black — CRT scanlines, matrix abyss.",
    isDark: true,
    utilityClasses: [],
    cssVars:        [],
    effects:        { hasNeonEffect: true, hasGlitchEffect: true },
  },

  the_one: {
    label:       "The One",
    description: "Escanor's blazing noon — liquid gold, solar crown shimmer.",
    lore:        "«Who decided that? … It was I.» — Escanor, Seven Deadly Sins. "
               + "The theme channels The One's divine solar power at high noon: "
               + "gold that blinds, light that no shadow can withstand.",
    isDark: true,
    utilityClasses: [],
    cssVars:        [],
    effects:        { hasSolarEffect: true },
  },

  metal: {
    label:       "Metal",
    description: "MGS stealth-ops — tactical browns, codec teal, alert siren red.",
    lore:        "A love letter to Hideo Kojima's Metal Gear Solid saga. "
               + "Cardboard-box disguise, Codec frequency overlays, "
               + "ALERT / CAUTION state transitions, radar sweep, and Snake's "
               + "eternal question: «Are you there, Colonel?»",
    isDark: true,
    utilityClasses: ["cardboard-box", "stealth-camo", "hud-alertable"],
    cssVars: [
      "--mgs-codec-snake",   // Codec frequency: 140.85
      "--mgs-codec-otacon",  // Codec frequency: 141.12
      "--mgs-alert",         // #E1061B — ALERT siren red
      "--mgs-caution",       // #F2C94C — CAUTION amber
      "--mgs-codec",         // #37D6C7 — Codec screen teal
    ],
    effects: {
      hasStealthMode:  true,
      hasAlertStates:  true,
      hasBrigadeScanEffect: true, // radar sweep is functionally similar
    },
  },

  future: {
    label:       "Future",
    description: "2555 Paris in ruins — Visitor's amber coat, Brigade steel blue, irradiated green.",
    lore:        "«Here's what's gonna happen...» — Le Visiteur du Futur (web series 2009–2012, film 2022). "
               + "The Visitor time-travels to prevent the ecological apocalypse of 2555. "
               + "The Brigade Temporelle, temporal paradoxes, and a bracelet "
               + "that always has just enough charge for one more jump.",
    isDark: true,
    utilityClasses: [
      "temporal-arrive",  // element enters as if stepping out of a portal
      "portal-flash",     // radial blue burst pseudo-element
      "contaminated",     // irradiated green pulsing border
      "brigade-scan",     // cold blue scan sweep + animated shimmer
      "temporal-glitch",  // periodic timeline-corruption glitch
      "visitor-briefing", // scrawled note styled like the Visitor's field notes
      "fennec",           // ambient amber heartbeat — Fennec approves
    ],
    cssVars: [
      "--visitor-coat",    // #E8720C — Visitor's amber coat
      "--visitor-fennec",  // #F5A623 — Fennec ear-tips & paw pads
      "--visitor-ash",     // #E8DED0 — ash bone text
      "--brigade-blue",    // #4A90D9 — Brigade armour & portal flash
      "--brigade-ghost",   // #8FA8C0 — Brigade ghost / smoke secondary
      "--brigade-alert",   // #C42B0A — Brigade alert siren
      "--future-char",     // #0D0905 — burnt char floor of 2555 Paris
      "--future-timber",   // #160E08 — scorched timber walls
      "--future-copper",   // #C87941 — copper wiring / relic tech
      "--future-green",    // #5CB85C — contamination / irradiation glow
      "--bracelet-on",     // #E8720C — bracelet active
      "--bracelet-full",   // #F5A623 — bracelet fully charged
    ],
    effects: {
      hasPortalEffect:        true,
      hasGlitchEffect:        true,
      hasContaminationEffect: true,
      hasBrigadeScanEffect:   true,
    },
  },
};

// ---------------------------------------------------------------------------
// Context type
// ---------------------------------------------------------------------------

type ThemeCtx = {
  themeName:    ThemeName;
  setThemeName: (t: ThemeName) => void;
  isDarkMode:   boolean;
  autoSeasonal: boolean;
  setAutoSeasonal: (v: boolean) => void;
  /** Capabilities of the currently resolved theme. */
  capabilities: ThemeCapabilities;
};

const ThemeContext = React.createContext<ThemeCtx | null>(null);

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export function useThemeMode() {
  const ctx = React.useContext(ThemeContext);
  if (!ctx) throw new Error("useThemeMode must be used inside AppThemeProvider");
  return ctx;
}

// ---------------------------------------------------------------------------
// Out-of-React hydration
//
// Called by auth.ts → getMe() immediately after a successful /auth/me/
// response. Cannot use React hooks (we're outside the component tree) so
// we write directly to localStorage and fire a custom DOM event that
// AppThemeProvider listens for — same approach as BroadcastChannel for
// multi-tab sync, but simpler.
//
// Priority:
//   1. Server value (always wins — reflects the user's saved preference)
//   2. localStorage (offline / pre-login fallback)
//   3. OS preference (absolute default for new users)
// ---------------------------------------------------------------------------

export function hydrateThemeFromServer(theme: string, autoSeasonal: boolean): void {
  try {
    if (isValidThemeName(theme)) {
      localStorage.setItem(STORAGE_KEY, theme);
    }
    localStorage.setItem(STORAGE_KEY_AUTO, autoSeasonal ? "1" : "0");

    // Notify AppThemeProvider to re-read and update its React state.
    window.dispatchEvent(
      new CustomEvent(THEME_HYDRATE_EVENT, {
        detail: { theme, autoSeasonal },
      })
    );
  } catch {
    // localStorage unavailable (private browsing extreme mode) — silently
    // fall through; the event still fires if dispatchEvent hasn't thrown.
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isValidThemeName(value: unknown): value is ThemeName {
  return typeof value === "string" && value in themes;
}

function readBool(key: string, fallback: boolean): boolean {
  try {
    const v = localStorage.getItem(key);
    if (v === "1") return true;
    if (v === "0") return false;
    return fallback;
  } catch {
    return fallback;
  }
}

function writeBool(key: string, v: boolean) {
  try {
    localStorage.setItem(key, v ? "1" : "0");
  } catch { /* ignore */ }
}

/**
 * Initial theme resolution (runs once on mount, before getMe() resolves):
 * 1. Stored localStorage preference → use it
 * 2. No preference → follow OS dark/light preference
 */
function getInitialTheme(): ThemeName {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (isValidThemeName(raw)) return raw;
    return DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function AppThemeProvider({ children }: { children: React.ReactNode }) {
  const [themeName, setThemeNameState] = React.useState<ThemeName>(getInitialTheme);

  const [autoSeasonal, setAutoSeasonalState] = React.useState<boolean>(
    () => readBool(STORAGE_KEY_AUTO, false)
  );

  // ── Setters (used by ProfilePage) ────────────────────────────────────────

  const setThemeName = React.useCallback((t: ThemeName) => {
    if (!isValidThemeName(t)) return;
    setThemeNameState(t);
    try { localStorage.setItem(STORAGE_KEY, t); } catch { /* ignore */ }
  }, []);

  const setAutoSeasonal = React.useCallback((v: boolean) => {
    setAutoSeasonalState(v);
    writeBool(STORAGE_KEY_AUTO, v);
  }, []);

  // ── Auth-time hydration via custom event ─────────────────────────────────
  //
  // When getMe() resolves (login, page load, tab focus), hydrateThemeFromServer()
  // fires THEME_HYDRATE_EVENT. We listen here and update React state so the
  // theme switches immediately without requiring a visit to ProfilePage.

  React.useEffect(() => {
    function onHydrate(e: Event) {
      const { theme, autoSeasonal: auto } = (e as CustomEvent<{
        theme: string;
        autoSeasonal: boolean;
      }>).detail;

      if (isValidThemeName(theme)) {
        setThemeNameState(theme);
      }
      setAutoSeasonalState(auto);
    }

    window.addEventListener(THEME_HYDRATE_EVENT, onHydrate);
    return () => window.removeEventListener(THEME_HYDRATE_EVENT, onHydrate);
  }, []); // stable — no deps, listener identity doesn't matter

  // ── Seasonal resolution ───────────────────────────────────────────────────
  //
  // When autoSeasonal is on, the resolved theme is the current seasonal
  // theme. The manual preference is still stored under STORAGE_KEY so it
  // survives when the user turns seasonal off.

  const resolvedThemeName: ThemeName = React.useMemo(() => {
    if (!autoSeasonal) return themeName;
    const seasonal = getSeasonalThemeName(new Date());
    return isValidThemeName(seasonal) ? seasonal : themeName;
  }, [autoSeasonal, themeName]);

  const theme        = themes[resolvedThemeName];
  const capabilities = THEME_CAPABILITIES[resolvedThemeName];

  // ── Context value ─────────────────────────────────────────────────────────

  const value = React.useMemo<ThemeCtx>(
    () => ({
      themeName:    resolvedThemeName,
      setThemeName,
      isDarkMode:   theme.palette.mode === "dark",
      autoSeasonal,
      setAutoSeasonal,
      capabilities,
    }),
    [resolvedThemeName, setThemeName, theme.palette.mode, autoSeasonal, setAutoSeasonal, capabilities]
  );

  return (
    <ThemeContext.Provider value={value}>
      <ThemeProvider theme={theme}>
        <CssBaseline enableColorScheme />
        {children}
      </ThemeProvider>
    </ThemeContext.Provider>
  );
}
