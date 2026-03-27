// src/styles/ThemeStore.tsx
import * as React from "react";
import { CssBaseline, ThemeProvider } from "@mui/material";
import { themes, type ThemeName, getSeasonalThemeName } from "./themes";

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

const STORAGE_KEY      = "suspicious.theme";
const STORAGE_KEY_AUTO = "suspicious.theme.auto"; // "1" | "0"
const DEFAULT_THEME: ThemeName = "graphite";

// Custom event dispatched by hydrateThemeFromServer() so AppThemeProvider
// can react immediately without a page reload.
const THEME_HYDRATE_EVENT = "suspicious:theme-hydrate";

// ---------------------------------------------------------------------------
// Context type
// ---------------------------------------------------------------------------

type ThemeCtx = {
  themeName: ThemeName;
  setThemeName: (t: ThemeName) => void;
  isDarkMode: boolean;
  autoSeasonal: boolean;
  setAutoSeasonal: (v: boolean) => void;
};

const ThemeContext = React.createContext<ThemeCtx | null>(null);

// ---------------------------------------------------------------------------
// Hook
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

    const prefersDark =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-color-scheme: dark)")?.matches;

    return prefersDark ? "graphite" : "light";
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
    () => readBool(STORAGE_KEY_AUTO, true)
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

  const theme = themes[resolvedThemeName];

  // ── OS preference (fallback for new users with no stored preference) ─────

  React.useEffect(() => {
    try {
      const hasStored = isValidThemeName(localStorage.getItem(STORAGE_KEY));
      if (hasStored) return; // server/user preference wins — don't override

      const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
      if (!mq) return;

      const onChange = () => setThemeNameState(mq.matches ? "graphite" : "light");
      onChange();
      mq.addEventListener?.("change", onChange);
      return () => mq.removeEventListener?.("change", onChange);
    } catch { /* ignore */ }
  }, []);

  // ── Context value ─────────────────────────────────────────────────────────

  const value = React.useMemo<ThemeCtx>(
    () => ({
      themeName: resolvedThemeName,
      setThemeName,
      isDarkMode: theme.palette.mode === "dark",
      autoSeasonal,
      setAutoSeasonal,
    }),
    [resolvedThemeName, setThemeName, theme.palette.mode, autoSeasonal, setAutoSeasonal]
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