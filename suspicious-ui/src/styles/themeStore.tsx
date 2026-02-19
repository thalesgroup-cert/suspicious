// src/styles/ThemeStore.tsx
import * as React from "react";
import { CssBaseline, ThemeProvider } from "@mui/material";
import { themes, type ThemeName, getSeasonalThemeName } from "./themes";

const STORAGE_KEY = "suspicious.theme";
const STORAGE_KEY_AUTO = "suspicious.theme.auto"; // "1" | "0"
const DEFAULT_THEME: ThemeName = "graphite";

type ThemeCtx = {
  themeName: ThemeName;
  setThemeName: (t: ThemeName) => void;
  isDarkMode: boolean;
  autoSeasonal: boolean;
  setAutoSeasonal: (v: boolean) => void;
};

const ThemeContext = React.createContext<ThemeCtx | null>(null);

export function useThemeMode() {
  const ctx = React.useContext(ThemeContext);
  if (!ctx) throw new Error("useThemeMode must be used inside AppThemeProvider");
  return ctx;
}

function isValidThemeName(value: unknown): value is ThemeName {
  return typeof value === "string" && value in themes;
}

function readBool(key: string, fallback: boolean) {
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
  } catch {
    // ignore
  }
}

/**
 * System preference: used only on first run (when no stored theme).
 * - If system is dark => graphite
 * - If system is light => light
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

export function AppThemeProvider({ children }: { children: React.ReactNode }) {
  const [themeName, setThemeNameState] = React.useState<ThemeName>(getInitialTheme);

  // default: enabled on first run (if you prefer default off, set fallback to false)
  const [autoSeasonal, setAutoSeasonalState] = React.useState<boolean>(() => readBool(STORAGE_KEY_AUTO, true));

  const setThemeName = React.useCallback((t: ThemeName) => {
    if (!isValidThemeName(t)) return;
    setThemeNameState(t);
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      // ignore
    }
  }, []);

  const setAutoSeasonal = React.useCallback((v: boolean) => {
    setAutoSeasonalState(v);
    writeBool(STORAGE_KEY_AUTO, v);
  }, []);

  // If autoSeasonal is enabled, force the seasonal theme (still persists last manual choice in STORAGE_KEY).
  const resolvedThemeName: ThemeName = React.useMemo(() => {
    if (!autoSeasonal) return themeName;

    const seasonal = getSeasonalThemeName(new Date());
    // If seasonal theme is not present for any reason, keep current
    return isValidThemeName(seasonal) ? seasonal : themeName;
  }, [autoSeasonal, themeName]);

  const theme = themes[resolvedThemeName];

  // Keep system preference reactive only if no user theme stored yet (optional).
  // This only updates the theme on OS changes when there is no stored preference.
  React.useEffect(() => {
    try {
      const hasStored = isValidThemeName(localStorage.getItem(STORAGE_KEY));
      if (hasStored) return;

      const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
      if (!mq) return;

      const onChange = () => {
        const prefersDark = mq.matches;
        setThemeNameState(prefersDark ? "graphite" : "light");
      };

      // init
      onChange();

      // subscribe
      mq.addEventListener?.("change", onChange);
      return () => mq.removeEventListener?.("change", onChange);
    } catch {
      // ignore
    }
  }, []);

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
