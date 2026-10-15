import { describe, it, expect, beforeEach } from "vitest";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  AppThemeProvider,
  hydrateThemeFromServer,
  useThemeMode,
  THEME_CAPABILITIES,
} from "@/styles/ThemeStore";
import { themes } from "@/styles/themes";

const STORAGE_KEY = "suspicious.theme";
const STORAGE_KEY_AUTO = "suspicious.theme.auto";

function Probe() {
  const { themeName, setThemeName, autoSeasonal, setAutoSeasonal } = useThemeMode();
  return (
    <div>
      <span data-testid="theme">{themeName}</span>
      <span data-testid="auto">{autoSeasonal ? "1" : "0"}</span>
      <button type="button" onClick={() => setThemeName("cyber")}>cyber</button>
      <button type="button" onClick={() => setAutoSeasonal(false)}>auto-off</button>
    </div>
  );
}

describe("ThemeStore", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("setThemeName writes the selected theme to localStorage", async () => {
    render(
      <AppThemeProvider>
        <Probe />
      </AppThemeProvider>
    );

    await userEvent.click(screen.getByText("auto-off"));
    await userEvent.click(screen.getByText("cyber"));

    expect(screen.getByTestId("theme")).toHaveTextContent("cyber");
    expect(localStorage.getItem(STORAGE_KEY)).toBe("cyber");
    expect(localStorage.getItem(STORAGE_KEY_AUTO)).toBe("0");
  });

  it("setThemeName ignores invalid theme names", async () => {
    localStorage.setItem(STORAGE_KEY, "graphite");
    localStorage.setItem(STORAGE_KEY_AUTO, "0");

    render(
      <AppThemeProvider>
        <Probe />
      </AppThemeProvider>
    );

    expect(screen.getByTestId("theme")).toHaveTextContent("graphite");

    act(() => {
      hydrateThemeFromServer("nonexistent-theme", false);
    });

    expect(screen.getByTestId("theme")).toHaveTextContent("graphite");
    expect(localStorage.getItem(STORAGE_KEY)).toBe("graphite");
  });

  it("hydrateThemeFromServer applies the server preference immediately", async () => {
    render(
      <AppThemeProvider>
        <Probe />
      </AppThemeProvider>
    );

    act(() => {
      hydrateThemeFromServer("valentine", false);
    });

    expect(screen.getByTestId("theme")).toHaveTextContent("valentine");
    expect(screen.getByTestId("auto")).toHaveTextContent("0");
    expect(localStorage.getItem(STORAGE_KEY)).toBe("valentine");
    expect(localStorage.getItem(STORAGE_KEY_AUTO)).toBe("0");
  });
});

describe("Renée theme", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("is registered as a valid light theme with the orchid-ink palette", () => {
    expect("renee" in themes).toBe(true);

    const t = themes.renee;
    expect(t.palette.mode).toBe("light");
    expect(t.palette.primary.main.toUpperCase()).toBe("#9B2FA8");
    expect(t.palette.error.main.toUpperCase()).toBe("#B23A2E");
    expect(t.palette.success.main.toUpperCase()).toBe("#4E7A3A");
    expect(t.palette.background.default.toUpperCase()).toBe("#F1E8DC");
  });

  it("exposes capabilities labelled Renée and marked light", () => {
    const cap = THEME_CAPABILITIES.renee;
    expect(cap.label).toBe("Renée");
    expect(cap.isDark).toBe(false);
    expect(cap.effects).toEqual({});
  });

  it("hydrateThemeFromServer accepts renee as a valid name", () => {
    render(
      <AppThemeProvider>
        <Probe />
      </AppThemeProvider>
    );
    act(() => {
      hydrateThemeFromServer("renee", false);
    });
    expect(screen.getByTestId("theme")).toHaveTextContent("renee");
    expect(localStorage.getItem(STORAGE_KEY)).toBe("renee");
  });
});

describe("Lure theme", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("is a dark theme with translucent surfaces and the logo's orange as warning", () => {
    expect(themes.lure.palette.mode).toBe("dark");
    expect(themes.lure.palette.background.default.toLowerCase()).toBe("#151515");
    expect(themes.lure.palette.warning.main.toUpperCase()).toBe("#F08A24");
  });

  it("is the only theme with the glyph-smoke backdrop", () => {
    expect(THEME_CAPABILITIES.lure.effects.hasGlyphSmokeEffect).toBe(true);
    const others = Object.entries(THEME_CAPABILITIES).filter(([k, v]) => k !== "lure" && v.effects.hasGlyphSmokeEffect);
    expect(others).toEqual([]);
  });

  it("mounts the backdrop only while lure is active", () => {
    function Switch() {
      const { setThemeName } = useThemeMode();
      return (
        <>
          <button type="button" onClick={() => setThemeName("lure")}>lure</button>
          <button type="button" onClick={() => setThemeName("graphite")}>graphite</button>
        </>
      );
    }
    localStorage.setItem(STORAGE_KEY, "graphite");
    localStorage.setItem(STORAGE_KEY_AUTO, "0");
    render(<AppThemeProvider><Switch /></AppThemeProvider>);
    expect(screen.queryByTestId("glyph-smoke")).toBeNull();
    act(() => { hydrateThemeFromServer("lure", false); });
    expect(screen.getByTestId("glyph-smoke")).toBeInTheDocument();
    act(() => { hydrateThemeFromServer("graphite", false); });
    expect(screen.queryByTestId("glyph-smoke")).toBeNull();
  });
});
