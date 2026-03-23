// src/styles/themes.ts
import { createTheme, alpha, type ThemeOptions } from "@mui/material/styles";

// ---------------------------------------------------------------------------
// Font stacks
// ---------------------------------------------------------------------------

const sansStack = [
  "Inter", "system-ui", "-apple-system", "Segoe UI",
  "Roboto", "Arial", "sans-serif",
].join(",");

const monoStack = [
  '"IBM Plex Mono"', "ui-monospace", "SFMono-Regular",
  "Menlo", "Monaco", "Consolas", '"Courier New"', "monospace",
].join(",");

const serifStack = [
  '"Iowan Old Style"', '"Palatino Linotype"', "Palatino", "Georgia", "serif",
].join(",");

const roundedStack = [
  '"Nunito"', "Inter", "system-ui", "-apple-system",
  "Segoe UI", "Roboto", "Arial", "sans-serif",
].join(",");

// ---------------------------------------------------------------------------
// Texture helpers
// ---------------------------------------------------------------------------

const border = (hex: string, a: number) => `1px solid ${alpha(hex, a)}`;

const scanlines = (a = 0.035, step = 4) =>
  `repeating-linear-gradient(0deg, rgba(255,255,255,${a}), rgba(255,255,255,${a}) 1px, transparent 1px, transparent ${step}px)`;

const grid = (a = 0.03, step = 18) =>
  `repeating-linear-gradient(0deg, rgba(255,255,255,${a}), rgba(255,255,255,${a}) 1px, transparent 1px, transparent ${step}px),
   repeating-linear-gradient(90deg, rgba(255,255,255,${a}), rgba(255,255,255,${a}) 1px, transparent 1px, transparent ${step}px)`;

const noiseSVG = (opacity = 0.06) => {
  const svg = encodeURIComponent(`
    <svg xmlns="http://www.w3.org/2000/svg" width="120" height="120">
      <filter id="n">
        <feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="3" stitchTiles="stitch"/>
        <feColorMatrix type="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 ${opacity} 0"/>
      </filter>
      <rect width="120" height="120" filter="url(#n)"/>
    </svg>
  `);
  return `url("data:image/svg+xml,${svg}")`;
};

// Horizontal scanlines tinted with a colour (for dystopian / CRT feels)
const tintedScanlines = (hex: string, a = 0.04, step = 3) =>
  `repeating-linear-gradient(0deg, ${alpha(hex, a)}, ${alpha(hex, a)} 1px, transparent 1px, transparent ${step}px)`;

// ---------------------------------------------------------------------------
// Base MUI theme defaults (shared across all themes)
// ---------------------------------------------------------------------------

const base: ThemeOptions = {
  shape: { borderRadius: 4 },
  typography: {
    fontFamily: sansStack,
    fontSize: 13,
    h1: { fontSize: 28, fontWeight: 750, letterSpacing: -0.6 },
    h2: { fontSize: 22, fontWeight: 750, letterSpacing: -0.4 },
    h3: { fontSize: 18, fontWeight: 750, letterSpacing: -0.2 },
    h4: { fontSize: 16, fontWeight: 750 },
    h5: { fontSize: 14, fontWeight: 750 },
    body1: { fontSize: 13, lineHeight: 1.55 },
    body2: { fontSize: 12.5, lineHeight: 1.5 },
    caption: { fontSize: 12, lineHeight: 1.35 },
    button: { textTransform: "none", fontWeight: 650 },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          textRendering: "optimizeLegibility",
          WebkitFontSmoothing: "antialiased",
          MozOsxFontSmoothing: "grayscale",
        },
      },
    },
    MuiContainer: { defaultProps: { maxWidth: "xl" } },
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: {
        root: { borderRadius: 10, paddingInline: 12, height: 34 },
        sizeSmall: { height: 30, paddingInline: 10 },
        sizeLarge: { height: 40, paddingInline: 14 },
      },
    },
    MuiIconButton: { styleOverrides: { root: { borderRadius: 10 } } },
    MuiTextField: { defaultProps: { variant: "outlined", size: "small" } },
    MuiOutlinedInput: {
      styleOverrides: {
        root: ({ theme }) => ({
          borderRadius: 10,
          backgroundColor:
            theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.04) : alpha("#0B1220", 0.03),
          transition: "background-color 120ms ease, border-color 120ms ease",
          "&:hover": {
            backgroundColor:
              theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.06) : alpha("#0B1220", 0.045),
          },
          "&.Mui-focused": {
            backgroundColor:
              theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.05) : alpha("#0B1220", 0.035),
          },
        }),
        notchedOutline: ({ theme }) => ({
          borderColor:
            theme.palette.mode === "dark" ? alpha("#E5E7EB", 0.14) : alpha("#0B1220", 0.14),
        }),
      },
    },
    MuiInputLabel: { styleOverrides: { root: { fontSize: 12.5 } } },
    MuiSelect: { defaultProps: { size: "small" } },
    MuiPaper: {
      styleOverrides: {
        root: ({ theme }) => ({
          backgroundImage: "none",
          borderRadius: 14,
          border:
            theme.palette.mode === "dark" ? border("#E5E7EB", 0.1) : border("#0B1220", 0.08),
        }),
      },
    },
    MuiCard: {
      styleOverrides: {
        root: ({ theme }) => ({
          borderRadius: 16,
          border:
            theme.palette.mode === "dark" ? border("#E5E7EB", 0.12) : border("#0B1220", 0.08),
          boxShadow: "none",
        }),
      },
    },
    MuiDivider: {
      styleOverrides: {
        root: ({ theme }) => ({
          borderColor:
            theme.palette.mode === "dark" ? alpha("#E5E7EB", 0.1) : alpha("#0B1220", 0.1),
        }),
      },
    },
    MuiChip: {
      defaultProps: { size: "small" },
      styleOverrides: {
        root: ({ theme }) => ({
          borderRadius: 10,
          fontWeight: 600,
          height: 24,
          backgroundColor:
            theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.06) : alpha("#0B1220", 0.05),
          border:
            theme.palette.mode === "dark" ? border("#E5E7EB", 0.12) : border("#0B1220", 0.1),
        }),
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: ({ theme }) => ({
          fontSize: 12,
          padding: "8px 10px",
          borderRadius: 10,
          backgroundColor:
            theme.palette.mode === "dark"
              ? alpha("#0B1220", 0.92)
              : alpha("#0B1220", 0.9),
          border: border("#E5E7EB", theme.palette.mode === "dark" ? 0.12 : 0.1),
        }),
      },
    },
    MuiAlert: {
      defaultProps: { variant: "outlined" },
      styleOverrides: {
        root: ({ theme }) => ({
          borderRadius: 14,
          alignItems: "center",
          backgroundColor:
            theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.03) : alpha("#0B1220", 0.02),
        }),
        message: { fontSize: 12.5 },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: { paddingTop: 8, paddingBottom: 8, borderBottomStyle: "solid" },
        head: ({ theme }) => ({
          fontSize: 12,
          fontWeight: 750,
          color: theme.palette.text.secondary,
          backgroundColor:
            theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.03) : alpha("#0B1220", 0.025),
        }),
      },
    },
    MuiTableRow: {
      styleOverrides: {
        root: ({ theme }) => ({
          "&:hover": {
            backgroundColor:
              theme.palette.mode === "dark"
                ? alpha("#FFFFFF", 0.04)
                : alpha("#0B1220", 0.03),
          },
        }),
      },
    },
    MuiLink: {
      defaultProps: { underline: "hover" },
      styleOverrides: {
        root: ({ theme }) => ({ fontWeight: 600, color: theme.palette.primary.main }),
      },
    },
  },
};

// ---------------------------------------------------------------------------
// Helper factories
// ---------------------------------------------------------------------------

function mkDark(opts: {
  bg: string;
  paper: string;
  primary: string;
  secondary: string;
  info?: string;
  success?: string;
  warning?: string;
  error?: string;
  text?: string;
  components?: ThemeOptions["components"];
  typography?: ThemeOptions["typography"];
  shape?: ThemeOptions["shape"];
}) {
  const textPrimary = opts.text ?? "#E8EDF4";
  return createTheme({
    ...base,
    ...(opts.shape ? { shape: opts.shape } : {}),
    ...(opts.typography ? { typography: { ...base.typography, ...opts.typography } } : {}),
    palette: {
      mode: "dark",
      background: { default: opts.bg, paper: opts.paper },
      primary: { main: opts.primary },
      secondary: { main: opts.secondary },
      info: { main: opts.info ?? "#60A5FA" },
      success: { main: opts.success ?? "#34D399" },
      warning: { main: opts.warning ?? "#FBBF24" },
      error: { main: opts.error ?? "#FF6B6B" },
      text: { primary: textPrimary, secondary: alpha(textPrimary, 0.72) },
    },
    components: { ...base.components, ...(opts.components ?? {}) },
  });
}

function mkLight(opts: {
  bg: string;
  paper: string;
  primary: string;
  secondary: string;
  info?: string;
  success?: string;
  warning?: string;
  error?: string;
  text?: string;
  components?: ThemeOptions["components"];
  typography?: ThemeOptions["typography"];
  shape?: ThemeOptions["shape"];
}) {
  const textPrimary = opts.text ?? "#0B1220";
  return createTheme({
    ...base,
    ...(opts.shape ? { shape: opts.shape } : {}),
    ...(opts.typography ? { typography: { ...base.typography, ...opts.typography } } : {}),
    palette: {
      mode: "light",
      background: { default: opts.bg, paper: opts.paper },
      primary: { main: opts.primary },
      secondary: { main: opts.secondary },
      info: { main: opts.info ?? "#2563EB" },
      success: { main: opts.success ?? "#067647" },
      warning: { main: opts.warning ?? "#B54708" },
      error: { main: opts.error ?? "#D92D20" },
      text: { primary: textPrimary, secondary: alpha(textPrimary, 0.7) },
    },
    components: {
      ...base.components,
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 10,
            backgroundColor: alpha("#0B1220", 0.03),
            "&:hover": { backgroundColor: alpha("#0B1220", 0.045) },
            "&.Mui-focused": { backgroundColor: alpha("#0B1220", 0.035) },
          },
          notchedOutline: { borderColor: alpha("#0B1220", 0.14) },
        },
      },
      MuiPaper: {
        styleOverrides: { root: { boxShadow: "none", border: border("#0B1220", 0.08) } },
      },
      MuiCard: {
        styleOverrides: { root: { boxShadow: "none", border: border("#0B1220", 0.08) } },
      },
      ...(opts.components ?? {}),
    },
  });
}

// ---------------------------------------------------------------------------
// ThemeName
// ---------------------------------------------------------------------------

export type ThemeName =
  | "midnight"
  | "graphite"
  | "slate"
  | "light"
  | "paper"
  | "high_contrast"
  | "sunrise"
  | "valentine"
  | "cyber"
  | "the_one"
  | "winter"
  | "spring"
  | "summer"
  | "autumn"
  | "metal"
  | "future";

export function getSeasonalThemeName(date = new Date()): ThemeName {
  const m = date.getMonth();
  if (m === 11 || m <= 1) return "winter";
  if (m >= 2 && m <= 4)  return "spring";
  if (m >= 5 && m <= 7)  return "summer";
  if (m >= 8 && m <= 10) return "autumn";
  return "graphite";
}

// ---------------------------------------------------------------------------
// Themes
// ---------------------------------------------------------------------------

export const themes: Record<ThemeName, ReturnType<typeof createTheme>> = {

  // ── 1. MIDNIGHT — deep space, not just "dark navy" ────────────────────
  // True void black background with electric blue accent — like staring
  // into a server room at 3 AM. Sharp edges, high contrast text.
  midnight: mkDark({
    bg: "#03050D",
    paper: "#080D1A",
    primary: "#4D8FFF",
    secondary: "#7BB3FF",
    info: "#60A5FA",
    success: "#22D67A",
    warning: "#F5A623",
    error: "#F56565",
    text: "#E6ECF8",
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#03050D",
            backgroundImage: `
              radial-gradient(ellipse 1400px 700px at 20% -5%, rgba(77,143,255,.22), transparent 60%),
              radial-gradient(ellipse 1000px 600px at 90% 15%, rgba(123,179,255,.14), transparent 55%),
              ${noiseSVG(0.04)}
            `,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            backgroundImage: "linear-gradient(180deg, rgba(255,255,255,.055), rgba(255,255,255,.02))",
            backdropFilter: "blur(12px)",
            border: `1px solid ${alpha("#4D8FFF", 0.12)}`,
          }),
        },
      },
      MuiButton: {
        styleOverrides: {
          containedPrimary: ({ theme }) => ({
            backgroundImage: `linear-gradient(180deg, ${alpha("#4D8FFF", 0.95)}, ${alpha("#3A7AE8", 0.85)})`,
            boxShadow: `0 4px 16px ${alpha("#4D8FFF", 0.3)}`,
          }),
        },
      },
    },
  }),

  // ── 2. GRAPHITE — industrial matte, the workhorse ─────────────────────
  // Pulled-back desaturated dark. Everything recedes except what matters.
  // Like a military briefing room — functional, no decoration, no apology.
  graphite: mkDark({
    bg: "#0A0C10",
    paper: "#10141C",
    primary: "#4FB3FF",
    secondary: "#7A9EB8",
    info: "#60A5FA",
    success: "#3DDC97",
    warning: "#F6C177",
    error: "#FF6B6B",
    text: "#E8EDF4",
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#0A0C10",
            backgroundImage: `
              radial-gradient(ellipse 1200px 500px at 30% -10%, rgba(79,179,255,.09), transparent 55%),
              ${noiseSVG(0.07)}
            `,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: { backgroundImage: "none", border: "1px solid rgba(229,231,235,.10)" },
        },
      },
    },
  }),

  // ── 3. SLATE — blueprint engineering ──────────────────────────────────
  // Technical blue-ink on dark paper. Grid underlays, mono headings,
  // the feel of reading a technical schematic. Calm authority.
  slate: mkDark({
    bg: "#08101E",
    paper: "#0E1830",
    primary: "#5D9EFF",
    secondary: "#6EC2F5",
    info: "#38BDF8",
    success: "#34D399",
    warning: "#FBBF24",
    error: "#F87171",
    text: "#DDE8F8",
    typography: {
      h1: { fontFamily: monoStack, fontWeight: 850, letterSpacing: -0.7 },
      h2: { fontFamily: monoStack, fontWeight: 850 },
      h3: { fontFamily: monoStack, fontWeight: 800 },
      button: { fontFamily: monoStack, letterSpacing: 0.4, fontWeight: 800 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#08101E",
            backgroundImage: `
              ${grid(0.022, 24)},
              radial-gradient(ellipse 1000px 600px at 75% -15%, rgba(93,158,255,.18), transparent 60%)
            `,
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: ({ theme }) => ({
            fontFamily: monoStack,
            textTransform: "uppercase",
            letterSpacing: 0.7,
            backgroundColor: alpha("#ffffff", 0.03),
          }),
        },
      },
    },
  }),

  // ── 4. LIGHT — clean product, max clarity ─────────────────────────────
  // Pure white surfaces, strong blue accent. Zero texture, zero gradient
  // background — everything is sharp and professional.
  light: mkLight({
    bg: "#F4F5F7",
    paper: "#FFFFFF",
    primary: "#1B5FFF",
    secondary: "#0D766B",
    info: "#2563EB",
    success: "#067647",
    warning: "#B54708",
    error: "#C4281C",
    text: "#0B1220",
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#F4F5F7",
            backgroundImage: `radial-gradient(ellipse 1200px 600px at 15% -5%, rgba(27,95,255,.08), transparent 55%)`,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            boxShadow: "0 2px 8px rgba(11,18,32,.07), 0 0 0 1px rgba(11,18,32,.07)",
            border: "none",
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            boxShadow: "0 2px 8px rgba(11,18,32,.07), 0 0 0 1px rgba(11,18,32,.07)",
            border: "none",
          },
        },
      },
    },
  }),

  // ── 5. PAPER — archival, warm ink on cream ────────────────────────────
  // Serifed, warm, analogue. Like reading a printed security brief.
  // Noise texture gives it physical weight. Deep ink blue accent.
  paper: mkLight({
    bg: "#F0EDE7",
    paper: "#FDFBF8",
    primary: "#0F4CFF",
    secondary: "#34495E",
    info: "#1D4ED8",
    success: "#056139",
    warning: "#7A4100",
    error: "#B42318",
    text: "#111827",
    typography: {
      fontFamily: serifStack,
      h1: { fontFamily: serifStack, fontWeight: 800, letterSpacing: -0.4 },
      h2: { fontFamily: serifStack, fontWeight: 800 },
      h3: { fontFamily: serifStack, fontWeight: 750 },
      button: { fontFamily: serifStack, fontWeight: 800 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#F0EDE7",
            backgroundImage: noiseSVG(0.14),
            backgroundBlendMode: "multiply",
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: `linear-gradient(180deg, rgba(255,255,255,.7), rgba(255,255,255,.95)), ${noiseSVG(0.1)}`,
            backgroundBlendMode: "normal, multiply",
            border: border("#111827", 0.1),
            boxShadow: "0 1px 3px rgba(17,24,39,.08)",
          },
        },
      },
    },
  }),

  // ── 6. HIGH CONTRAST — pure accessibility terminal ────────────────────
  // Absolute black, absolute white. No ambiguity. Every element renders
  // as pure on/off. Critical for low-vision and screen readers.
  high_contrast: mkDark({
    bg: "#000000",
    paper: "#080808",
    primary: "#FFFFFF",
    secondary: "#FFFFFF",
    info: "#FFFFFF",
    success: "#00FF88",
    warning: "#FFD600",
    error: "#FF3B30",
    text: "#FFFFFF",
    shape: { borderRadius: 0 },
    typography: {
      fontFamily: monoStack,
      button: {
        fontFamily: monoStack,
        fontWeight: 900,
        letterSpacing: 1.2,
        textTransform: "uppercase",
      },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: { backgroundColor: "#000000" },
          "*, *::before, *::after": { outlineColor: "#FFFFFF !important" },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: { borderRadius: 0, border: "2px solid rgba(255,255,255,.88)" },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: { borderRadius: 0, border: "2px solid rgba(255,255,255,.88)" },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: { borderRadius: 0, border: "2px solid rgba(255,255,255,.88)" },
          containedPrimary: {
            backgroundColor: "#FFFFFF",
            color: "#000000",
            "&:hover": { backgroundColor: "#E0E0E0" },
          },
        },
      },
    },
  }),

  // ── 7. SUNRISE — warmth, energy, optimism ─────────────────────────────
  // Coral + amber gradient light. The feeling of a 7 AM alert being
  // resolved just as the sun comes up. Rounded, friendly, human.
  sunrise: mkLight({
    bg: "#FFF5F0",
    paper: "#FFFFFF",
    primary: "#F03D2F",
    secondary: "#FF8C00",
    info: "#0EA5E9",
    success: "#16A34A",
    warning: "#D97706",
    error: "#DC2626",
    text: "#1A1A2E",
    typography: { fontFamily: roundedStack },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#FFF5F0",
            backgroundImage: `
              radial-gradient(ellipse 900px 500px at 10% 5%, rgba(240,61,47,.14), transparent 55%),
              radial-gradient(ellipse 800px 500px at 90% 20%, rgba(255,140,0,.14), transparent 55%),
              ${noiseSVG(0.04)}
            `,
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: { borderRadius: 999, height: 36 },
          containedPrimary: ({ theme }) => ({
            backgroundImage: `linear-gradient(135deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
            boxShadow: `0 4px 16px ${alpha(theme.palette.primary.main, 0.35)}`,
          }),
        },
      },
      MuiChip: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 999,
            backgroundImage: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.15)}, ${alpha(theme.palette.secondary.main, 0.12)})`,
          }),
        },
      },
    },
  }),

  // ── 8. VALENTINE — bold berry, glass softness ─────────────────────────
  // Deep rose + magenta on white glass. Not "cute pink" — this is
  // bold and saturated. Berry-stained fingertips meeting crystal.
  valentine: mkLight({
    bg: "#FFF0F4",
    paper: "#FFFFFF",
    primary: "#C2185B",
    secondary: "#E91E8C",
    info: "#7C3AED",
    success: "#15803D",
    warning: "#B45309",
    error: "#B91C1C",
    text: "#1A0814",
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#FFF0F4",
            backgroundImage: `
              radial-gradient(ellipse 900px 500px at 15% 0%, rgba(194,24,91,.15), transparent 55%),
              radial-gradient(ellipse 800px 500px at 85% 15%, rgba(233,30,140,.12), transparent 55%),
              ${noiseSVG(0.04)}
            `,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backdropFilter: "blur(12px)",
            backgroundImage: `linear-gradient(180deg, rgba(255,255,255,.88), rgba(255,255,255,.98))`,
            border: border("#C2185B", 0.12),
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: { borderRadius: 14, height: 36 },
        },
      },
    },
  }),

  // ── 9. CYBER — neon on void, maximum contrast ─────────────────────────
  // This is NOT a gentle dark blue. It's a black void with electric
  // cyan + magenta neon. CRT scanlines. Monospace everywhere.
  // Like operating a terminal in 2077 while someone plays synthwave.
  cyber: mkDark({
    bg: "#020408",
    paper: "#06090F",
    primary: "#00E5FF",
    secondary: "#FF00CC",
    info: "#00FF88",
    success: "#00FF88",
    warning: "#FFD600",
    error: "#FF1744",
    text: "#E8F4FF",
    typography: {
      fontFamily: monoStack,
      h1: { fontFamily: monoStack, fontWeight: 900, letterSpacing: -0.8 },
      h2: { fontFamily: monoStack, fontWeight: 900 },
      h3: { fontFamily: monoStack, fontWeight: 850 },
      button: {
        fontFamily: monoStack,
        letterSpacing: 1.2,
        fontWeight: 900,
        textTransform: "uppercase",
      },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#020408",
            backgroundImage: `
              radial-gradient(ellipse 1000px 600px at 15% 10%, rgba(0,229,255,.12), transparent 55%),
              radial-gradient(ellipse 800px 500px at 85% 15%, rgba(255,0,204,.1), transparent 55%),
              ${scanlines(0.028, 3)}
            `,
          },
          "@keyframes neonPulse": {
            "0%, 100%": { opacity: 1 },
            "50%": { opacity: 0.75 },
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            backgroundImage: "none",
            backgroundColor: alpha("#020408", 0.9),
            border: `1px solid ${alpha("#00E5FF", 0.18)}`,
            boxShadow: `0 0 0 1px ${alpha("#FF00CC", 0.08)}`,
            position: "relative",
            overflow: "hidden",
            "&::before": {
              content: '""',
              position: "absolute",
              inset: 0,
              backgroundImage: scanlines(0.02, 3),
              opacity: 0.4,
              pointerEvents: "none",
            },
          }),
        },
      },
      MuiButton: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 4,
            border: `1px solid ${alpha("#00E5FF", 0.45)}`,
            backgroundImage: "none",
            backgroundColor: alpha("#00E5FF", 0.06),
            "&:hover": {
              backgroundColor: alpha("#00E5FF", 0.12),
              boxShadow: `0 0 16px ${alpha("#00E5FF", 0.25)}`,
            },
          }),
          containedPrimary: ({ theme }) => ({
            backgroundImage: "none",
            backgroundColor: "#00E5FF",
            color: "#000",
            boxShadow: `0 0 20px ${alpha("#00E5FF", 0.45)}`,
            "&:hover": {
              backgroundColor: "#33ECFF",
              boxShadow: `0 0 28px ${alpha("#00E5FF", 0.6)}`,
            },
          }),
        },
      },
    },
  }),

  // ── 10. THE ONE — luxury, gold on obsidian ────────────────────────────
  // Cream text on near-black. Gold primary. This is what the inside of
  // a premium security briefing room looks like. No compromise, no noise.
  the_one: mkDark({
    bg: "#060606",
    paper: "#0D0D0D",
    primary: "#C9A84C",
    secondary: "#E8D5A3",
    info: "#6B9FD4",
    success: "#4CAF82",
    warning: "#E8A020",
    error: "#E05252",
    text: "#F0ECD8",
    typography: {
      h1: { fontWeight: 900, letterSpacing: -0.8 },
      h2: { fontWeight: 850, letterSpacing: -0.5 },
      button: { fontWeight: 900, letterSpacing: 0.5 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#060606",
            backgroundImage: `
              radial-gradient(ellipse 1200px 600px at 25% -5%, rgba(201,168,76,.14), transparent 55%),
              ${noiseSVG(0.06)}
            `,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            backgroundImage: "linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.015))",
            border: `1px solid ${alpha("#C9A84C", 0.16)}`,
          }),
        },
      },
      MuiButton: {
        styleOverrides: {
          containedPrimary: ({ theme }) => ({
            color: "#060606",
            backgroundImage: `linear-gradient(180deg, ${alpha("#C9A84C", 0.98)}, ${alpha("#A8893A", 0.9)})`,
            boxShadow: `0 4px 18px ${alpha("#C9A84C", 0.28)}`,
            border: `1px solid ${alpha("#C9A84C", 0.5)}`,
          }),
        },
      },
    },
  }),

  // ── 11. METAL — stealth HUD, alert red, CRT edges ─────────────────────
  // Emergency response aesthetic. Red primary on near-black with
  // scanlines and grid. Monospace everywhere. Alarm-room severity.
  metal: createTheme({
    ...base,
    shape: { borderRadius: 4 },
    typography: {
      fontFamily: sansStack,
      fontSize: 13,
      h1: { fontSize: 28, fontWeight: 900, letterSpacing: -0.8, fontFamily: monoStack },
      h2: { fontSize: 22, fontWeight: 900, letterSpacing: -0.6, fontFamily: monoStack },
      h3: { fontSize: 18, fontWeight: 850, letterSpacing: -0.3, fontFamily: monoStack },
      h4: { fontSize: 16, fontWeight: 750, fontFamily: monoStack },
      h5: { fontSize: 14, fontWeight: 750, fontFamily: monoStack },
      body1: { fontSize: 13, lineHeight: 1.55 },
      body2: { fontSize: 12.5, lineHeight: 1.5 },
      caption: { fontSize: 12, lineHeight: 1.35 },
      button: {
        textTransform: "uppercase",
        letterSpacing: 1.0,
        fontWeight: 900,
        fontFamily: monoStack,
      },
    },
    palette: {
      mode: "dark",
      background: { default: "#06080C", paper: "#0A0F15" },
      primary: { main: "#E1061B" },
      secondary: { main: "#EDEDED" },
      info: { main: "#37D6C7" },
      success: { main: "#2DE39A" },
      warning: { main: "#F2C94C" },
      error: { main: "#E1061B" },
      text: { primary: "#EDEDED", secondary: alpha("#EDEDED", 0.72) },
    },
    components: {
      ...base.components,
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#06080C",
            backgroundImage: `
              radial-gradient(ellipse 1000px 600px at 50% -10%, rgba(55,214,199,.08), transparent 55%),
              radial-gradient(ellipse 800px 500px at 10% 15%, rgba(225,6,27,.1), transparent 55%),
              ${scanlines(0.025, 4)},
              ${grid(0.015, 28)}
            `,
          },
          "@keyframes alertPulse": {
            "0%, 100%": { boxShadow: "none" },
            "50%": { boxShadow: "0 0 0 1px rgba(225,6,27,.22), 0 0 24px rgba(225,6,27,.1)" },
          },
          ".hud-alertable": { transition: "box-shadow 160ms ease" },
          'body[data-alert="on"] .hud-alertable': {
            animation: "alertPulse 1400ms ease-in-out infinite",
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            borderRadius: 10,
            border: `1px solid ${alpha("#EDEDED", 0.1)}`,
            position: "relative",
            overflow: "hidden",
            "&::before": {
              content: '""',
              position: "absolute",
              inset: 0,
              backgroundImage: scanlines(0.018, 4),
              opacity: 0.3,
              pointerEvents: "none",
              mixBlendMode: "overlay",
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            border: `1px solid ${alpha("#EDEDED", 0.2)}`,
            backgroundImage: `linear-gradient(180deg, ${alpha("#EDEDED", 0.06)}, ${alpha("#EDEDED", 0.02)})`,
          },
          containedPrimary: ({ theme }) => ({
            borderColor: alpha(theme.palette.primary.main, 0.6),
            backgroundImage: `linear-gradient(180deg, ${alpha(theme.palette.primary.main, 0.9)}, ${alpha(theme.palette.primary.main, 0.7)})`,
            color: "#fff",
            boxShadow: `0 0 18px ${alpha(theme.palette.primary.main, 0.3)}`,
          }),
        },
      },
    },
  }),

  // ── 12–15. SEASONAL ──────────────────────────────────────────────────

  // WINTER — frost and deep space ice
  winter: mkDark({
    bg: "#04080F",
    paper: "#08122A",
    primary: "#7DD3FC",
    secondary: "#A5B4FC",
    info: "#38BDF8",
    success: "#34D399",
    warning: "#FBBF24",
    error: "#FB7185",
    text: "#E8F2FF",
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#04080F",
            backgroundImage: `
              radial-gradient(ellipse 1200px 600px at 20% 0%, rgba(125,211,252,.18), transparent 55%),
              radial-gradient(ellipse 900px 500px at 80% 15%, rgba(165,180,252,.14), transparent 55%),
              ${noiseSVG(0.04)}
            `,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            border: `1px solid ${alpha("#7DD3FC", 0.14)}`,
            backgroundImage: `linear-gradient(180deg, ${alpha("#7DD3FC", 0.04)}, transparent)`,
          }),
        },
      },
    },
  }),

  // SPRING — botanical fresh, dew on green leaves
  spring: mkLight({
    bg: "#F2FFF5",
    paper: "#FFFFFF",
    primary: "#15803D",
    secondary: "#5B21B6",
    info: "#0284C7",
    success: "#15803D",
    warning: "#92400E",
    error: "#B91C1C",
    text: "#0B1A10",
    typography: { fontFamily: roundedStack },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#F2FFF5",
            backgroundImage: `
              radial-gradient(ellipse 900px 500px at 15% 0%, rgba(21,128,61,.14), transparent 55%),
              radial-gradient(ellipse 700px 400px at 85% 15%, rgba(91,33,182,.08), transparent 55%),
              radial-gradient(circle, rgba(11,26,16,.045) 1.5px, transparent 1.5px)
            `,
            backgroundSize: "auto, auto, 22px 22px",
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: { borderRadius: 999 },
        },
      },
    },
  }),

  // SUMMER — heat haze, amber sun on bone-white
  summer: mkLight({
    bg: "#FFFBEA",
    paper: "#FFFFFF",
    primary: "#D97706",
    secondary: "#DC2626",
    info: "#0369A1",
    success: "#15803D",
    warning: "#D97706",
    error: "#DC2626",
    text: "#1A1000",
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#FFFBEA",
            backgroundImage: `
              radial-gradient(ellipse 900px 500px at 15% 0%, rgba(217,119,6,.16), transparent 55%),
              radial-gradient(ellipse 700px 400px at 85% 15%, rgba(220,38,38,.1), transparent 55%),
              radial-gradient(circle, rgba(26,16,0,.04) 1px, transparent 1px)
            `,
            backgroundSize: "auto, auto, 10px 10px",
          },
        },
      },
    },
  }),

  // AUTUMN — ember glow, soot, deep terracotta
  autumn: mkDark({
    bg: "#0C0805",
    paper: "#170D09",
    primary: "#F97316",
    secondary: "#EAB308",
    info: "#60A5FA",
    success: "#34D399",
    warning: "#EAB308",
    error: "#EF4444",
    text: "#F5EDE0",
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#0C0805",
            backgroundImage: `
              radial-gradient(ellipse 1200px 600px at 20% 0%, rgba(249,115,22,.2), transparent 55%),
              radial-gradient(ellipse 900px 500px at 85% 15%, rgba(234,179,8,.13), transparent 55%),
              ${noiseSVG(0.08)}
            `,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            border: `1px solid ${alpha("#F97316", 0.14)}`,
          }),
        },
      },
    },
  }),


  // ── 16. FUTURE — Le Visiteur du Futur ────────────────────────────────
  //
  // «Je viens du futur. Si vous ne m'écoutez pas, voilà ce qui va se passer.»
  //
  // UNIVERSE: French sci-fi web series (2009–2014) by François Descraques,
  // adapted into a film in 2022. The Visitor (Raph) time-travels from 2555
  // wearing a copper bracelet, pursued by the Brigade Temporelle.
  // Year 2555: nuclear-devastated Paris — ash, rubble, fire, and Fennec
  // the small fennec fox who becomes the Visitor's inseparable companion.
  //
  // PALETTE — extracted directly from the film posters:
  //
  //   SCORCHED AMBER   #E8720C  — PRIMARY. The dominant warm glow of the
  //                              poster: fire, the Visitor's leather coat,
  //                              the amber atmosphere of the apocalypse.
  //                              Also the colour of Fennec's fur.
  //
  //   BRIGADE STEEL    #4A90D9  — SECONDARY. The cold blue half of the
  //                              split-tone poster — Brigade Temporelle
  //                              armour, the future sky before the blast,
  //                              the portal's arrival flash.
  //
  //   TEMPORAL COPPER  #C87941  — The bracelet itself. Oxidised copper
  //                              with warm highlights — the goggles frame,
  //                              the mechanical texture of 2555 tech.
  //
  //   EMBER RED        #C42B0A  — Deep fire-red behind the Visitor's
  //                              silhouette, the Brigade's danger alerts.
  //
  //   ASH BONE         #E8DED0  — text.primary. The rubble dust, bone-
  //                              white surfaces in the wasteland, the
  //                              warmth of candlelit survival shelters.
  //
  //   FENNEC TIP       #F5A623  — warning. The lighter amber of Fennec's
  //                              ear tips and paw pads — warm, small,
  //                              hopeful signal in a dark world.
  //
  //   IRRAD. GREEN     #5CB85C  — info. The faint green contamination
  //                              glow in the background of wasteland shots.
  //
  //   BRIGADE GHOST    #8FA8C0  — text.secondary. The cold grey-blue of
  //                              ash and smoke, Brigade comm-link static.
  //
  // BACKGROUND: Near-black burnt char with a warm amber radial at top-right
  //             (fire horizon), a cool blue at top-left (Brigade approach),
  //             and heavy noise texture for post-apocalyptic grit.
  //
  // TYPOGRAPHY: Mix of sans (body — survivors communicate fast and dirty)
  //             and mono (headings — tactical Brigade terminals).
  //             Stencilled letter-spacing. Weight 900 everywhere it matters.
  //
  // FENNEC DETAIL: The switch thumb, slider thumb, and active chip use the
  //                amber Fennec-fur colour with a warm glow — a tiny nod to
  //                the small fox who survived the end of the world.
  //
  future: createTheme({
    ...base,
    shape: { borderRadius: 6 }, // slightly rounded — survival tech, not precise Brigade
    typography: {
      fontFamily: sansStack,
      fontSize: 13,
      // Headings: stencil mono — Brigade tactical documents
      h1: { fontFamily: monoStack, fontWeight: 900, letterSpacing: -0.4, fontSize: 28 },
      h2: { fontFamily: monoStack, fontWeight: 900, letterSpacing: -0.3, fontSize: 22 },
      h3: { fontFamily: monoStack, fontWeight: 850, letterSpacing: -0.2, fontSize: 18 },
      h4: { fontFamily: monoStack, fontWeight: 800, fontSize: 16 },
      h5: { fontFamily: monoStack, fontWeight: 750, fontSize: 14 },
      // Body: sans — human survivors don't write in monospace
      body1: { fontFamily: sansStack, fontSize: 13, lineHeight: 1.6 },
      body2: { fontFamily: sansStack, fontSize: 12.5, lineHeight: 1.55 },
      caption: { fontFamily: sansStack, fontSize: 12, lineHeight: 1.35 },
      button: {
        fontFamily: monoStack,
        textTransform: "uppercase",
        letterSpacing: 1.1,
        fontWeight: 900,
        fontSize: 12,
      },
    },
    palette: {
      mode: "dark",
      background: {
        default: "#0D0905", // burnt char — the floor of 2555 Paris
        paper:   "#160E08", // scorched timber — walls still standing
      },
      primary:   { main: "#E8720C" }, // scorched amber — fire, Visitor's coat, Fennec's fur
      secondary: { main: "#4A90D9" }, // Brigade steel blue — their armour, portal flash
      info:      { main: "#5CB85C" }, // irradiated green — contamination glow
      success:   { main: "#5CB85C" }, // same: green = mission survived
      warning:   { main: "#F5A623" }, // Fennec amber — ear tips, paw pads, small hope
      error:     { main: "#C42B0A" }, // ember red — Brigade alert, deep fire
      text: {
        primary:   "#E8DED0",          // ash bone — warm rubble dust
        secondary: alpha("#8FA8C0", 0.9), // Brigade ghost — cold grey-blue smoke
      },
    },
    components: {
      ...base.components,

      // ── Body background ─────────────────────────────────────────────
      MuiCssBaseline: {
        styleOverrides: {
          ":root": {
            "--future-amber":  "#E8720C",
            "--future-blue":   "#4A90D9",
            "--future-copper": "#C87941",
            "--future-red":    "#C42B0A",
            "--future-fennec": "#F5A623",
          },
          body: {
            backgroundColor: "#0D0905",
            backgroundImage: `
              radial-gradient(ellipse 1100px 700px at 80% -5%, ${alpha("#E8720C", 0.22)}, transparent 55%),
              radial-gradient(ellipse 900px 600px at 5% 10%, ${alpha("#4A90D9", 0.16)}, transparent 50%),
              radial-gradient(ellipse 600px 400px at 50% 100%, ${alpha("#C42B0A", 0.1)}, transparent 50%),
              ${noiseSVG(0.12)}
            `,
          },

          // Visitor's temporal arrival — used for page transitions if desired
          "@keyframes temporalArrive": {
            "0%":   { opacity: 0, transform: "scale(0.97) translateY(6px)", filter: `blur(3px) sepia(0.5)` },
            "60%":  { opacity: 1, filter: "blur(0) sepia(0)" },
            "100%": { opacity: 1, transform: "scale(1) translateY(0)", filter: "none" },
          },

          // Fennec pulse — gentle amber heartbeat for primary interactive elements
          "@keyframes fennecPulse": {
            "0%, 100%": { boxShadow: `0 0 8px ${alpha("#E8720C", 0.2)}` },
            "50%":      { boxShadow: `0 0 20px ${alpha("#E8720C", 0.5)}, 0 0 40px ${alpha("#F5A623", 0.15)}` },
          },

          // Brigade sweep — cold blue scan used for Brigade-colored elements
          "@keyframes brigadeSweep": {
            "0%, 100%": { boxShadow: `0 0 6px ${alpha("#4A90D9", 0.15)}` },
            "50%":      { boxShadow: `0 0 18px ${alpha("#4A90D9", 0.4)}` },
          },
        },
      },

      // ── Paper — scorched timber surfaces ────────────────────────────
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            borderRadius: 10,
            backgroundColor: "#160E08",
            border: `1px solid ${alpha("#E8720C", 0.18)}`,
            // Warm amber inner glow at the top — like light from a fire below
            boxShadow: `inset 0 1px 0 ${alpha("#E8720C", 0.1)}`,
          },
        },
      },

      // ── Cards — survival shelter panels ─────────────────────────────
      MuiCard: {
        styleOverrides: {
          root: {
            borderRadius: 12,
            backgroundColor: "#160E08",
            border: `1px solid ${alpha("#E8720C", 0.2)}`,
            boxShadow: `
              0 4px 24px ${alpha("#0D0905", 0.7)},
              inset 0 1px 0 ${alpha("#E8720C", 0.12)},
              inset 0 -1px 0 ${alpha("#4A90D9", 0.06)}
            `,
            position: "relative",
            overflow: "hidden",
            // Warm gradient top — firelight from above
            "&::after": {
              content: '""',
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              height: 2,
              background: `linear-gradient(90deg, ${alpha("#E8720C", 0.6)}, ${alpha("#F5A623", 0.3)}, ${alpha("#4A90D9", 0.2)})`,
              pointerEvents: "none",
            },
          },
        },
      },

      // ── Dividers — ash line between worlds ──────────────────────────
      MuiDivider: {
        styleOverrides: {
          root: {
            borderColor: alpha("#E8720C", 0.18),
            // Subtle gradient: amber to blue — the split between
            // the Visitor's world and the Brigade's
            backgroundImage: `linear-gradient(90deg, ${alpha("#E8720C", 0.25)}, ${alpha("#4A90D9", 0.15)})`,
            height: 1,
            border: "none",
          },
        },
      },

      // ── Buttons ──────────────────────────────────────────────────────
      MuiButton: {
        defaultProps: { disableElevation: true },
        styleOverrides: {
          root: {
            borderRadius: 6,
            height: 34,
            paddingInline: 14,
            fontFamily: monoStack,
            letterSpacing: "0.08em",
            transition: "all 150ms ease",
          },
          // Primary: activate the bracelet — amber fire
          containedPrimary: {
            backgroundColor: "#E8720C",
            color: "#0D0905",
            border: `1px solid ${alpha("#F5A623", 0.4)}`,
            boxShadow: `0 4px 16px ${alpha("#E8720C", 0.4)}`,
            backgroundImage: `linear-gradient(180deg, ${alpha("#F08030", 1)}, ${alpha("#D4600A", 1)})`,
            animation: "fennecPulse 3s ease-in-out infinite",
            "&:hover": {
              backgroundImage: `linear-gradient(180deg, ${alpha("#F59030", 1)}, ${alpha("#E8720C", 1)})`,
              boxShadow: `0 6px 24px ${alpha("#E8720C", 0.55)}`,
              transform: "translateY(-1px)",
            },
            "&:active": { transform: "translateY(0)" },
          },
          // Outlined: Brigade steel blue — official channel
          outlined: {
            border: `1px solid ${alpha("#4A90D9", 0.45)}`,
            backgroundColor: alpha("#4A90D9", 0.06),
            color: "#8FC4E8",
            "&:hover": {
              backgroundColor: alpha("#4A90D9", 0.12),
              borderColor: alpha("#4A90D9", 0.7),
              boxShadow: `0 0 14px ${alpha("#4A90D9", 0.22)}`,
              animation: "brigadeSweep 2s ease-in-out infinite",
            },
          },
          // Text: survivor-scrawled, no frame
          text: {
            color: alpha("#E8DED0", 0.75),
            "&:hover": { backgroundColor: alpha("#E8720C", 0.07), color: "#E8DED0" },
          },
          sizeSmall: { height: 28, paddingInline: 10, fontSize: 11 },
          sizeLarge: { height: 42, paddingInline: 18 },
        },
      },

      MuiIconButton: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            border: `1px solid ${alpha("#E8720C", 0.22)}`,
            backgroundColor: alpha("#E8720C", 0.04),
            color: alpha("#E8DED0", 0.8),
            transition: "all 150ms ease",
            "&:hover": {
              backgroundColor: alpha("#E8720C", 0.1),
              borderColor: alpha("#E8720C", 0.45),
              color: "#E8DED0",
            },
          },
        },
      },

      // ── Input fields — survivor terminal entry ───────────────────────
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            backgroundColor: alpha("#0D0905", 0.55),
            fontFamily: sansStack,
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#E8720C", 0.5),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#E8720C",
              boxShadow: `0 0 0 3px ${alpha("#E8720C", 0.14)}`,
            },
          },
          notchedOutline: { borderColor: alpha("#E8720C", 0.25) },
        },
      },

      // ── Chips — hazard tags and ID badges ────────────────────────────
      MuiChip: {
        defaultProps: { size: "small" },
        styleOverrides: {
          root: {
            borderRadius: 6,
            fontFamily: monoStack,
            fontWeight: 800,
            fontSize: 11,
            height: 24,
            letterSpacing: "0.06em",
            backgroundColor: alpha("#E8720C", 0.1),
            border: `1px solid ${alpha("#E8720C", 0.28)}`,
            color: alpha("#E8DED0", 0.9),
            transition: "all 150ms ease",
            "&:hover": { backgroundColor: alpha("#E8720C", 0.18) },
          },
          // Filled chip: Fennec amber — hopeful, warm
          filled: {
            backgroundColor: "#E8720C",
            color: "#0D0905",
            border: "none",
          },
        },
      },

      // ── Tooltips — scrawled wasteland notes ──────────────────────────
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontFamily: monoStack,
            fontSize: 11.5,
            padding: "7px 11px",
            borderRadius: 6,
            backgroundColor: alpha("#160E08", 0.97),
            border: `1px solid ${alpha("#E8720C", 0.35)}`,
            color: "#E8DED0",
            letterSpacing: "0.04em",
            boxShadow: `0 4px 16px ${alpha("#0D0905", 0.6)}`,
          },
          arrow: { color: alpha("#160E08", 0.97) },
        },
      },

      // ── Alerts — Brigade communiqué style ────────────────────────────
      MuiAlert: {
        defaultProps: { variant: "outlined" },
        styleOverrides: {
          root: {
            borderRadius: 8,
            fontFamily: sansStack,
            fontSize: 12.5,
            backgroundColor: alpha("#0D0905", 0.65),
          },
          outlinedError: {
            borderColor: alpha("#C42B0A", 0.6),
            backgroundColor: alpha("#C42B0A", 0.07),
            color: "#FF8070",
          },
          outlinedWarning: {
            borderColor: alpha("#F5A623", 0.5),
            backgroundColor: alpha("#F5A623", 0.06),
            color: "#F5A623",
          },
          outlinedInfo: {
            borderColor: alpha("#5CB85C", 0.4),
            backgroundColor: alpha("#5CB85C", 0.06),
            color: "#80D880",
          },
          outlinedSuccess: {
            borderColor: alpha("#5CB85C", 0.4),
            backgroundColor: alpha("#5CB85C", 0.06),
            color: "#80D880",
          },
        },
      },

      // ── Tables — survivor registry / Brigade dossier ─────────────────
      MuiTableCell: {
        styleOverrides: {
          root: {
            paddingTop: 8,
            paddingBottom: 8,
            borderBottomColor: alpha("#E8720C", 0.12),
          },
          head: {
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 900,
            textTransform: "uppercase",
            letterSpacing: 0.9,
            color: alpha("#E8720C", 0.85),
            backgroundColor: alpha("#E8720C", 0.05),
            borderBottom: `1px solid ${alpha("#E8720C", 0.2)}`,
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: {
            transition: "background 120ms ease",
            "&:hover": { backgroundColor: alpha("#E8720C", 0.04) },
          },
        },
      },

      // ── Slider — bracelet temporal coordinate dial ───────────────────
      MuiSlider: {
        styleOverrides: {
          root: { color: "#E8720C" },
          rail: { backgroundColor: alpha("#E8720C", 0.18) },
          track: {
            backgroundImage: `linear-gradient(90deg, #E8720C, #F5A623)`,
            border: "none",
          },
          // Fennec paw — the warm amber thumb
          thumb: {
            backgroundColor: "#F5A623",
            border: `2px solid ${alpha("#E8720C", 0.6)}`,
            boxShadow: `0 0 0 3px ${alpha("#F5A623", 0.15)}, 0 0 10px ${alpha("#F5A623", 0.4)}`,
            "&:hover, &.Mui-active": {
              boxShadow: `0 0 0 5px ${alpha("#F5A623", 0.22)}, 0 0 16px ${alpha("#F5A623", 0.55)}`,
            },
          },
        },
      },

      // ── Switch — Fennec ear toggle ────────────────────────────────────
      // The switch thumb uses Fennec amber when active — the little fox
      // twitching an ear to listen for the Brigade
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            color: alpha("#E8DED0", 0.4),
            "&.Mui-checked": {
              color: "#F5A623",
              "& + .MuiSwitch-track": {
                backgroundColor: alpha("#E8720C", 0.45),
                opacity: 1,
              },
            },
          },
          thumb: {
            boxShadow: "none",
          },
          track: {
            backgroundColor: alpha("#E8DED0", 0.15),
            opacity: 1,
          },
        },
      },

      // ── Select ────────────────────────────────────────────────────────
      MuiSelect: {
        defaultProps: { size: "small" },
        styleOverrides: {
          icon: { color: alpha("#E8720C", 0.65) },
        },
      },

      // ── Linear progress — bracelet charge indicator ───────────────────
      MuiLinearProgress: {
        styleOverrides: {
          root: { backgroundColor: alpha("#E8720C", 0.15), borderRadius: 999 },
          bar: {
            backgroundImage: `linear-gradient(90deg, #E8720C, #F5A623)`,
            borderRadius: 999,
          },
        },
      },
    },
  }),
};