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
  | "future"
  | "renee";

export function getSeasonalThemeName(date = new Date()): ThemeName {
  const m = date.getMonth();
  if (m === 11 || m <= 1) return "winter";
  if (m >= 2 && m <= 4)  return "spring";
  if (m >= 5 && m <= 7)  return "summer";
  if (m >= 8 && m <= 10) return "autumn";
  return "light";
}

// ---------------------------------------------------------------------------
// Themes
// ---------------------------------------------------------------------------

export const themes: Record<ThemeName, ReturnType<typeof createTheme>> = {

  // ── 1. MIDNIGHT — dark ───────────────────────────────────────────────
  // Near-black background with blue corner glows and blurred glass surfaces.
  midnight: mkDark({
    bg: "#03050D",
    paper: "#070C1A",
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
              radial-gradient(ellipse 1400px 700px at 20% -5%, rgba(77,143,255,.2), transparent 60%),
              radial-gradient(ellipse 900px 500px at 92% 12%, rgba(123,179,255,.13), transparent 55%),
              radial-gradient(ellipse 500px 350px at 50% 95%, rgba(60,90,200,.09), transparent 50%),
              radial-gradient(ellipse 350px 250px at 3% 65%, rgba(90,130,220,.06), transparent 50%),
              ${noiseSVG(0.042)}
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#4D8FFF", 0.38)} transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 4,
              backgroundColor: alpha("#4D8FFF", 0.3),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: alpha("#4D8FFF", 0.5) },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#4D8FFF", 0.42), color: "#E6ECF8" },
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "linear-gradient(145deg, rgba(77,143,255,.06) 0%, rgba(255,255,255,.018) 60%, transparent 100%)",
            backdropFilter: "blur(18px)",
            border: `1px solid ${alpha("#4D8FFF", 0.16)}`,
            boxShadow: `0 4px 32px rgba(3,5,13,.65), inset 0 1px 0 ${alpha("#7BB3FF", 0.09)}`,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: "linear-gradient(145deg, rgba(77,143,255,.07) 0%, rgba(255,255,255,.02) 55%, transparent 100%)",
            backdropFilter: "blur(14px)",
            border: `1px solid ${alpha("#4D8FFF", 0.2)}`,
            boxShadow: `0 8px 40px rgba(3,5,13,.6), inset 0 1px 0 ${alpha("#7BB3FF", 0.12)}`,
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          outlined: {
            border: `1px solid ${alpha("#4D8FFF", 0.38)}`,
            backgroundColor: alpha("#4D8FFF", 0.06),
            color: "#7BB3FF",
            "&:hover": {
              backgroundColor: alpha("#4D8FFF", 0.12),
              borderColor: alpha("#4D8FFF", 0.62),
              boxShadow: `0 0 16px ${alpha("#4D8FFF", 0.22)}`,
            },
          },
          text: {
            color: alpha("#7BB3FF", 0.88),
            "&:hover": {
              backgroundColor: alpha("#4D8FFF", 0.08),
              color: "#7BB3FF",
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundImage: `linear-gradient(180deg, ${alpha("#5A9BFF", 1)}, ${alpha("#3A7AE8", 0.94)})`,
              boxShadow: `0 4px 20px ${alpha("#4D8FFF", 0.38)}, inset 0 1px 0 ${alpha("#8FC4FF", 0.22)}`,
              "&:hover": {
                backgroundImage: `linear-gradient(180deg, #6AABFF, #4A8AF8)`,
                boxShadow: `0 6px 28px ${alpha("#4D8FFF", 0.55)}`,
                transform: "translateY(-1px)",
              },
              "&:active": {
                transform: "translateY(0)",
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#4D8FFF", 0.45),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#4D8FFF",
              boxShadow: `0 0 0 3px ${alpha("#4D8FFF", 0.15)}`,
            },
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            backgroundColor: alpha("#4D8FFF", 0.1),
            border: `1px solid ${alpha("#4D8FFF", 0.24)}`,
            color: alpha("#E6ECF8", 0.92),
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 750,
            textTransform: "uppercase",
            letterSpacing: 0.7,
            color: alpha("#7BB3FF", 0.82),
            backgroundColor: alpha("#4D8FFF", 0.06),
            borderBottom: `1px solid ${alpha("#4D8FFF", 0.16)}`,
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: { "&:hover": { backgroundColor: alpha("#4D8FFF", 0.05) } },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: alpha("#4D8FFF", 0.13) },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 999, backgroundColor: alpha("#4D8FFF", 0.16), height: 5 },
          bar: {
            borderRadius: 999,
            backgroundImage: `linear-gradient(90deg, #4D8FFF, #7BB3FF)`,
            boxShadow: `0 0 8px ${alpha("#4D8FFF", 0.5)}`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#7BB3FF",
              "& + .MuiSwitch-track": { backgroundColor: alpha("#4D8FFF", 0.52), opacity: 1 },
            },
          },
          track: { backgroundColor: alpha("#E6ECF8", 0.18), opacity: 1 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            backgroundColor: "#4D8FFF",
            boxShadow: `0 0 10px ${alpha("#4D8FFF", 0.7)}`,
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            backgroundColor: alpha("#070C1A", 0.97),
            border: `1px solid ${alpha("#4D8FFF", 0.28)}`,
            boxShadow: `0 4px 20px rgba(3,5,13,.7)`,
          },
        },
      },
    },
  }),

  // ── 2. GRAPHITE — dark ───────────────────────────────────────────────
  // Flat matte charcoal surfaces, steel-blue accent, left-stripe cards.
  graphite: mkDark({
    bg: "#0A0C10",
    paper: "#0F1318",
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
              radial-gradient(ellipse 1200px 500px at 30% -10%, rgba(79,179,255,.08), transparent 55%),
              radial-gradient(ellipse 600px 400px at 85% 80%, rgba(60,100,160,.05), transparent 50%),
              ${noiseSVG(0.07)}
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#7A9EB8", 0.35)} transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 3,
              backgroundColor: alpha("#7A9EB8", 0.28),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: alpha("#7A9EB8", 0.45) },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#4FB3FF", 0.35), color: "#E8EDF4" },
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            backgroundColor: "#0F1318",
            border: "1px solid rgba(229,231,235,.09)",
            boxShadow: "none",
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            backgroundColor: "#0F1318",
            border: "1px solid rgba(229,231,235,.09)",
            // Left accent stripe — field report classification bar
            borderLeft: `3px solid ${alpha("#4FB3FF", 0.38)}`,
            boxShadow: `0 2px 12px rgba(10,12,16,.55)`,
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          outlined: {
            border: `1px solid ${alpha("#4FB3FF", 0.34)}`,
            color: alpha("#4FB3FF", 0.88),
            "&:hover": {
              backgroundColor: alpha("#4FB3FF", 0.08),
              borderColor: alpha("#4FB3FF", 0.58),
            },
          },
          text: {
            color: alpha("#7A9EB8", 0.9),
            "&:hover": {
              backgroundColor: alpha("#4FB3FF", 0.07),
              color: "#4FB3FF",
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundColor: "#4FB3FF",
              backgroundImage: "none",
              color: "#06090E",
              boxShadow: "none",
              "&:hover": {
                backgroundColor: "#65BBFF",
                boxShadow: `0 2px 10px ${alpha("#4FB3FF", 0.28)}`,
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#4FB3FF", 0.4),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#4FB3FF",
              boxShadow: `0 0 0 2px ${alpha("#4FB3FF", 0.12)}`,
            },
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            backgroundColor: alpha("#7A9EB8", 0.1),
            border: `1px solid ${alpha("#7A9EB8", 0.22)}`,
            color: alpha("#E8EDF4", 0.85),
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 750,
            textTransform: "uppercase",
            letterSpacing: 0.85,
            color: alpha("#7A9EB8", 0.8),
            backgroundColor: alpha("#ffffff", 0.028),
            borderBottom: "1px solid rgba(229,231,235,.1)",
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: { "&:hover": { backgroundColor: alpha("#4FB3FF", 0.04) } },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: "rgba(229,231,235,.08)" },
        },
      },
      // Matte progress — sharp ends, no glow (military precision)
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 2, backgroundColor: alpha("#4FB3FF", 0.14), height: 4 },
          bar: { borderRadius: 2, backgroundColor: "#4FB3FF" },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#4FB3FF",
              "& + .MuiSwitch-track": { backgroundColor: alpha("#4FB3FF", 0.45), opacity: 1 },
            },
          },
          track: { backgroundColor: alpha("#E8EDF4", 0.16), opacity: 1 },
        },
      },
      // Sharp indicator — no soft rounding here
      MuiTabs: {
        styleOverrides: {
          indicator: { backgroundColor: "#4FB3FF", height: 2, borderRadius: 0 },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            backgroundColor: alpha("#0F1318", 0.98),
            border: "1px solid rgba(229,231,235,.12)",
            boxShadow: "0 4px 16px rgba(10,12,16,.7)",
          },
        },
      },
    },
  }),

  // ── 3. SLATE — dark ──────────────────────────────────────────────────
  // Blueprint look: graph-paper grid, monospace, registration-mark cards.
  slate: mkDark({
    bg: "#07101D",
    paper: "#0C1828",
    primary: "#5D9EFF",
    secondary: "#6EC2F5",
    info: "#38BDF8",
    success: "#34D399",
    warning: "#FBBF24",
    error: "#F87171",
    text: "#D8E8F8",
    typography: {
      h1: { fontFamily: monoStack, fontWeight: 850, letterSpacing: -0.7 },
      h2: { fontFamily: monoStack, fontWeight: 850 },
      h3: { fontFamily: monoStack, fontWeight: 800 },
      h4: { fontFamily: monoStack, fontWeight: 750 },
      button: { fontFamily: monoStack, letterSpacing: 0.5, fontWeight: 800 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#07101D",
            backgroundImage: `
              ${grid(0.019, 24)},
              ${grid(0.007, 6)},
              radial-gradient(ellipse 1000px 600px at 78% -12%, rgba(93,158,255,.17), transparent 60%),
              radial-gradient(ellipse 400px 300px at 8% 75%, rgba(60,140,220,.06), transparent 50%)
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#5D9EFF", 0.38)} transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 2,
              backgroundColor: alpha("#5D9EFF", 0.3),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: alpha("#5D9EFF", 0.5) },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#5D9EFF", 0.4), color: "#D8E8F8" },
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: `linear-gradient(180deg, ${alpha("#5D9EFF", 0.04)}, transparent 40%)`,
            backgroundColor: "#0C1828",
            border: `1px solid ${alpha("#5D9EFF", 0.16)}`,
            boxShadow: `0 2px 16px rgba(7,16,29,.55)`,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundColor: "#0A1522",
            border: `1px solid ${alpha("#5D9EFF", 0.18)}`,
            // Top accent bar — blueprint title block underline
            boxShadow: `
              0 2px 20px rgba(7,16,29,.55),
              inset 0 2px 0 ${alpha("#5D9EFF", 0.22)}
            `,
            // Corner registration marks via outline trick
            outline: `1px solid ${alpha("#5D9EFF", 0.07)}`,
            outlineOffset: 3,
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          outlined: {
            border: `1px solid ${alpha("#5D9EFF", 0.4)}`,
            color: "#6EC2F5",
            fontFamily: monoStack,
            letterSpacing: "0.04em",
            "&:hover": {
              backgroundColor: alpha("#5D9EFF", 0.09),
              borderColor: alpha("#5D9EFF", 0.65),
            },
          },
          text: {
            color: alpha("#6EC2F5", 0.88),
            fontFamily: monoStack,
            letterSpacing: "0.04em",
            "&:hover": {
              backgroundColor: alpha("#5D9EFF", 0.08),
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundColor: "#5D9EFF",
              backgroundImage: "none",
              color: "#04090F",
              fontFamily: monoStack,
              letterSpacing: "0.05em",
              boxShadow: `0 0 0 1px ${alpha("#5D9EFF", 0.4)}`,
              "&:hover": {
                backgroundColor: "#6EAAFF",
                boxShadow: `0 4px 16px ${alpha("#5D9EFF", 0.35)}, 0 0 0 1px ${alpha("#5D9EFF", 0.5)}`,
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            fontFamily: monoStack,
            fontSize: 12.5,
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#5D9EFF", 0.45),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#5D9EFF",
              boxShadow: `0 0 0 2px ${alpha("#5D9EFF", 0.13)}`,
            },
          },
          notchedOutline: { borderColor: alpha("#5D9EFF", 0.2) },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 4,
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: "0.05em",
            backgroundColor: alpha("#5D9EFF", 0.1),
            border: `1px solid ${alpha("#5D9EFF", 0.25)}`,
            color: "#6EC2F5",
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 800,
            textTransform: "uppercase",
            letterSpacing: 0.9,
            color: alpha("#6EC2F5", 0.78),
            backgroundColor: alpha("#5D9EFF", 0.05),
            borderBottom: `1px solid ${alpha("#5D9EFF", 0.18)}`,
          },
          root: { fontFamily: monoStack, fontSize: 12.5 },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: { "&:hover": { backgroundColor: alpha("#5D9EFF", 0.05) } },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: alpha("#5D9EFF", 0.14) },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 0, backgroundColor: alpha("#5D9EFF", 0.14), height: 3 },
          bar: { borderRadius: 0, backgroundColor: "#5D9EFF" },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#5D9EFF",
              "& + .MuiSwitch-track": { backgroundColor: alpha("#5D9EFF", 0.48), opacity: 1 },
            },
          },
          track: { backgroundColor: alpha("#D8E8F8", 0.18), opacity: 1 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: { backgroundColor: "#5D9EFF", height: 2, borderRadius: 0 },
          root: {
            borderBottom: `1px solid ${alpha("#5D9EFF", 0.16)}`,
          },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            fontFamily: monoStack,
            letterSpacing: "0.04em",
            fontSize: 12,
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontFamily: monoStack,
            fontSize: 11.5,
            backgroundColor: alpha("#0A1522", 0.98),
            border: `1px solid ${alpha("#5D9EFF", 0.3)}`,
            boxShadow: `0 4px 18px rgba(7,16,29,.7)`,
          },
        },
      },
    },
  }),

  // ── 4. LIGHT — light ─────────────────────────────────────────────────
  // White surfaces, three-level shadow depth, blue accent, no textures.
  light: mkLight({
    bg: "#F3F4F6",
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
            backgroundColor: "#F3F4F6",
            backgroundImage: `
              radial-gradient(ellipse 1200px 600px at 15% -5%, rgba(27,95,255,.07), transparent 55%),
              radial-gradient(ellipse 800px 400px at 90% 10%, rgba(13,118,107,.05), transparent 50%)
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `rgba(11,18,32,.22) transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 4,
              backgroundColor: "rgba(11,18,32,.18)",
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: "rgba(11,18,32,.3)" },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#1B5FFF", 0.18), color: "#0B1220" },
          },
        },
      },
      // Level 1 — surfaces, sidebars, panels
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            boxShadow: "0 1px 3px rgba(11,18,32,.06), 0 0 0 1px rgba(11,18,32,.055)",
            border: "none",
          },
        },
      },
      // Level 2 — content cards, clearly elevated
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            boxShadow: "0 2px 8px rgba(11,18,32,.09), 0 0 0 1px rgba(11,18,32,.06)",
            border: "none",
            transition: "box-shadow 150ms ease, transform 150ms ease",
            "&:hover": {
              boxShadow: "0 4px 16px rgba(11,18,32,.12), 0 0 0 1px rgba(11,18,32,.07)",
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          outlined: {
            border: `1px solid ${alpha("#1B5FFF", 0.35)}`,
            color: "#1B5FFF",
            backgroundColor: alpha("#1B5FFF", 0.04),
            "&:hover": {
              backgroundColor: alpha("#1B5FFF", 0.08),
              borderColor: alpha("#1B5FFF", 0.6),
              boxShadow: `0 2px 8px ${alpha("#1B5FFF", 0.14)}`,
            },
          },
          text: {
            color: "#1B5FFF",
            "&:hover": {
              backgroundColor: alpha("#1B5FFF", 0.07),
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundImage: `linear-gradient(180deg, #2868FF, #1450E8)`,
              boxShadow: `0 2px 8px ${alpha("#1B5FFF", 0.32)}, inset 0 1px 0 rgba(255,255,255,.15)`,
              "&:hover": {
                backgroundImage: `linear-gradient(180deg, #3A78FF, #1B5FFF)`,
                boxShadow: `0 4px 14px ${alpha("#1B5FFF", 0.42)}`,
                transform: "translateY(-1px)",
              },
              "&:active": {
                transform: "translateY(0)",
                boxShadow: `0 1px 4px ${alpha("#1B5FFF", 0.3)}`,
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            backgroundColor: "#FFFFFF",
            boxShadow: "0 1px 2px rgba(11,18,32,.04)",
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#1B5FFF", 0.45),
            },
            "&.Mui-focused": {
              boxShadow: `0 0 0 3px ${alpha("#1B5FFF", 0.12)}`,
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#1B5FFF",
            },
          },
          notchedOutline: { borderColor: "rgba(11,18,32,.18)" },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            backgroundColor: alpha("#1B5FFF", 0.08),
            border: `1px solid ${alpha("#1B5FFF", 0.2)}`,
            color: "#1449CC",
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontSize: 11.5,
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: 0.5,
            color: alpha("#0B1220", 0.5),
            backgroundColor: "rgba(11,18,32,.025)",
            borderBottom: "1px solid rgba(11,18,32,.1)",
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: {
            "&:hover": { backgroundColor: alpha("#1B5FFF", 0.03) },
          },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: "rgba(11,18,32,.1)" },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 999, backgroundColor: alpha("#1B5FFF", 0.12), height: 5 },
          bar: {
            borderRadius: 999,
            backgroundImage: `linear-gradient(90deg, #1B5FFF, #5584FF)`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#1B5FFF",
              "& + .MuiSwitch-track": { backgroundColor: alpha("#1B5FFF", 0.5), opacity: 1 },
            },
          },
          track: { backgroundColor: "rgba(11,18,32,.22)", opacity: 1 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: { backgroundColor: "#1B5FFF", borderRadius: 2, height: 2 },
        },
      },
      // Level 3 — floating (menu, tooltip)
      MuiMenu: {
        styleOverrides: {
          paper: {
            boxShadow: "0 8px 24px rgba(11,18,32,.14), 0 0 0 1px rgba(11,18,32,.07)",
            border: "none",
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            backgroundColor: "#0B1220",
            color: "#F3F4F6",
            boxShadow: "0 4px 16px rgba(11,18,32,.2)",
            border: "none",
          },
          arrow: { color: "#0B1220" },
        },
      },
    },
  }),

  // ── 5. PAPER — light ─────────────────────────────────────────────────
  // Warm paper surfaces with grain/noise, stacked-paper shadows, serif type.
  paper: mkLight({
    bg: "#EDE8DF",
    paper: "#FAF7F2",
    primary: "#0F4CFF",
    secondary: "#34495E",
    info: "#1D4ED8",
    success: "#056139",
    warning: "#7A4100",
    error: "#B42318",
    text: "#1A1209",
    typography: {
      fontFamily: serifStack,
      fontSize: 13.5,
      h1: { fontFamily: serifStack, fontWeight: 800, letterSpacing: -0.5, lineHeight: 1.2 },
      h2: { fontFamily: serifStack, fontWeight: 800, letterSpacing: -0.3 },
      h3: { fontFamily: serifStack, fontWeight: 750, letterSpacing: -0.1 },
      h4: { fontFamily: serifStack, fontWeight: 700 },
      h5: { fontFamily: serifStack, fontWeight: 700 },
      body1: { fontFamily: serifStack, fontSize: 13.5, lineHeight: 1.68 },
      body2: { fontFamily: serifStack, fontSize: 13, lineHeight: 1.62 },
      caption: { fontFamily: serifStack, fontSize: 12, fontStyle: "italic", lineHeight: 1.4 },
      button: { fontFamily: serifStack, fontWeight: 800, letterSpacing: 0.2 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#EDE8DF",
            // Paper grain + edge vignette — like aged document paper
            backgroundImage: `
              ${noiseSVG(0.16)},
              radial-gradient(ellipse 120% 80% at 50% 50%, transparent 58%, rgba(120,85,40,.07) 100%)
            `,
            backgroundBlendMode: "multiply, normal",
            scrollbarWidth: "thin",
            scrollbarColor: `rgba(120,85,40,.3) transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 3,
              backgroundColor: "rgba(120,85,40,.24)",
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: "rgba(120,85,40,.4)" },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#0F4CFF", 0.18), color: "#1A1209" },
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: noiseSVG(0.09),
            backgroundBlendMode: "multiply",
            backgroundColor: "#FAF7F2",
            border: "1px solid rgba(26,18,9,.1)",
            boxShadow: "0 1px 3px rgba(26,18,9,.07), 0 0 0 1px rgba(26,18,9,.05)",
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            // White card on cream desk — grain + stacked paper shadow
            backgroundImage: `linear-gradient(180deg, rgba(255,255,255,.65), rgba(255,255,255,.9)), ${noiseSVG(0.1)}`,
            backgroundBlendMode: "normal, multiply",
            backgroundColor: "#FAF7F2",
            border: "1px solid rgba(26,18,9,.1)",
            boxShadow: `
              0 1px 1px rgba(26,18,9,.05),
              0 2px 4px rgba(26,18,9,.05),
              0 4px 10px rgba(26,18,9,.04)
            `,
            transition: "box-shadow 220ms ease",
            "&:hover": {
              boxShadow: `
                0 2px 4px rgba(26,18,9,.07),
                0 4px 10px rgba(26,18,9,.07),
                0 8px 20px rgba(26,18,9,.05)
              `,
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          outlined: {
            border: "1px solid rgba(26,18,9,.24)",
            color: "#1A1209",
            fontFamily: serifStack,
            backgroundColor: alpha("#FAF7F2", 0.5),
            "&:hover": {
              backgroundColor: "rgba(26,18,9,.04)",
              borderColor: "rgba(26,18,9,.4)",
            },
          },
          text: {
            color: "#0F4CFF",
            fontFamily: serifStack,
            "&:hover": { backgroundColor: alpha("#0F4CFF", 0.07) },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundImage: "none",
              backgroundColor: "#0F4CFF",
              fontFamily: serifStack,
              fontWeight: 800,
              boxShadow: `inset 0 1px 0 rgba(255,255,255,.12), 0 2px 6px ${alpha("#0F4CFF", 0.32)}`,
              "&:hover": {
                backgroundColor: "#1A58FF",
                boxShadow: `inset 0 1px 0 rgba(255,255,255,.12), 0 4px 12px ${alpha("#0F4CFF", 0.4)}`,
              },
              "&:active": {
                transform: "translateY(1px)",
                boxShadow: `inset 0 2px 4px rgba(0,0,0,.16)`,
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            fontFamily: serifStack,
            backgroundColor: "#FDFAF6",
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: "rgba(26,18,9,.35)",
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#0F4CFF",
              boxShadow: `0 0 0 2px ${alpha("#0F4CFF", 0.12)}`,
            },
          },
          notchedOutline: { borderColor: "rgba(26,18,9,.18)" },
        },
      },
      MuiInputLabel: {
        styleOverrides: {
          root: { fontFamily: serifStack, fontStyle: "italic", fontSize: 12.5 },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            fontFamily: serifStack,
            fontWeight: 700,
            borderRadius: 4,
            backgroundColor: "rgba(26,18,9,.06)",
            border: "1px solid rgba(26,18,9,.15)",
            color: "#1A1209",
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          // Italic serif ledger headers — not uppercase, not mono
          head: {
            fontFamily: serifStack,
            fontSize: 12.5,
            fontWeight: 800,
            fontStyle: "italic",
            color: alpha("#1A1209", 0.6),
            backgroundColor: "rgba(26,18,9,.025)",
            textTransform: "none",
            letterSpacing: 0,
            borderBottom: "2px solid rgba(26,18,9,.14)",
          },
          root: { fontFamily: serifStack, fontSize: 13, borderBottomColor: "rgba(26,18,9,.08)" },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: { "&:hover": { backgroundColor: alpha("#0F4CFF", 0.03) } },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: "rgba(26,18,9,.12)" },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 2, backgroundColor: "rgba(26,18,9,.1)", height: 5 },
          bar: { borderRadius: 2, backgroundColor: "#0F4CFF" },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#0F4CFF",
              "& + .MuiSwitch-track": { backgroundColor: alpha("#0F4CFF", 0.45), opacity: 1 },
            },
          },
          track: { backgroundColor: "rgba(26,18,9,.22)", opacity: 1 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: { backgroundColor: "#0F4CFF", height: 2, borderRadius: 1 },
          root: { borderBottom: "1px solid rgba(26,18,9,.12)" },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: { fontFamily: serifStack, fontWeight: 700, fontSize: 13 },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          // Marginalia note — dark ink, italic serif
          tooltip: {
            fontFamily: serifStack,
            fontSize: 12,
            fontStyle: "italic",
            backgroundColor: "#1A1209",
            color: "#EDE8DF",
            boxShadow: "0 4px 16px rgba(26,18,9,.3)",
          },
          arrow: { color: "#1A1209" },
        },
      },
      MuiAlert: {
        styleOverrides: {
          root: {
            fontFamily: serifStack,
            backgroundImage: noiseSVG(0.06),
            backgroundBlendMode: "multiply",
          },
        },
      },
    },
  }),

  // ── 17. RENÉE — light ────────────────────────────────────────────────
  // Cream background with walnut wood-grain and gold-leaf card edges.
  // Orchid primary: ink #9B2FA8 for text/buttons, bloom #C667D4 for fills/glow.
  // Gold and walnut accents; red reserved for errors.
  renee: mkLight({
    bg: "#F1E8DC",
    paper: "#FBF6EE",
    primary: "#9B2FA8",
    secondary: "#9A6B12",
    info: "#8A4FA0",
    success: "#4E7A3A",
    warning: "#B5730A",
    error: "#B23A2E",
    text: "#2A1B10",
    // Serif display headings only; body/button intentionally inherit sansStack
    // for legibility contrast (editorial atelier feel).
    typography: {
      h1: { fontFamily: serifStack, fontWeight: 800, letterSpacing: -0.5 },
      h2: { fontFamily: serifStack, fontWeight: 800, letterSpacing: -0.3 },
      h3: { fontFamily: serifStack, fontWeight: 750, letterSpacing: -0.1 },
      h4: { fontFamily: serifStack, fontWeight: 700 },
      h5: { fontFamily: serifStack, fontWeight: 700 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#F1E8DC",
            backgroundImage: `
              repeating-linear-gradient(94deg, rgba(107,74,50,.055) 0px, rgba(107,74,50,.02) 3px, transparent 6px, rgba(120,82,52,.045) 11px),
              repeating-linear-gradient(94deg, rgba(80,54,34,.03) 0px, transparent 2px, transparent 7px),
              radial-gradient(ellipse 1100px 600px at 12% -8%, rgba(198,103,212,.10), transparent 58%),
              radial-gradient(ellipse 800px 500px at 92% 4%, rgba(199,154,46,.10), transparent 55%),
              ${noiseSVG(0.05)}
            `,
            backgroundBlendMode: "normal, normal, normal, normal, multiply",
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#C667D4", 0.4)} transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 4,
              backgroundColor: alpha("#C667D4", 0.32),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: alpha("#9B2FA8", 0.45) },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#C667D4", 0.28), color: "#2A1B10" },
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            backgroundColor: "#FBF6EE",
            border: "none",
            boxShadow: `0 0 0 1px ${alpha("#C79A2E", 0.42)}, 0 1px 3px rgba(74,50,30,.08)`,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            backgroundColor: "#FBF6EE",
            border: "none",
            boxShadow: `0 0 0 1px ${alpha("#C79A2E", 0.55)}, 0 2px 10px rgba(74,50,30,.10)`,
            transition: "box-shadow 160ms ease, transform 160ms ease",
            "&:hover": {
              boxShadow: `0 0 0 1px ${alpha("#C79A2E", 0.7)}, 0 6px 18px rgba(74,50,30,.14)`,
              transform: "translateY(-1px)",
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          outlined: {
            border: `1px solid ${alpha("#9A6B12", 0.5)}`,
            color: "#7E2390",
            backgroundColor: alpha("#C667D4", 0.04),
            "&:hover": {
              backgroundColor: alpha("#9B2FA8", 0.08),
              borderColor: alpha("#9B2FA8", 0.55),
            },
          },
          text: {
            color: "#9B2FA8",
            "&:hover": { backgroundColor: alpha("#9B2FA8", 0.07) },
          },
        },
        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundImage: "linear-gradient(180deg, #9B2FA8, #7E2390)",
              color: "#FBF1F6",
              boxShadow: `inset 0 1px 0 ${alpha("#C79A2E", 0.3)}, 0 2px 8px ${alpha("#9B2FA8", 0.3)}`,
              "&:hover": {
                backgroundImage: "linear-gradient(180deg, #A93BB6, #8A2A9C)",
                boxShadow: `inset 0 1px 0 ${alpha("#C79A2E", 0.35)}, 0 4px 14px ${alpha("#9B2FA8", 0.42)}`,
                transform: "translateY(-1px)",
              },
              "&:active": { transform: "translateY(0)" },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            backgroundColor: "#FDFAF4",
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#9B2FA8", 0.45),
            },
            "&.Mui-focused": { boxShadow: `0 0 0 3px ${alpha("#9B2FA8", 0.12)}` },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": { borderColor: "#9B2FA8" },
          },
          notchedOutline: { borderColor: alpha("#6B4A32", 0.22) },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            backgroundColor: alpha("#C667D4", 0.14),
            border: `1px solid ${alpha("#C667D4", 0.4)}`,
            color: "#7E2390",
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontSize: 11.5,
            fontWeight: 750,
            textTransform: "uppercase",
            letterSpacing: 0.6,
            color: alpha("#9A6B12", 0.95),
            backgroundColor: alpha("#C79A2E", 0.08),
            borderBottom: `1px solid ${alpha("#6B4A32", 0.18)}`,
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: { "&:hover": { backgroundColor: alpha("#9B2FA8", 0.03) } },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: alpha("#6B4A32", 0.16) },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 999, backgroundColor: alpha("#C79A2E", 0.16), height: 5 },
          bar: {
            borderRadius: 999,
            backgroundImage: "linear-gradient(90deg, #9B2FA8, #C667D4)",
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#9B2FA8",
              "& + .MuiSwitch-track": { backgroundColor: alpha("#9B2FA8", 0.45), opacity: 1 },
            },
          },
          track: { backgroundColor: alpha("#6B4A32", 0.24), opacity: 1 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            backgroundColor: "#9B2FA8",
            height: 2,
            borderRadius: 1,
            boxShadow: `0 0 8px ${alpha("#C667D4", 0.5)}`,
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            backgroundColor: "#2A1B10",
            color: "#F1E8DC",
            boxShadow: "0 4px 16px rgba(42,27,16,.3)",
            border: "none",
          },
          arrow: { color: "#2A1B10" },
        },
      },
    },
  }),

  // ── 6. HIGH CONTRAST — dark, WCAG AAA ────────────────────────────────
  // Black/white + yellow (#FFD600) primary (14.7:1 on black), sharp corners,
  // 2px borders, strong focus rings.
  high_contrast: mkDark({
    bg: "#000000",
    paper: "#0A0A0A",
    primary: "#FFD600",
    secondary: "#FFFFFF",
    info: "#00E5FF",
    success: "#00FF88",
    warning: "#FFD600",
    error: "#FF3B30",
    text: "#FFFFFF",
    shape: { borderRadius: 0 },
    typography: {
      fontFamily: monoStack,
      h1: { fontFamily: monoStack, fontWeight: 900, letterSpacing: -0.5 },
      h2: { fontFamily: monoStack, fontWeight: 900, letterSpacing: -0.3 },
      h3: { fontFamily: monoStack, fontWeight: 900 },
      h4: { fontFamily: monoStack, fontWeight: 800 },
      h5: { fontFamily: monoStack, fontWeight: 800 },
      body1: { fontFamily: monoStack, fontSize: 13, lineHeight: 1.6 },
      body2: { fontFamily: monoStack, fontSize: 12.5, lineHeight: 1.55 },
      caption: { fontFamily: monoStack, fontSize: 12 },
      button: { fontFamily: monoStack, fontWeight: 900, letterSpacing: 1.4, textTransform: "uppercase" },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#000000",
            backgroundImage: "none",
          },
          // 3px yellow focus ring — unmissable for keyboard nav and low vision
          "*:focus-visible": {
            outline: "3px solid #FFD600 !important",
            outlineOffset: "2px !important",
          },
          "*, *::before, *::after": { outlineColor: "#FFD600 !important" },
          "::selection": { backgroundColor: "#FFD600", color: "#000000" },
          // Windows High Contrast Mode passthrough
          "@media (forced-colors: active)": {
            "*": { forcedColorAdjust: "auto" },
          },
          scrollbarWidth: "thin",
          scrollbarColor: `#FFD600 #000000`,
          "&::-webkit-scrollbar": { width: 10, height: 10 },
          "&::-webkit-scrollbar-thumb": {
            backgroundColor: "#FFD600",
            border: "2px solid #000000",
          },
          "&::-webkit-scrollbar-track": { backgroundColor: "#111111" },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            backgroundImage: "none",
            backgroundColor: "#0A0A0A",
            border: "2px solid rgba(255,255,255,.85)",
            boxShadow: "none",
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            backgroundImage: "none",
            backgroundColor: "#0A0A0A",
            border: "2px solid rgba(255,255,255,.85)",
            // Yellow top tab — filing label for the card
            borderTop: "3px solid #FFD600",
            boxShadow: "none",
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            border: "2px solid rgba(255,255,255,.85)",
            letterSpacing: "0.1em",
          },
          outlined: {
            border: "2px solid #FFD600",
            color: "#FFD600",
            backgroundColor: "transparent",
            "&:hover": {
              backgroundColor: alpha("#FFD600", 0.1),
              border: "2px solid #FFE033",
            },
          },
          text: {
            color: "#FFD600",
            textDecoration: "underline",
            textUnderlineOffset: 3,
            "&:hover": {
              backgroundColor: alpha("#FFD600", 0.1),
              textDecoration: "underline",
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundColor: "#FFD600",
              color: "#000000",
              border: "2px solid #FFD600",
              boxShadow: "none",
              "&:hover": {
                backgroundColor: "#FFE033",
                boxShadow: `0 0 0 2px #FFD600`,
              },
              "&:focus-visible": {
                outline: "3px solid #FFFFFF",
                outlineOffset: 2,
              },
            },
          },
        ],
      },
      MuiIconButton: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            border: "1px solid rgba(255,255,255,.4)",
            "&:hover": { border: "1px solid #FFD600", color: "#FFD600" },
          },
        },
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            "&:hover .MuiOutlinedInput-notchedOutline": { borderColor: "#FFD600", borderWidth: 2 },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#FFD600",
              borderWidth: 2,
              boxShadow: `0 0 0 3px ${alpha("#FFD600", 0.25)}`,
            },
          },
          notchedOutline: { borderColor: "rgba(255,255,255,.7)", borderWidth: 2, borderRadius: 0 },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            fontFamily: monoStack,
            fontWeight: 800,
            fontSize: 11,
            letterSpacing: "0.06em",
            backgroundColor: "transparent",
            border: "2px solid #FFD600",
            color: "#FFD600",
            height: 26,
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 900,
            textTransform: "uppercase",
            letterSpacing: 1.0,
            color: "#FFD600",
            backgroundColor: "#000000",
            borderBottom: "2px solid #FFD600",
          },
          root: {
            fontFamily: monoStack,
            borderBottomColor: "rgba(255,255,255,.25)",
            borderBottomWidth: 1,
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: {
            "&:hover": { backgroundColor: alpha("#FFD600", 0.06) },
          },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: "rgba(255,255,255,.4)", borderWidth: 1 },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 0, backgroundColor: "rgba(255,255,255,.15)", height: 6 },
          bar: { borderRadius: 0, backgroundColor: "#FFD600" },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#FFD600",
              "& + .MuiSwitch-track": { backgroundColor: alpha("#FFD600", 0.4), opacity: 1 },
            },
          },
          thumb: { boxShadow: "none" },
          track: { backgroundColor: "rgba(255,255,255,.2)", opacity: 1, borderRadius: 0 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: { backgroundColor: "#FFD600", height: 3, borderRadius: 0 },
          root: { borderBottom: "2px solid rgba(255,255,255,.3)" },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            fontFamily: monoStack,
            fontWeight: 800,
            fontSize: 12,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            "&.Mui-selected": { color: "#FFD600" },
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontFamily: monoStack,
            fontSize: 12,
            borderRadius: 0,
            backgroundColor: "#FFD600",
            color: "#000000",
            fontWeight: 800,
            border: "none",
            boxShadow: "none",
          },
          arrow: { color: "#FFD600" },
        },
      },
      MuiAlert: {
        styleOverrides: {
          root: {
            borderRadius: 0,
            borderWidth: 2,
            fontFamily: monoStack,
          },
        },

        variants: [
          {
            props: { variant: "outlined", severity: "error" },
            style: {
              borderColor: "#FF3B30",
              color: "#FF3B30",
            },
          },
          {
            props: { variant: "outlined", severity: "warning" },
            style: {
              borderColor: "#FFD600",
              color: "#FFD600",
            },
          },
          {
            props: { variant: "outlined", severity: "success" },
            style: {
              borderColor: "#00FF88",
              color: "#00FF88",
            },
          },
          {
            props: { variant: "outlined", severity: "info" },
            style: {
              borderColor: "#00E5FF",
              color: "#00E5FF",
            },
          },
        ],
      },
    },
  }),

  // ── 7. SUNRISE — light ───────────────────────────────────────────────
  // Warm coral/amber/gold gradients, glass cards, fully rounded controls.
  sunrise: mkLight({
    bg: "#FFF0E8",
    paper: "#FFFFFF",
    primary: "#F03D2F",
    secondary: "#FF8C00",
    info: "#0284C7",
    success: "#15803D",
    warning: "#D97706",
    error: "#DC2626",
    text: "#1A0A00",
    typography: {
      fontFamily: roundedStack,
      h1: { fontFamily: roundedStack, fontWeight: 800, letterSpacing: -0.5 },
      h2: { fontFamily: roundedStack, fontWeight: 800, letterSpacing: -0.3 },
      h3: { fontFamily: roundedStack, fontWeight: 700 },
      h4: { fontFamily: roundedStack, fontWeight: 700 },
      h5: { fontFamily: roundedStack, fontWeight: 700 },
      body1: { fontFamily: roundedStack, lineHeight: 1.65 },
      body2: { fontFamily: roundedStack, lineHeight: 1.6 },
      button: { fontFamily: roundedStack, fontWeight: 800 },
    },
    shape: { borderRadius: 14 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#FFF0E8",
            backgroundImage: `
              radial-gradient(ellipse 700px 500px at 8% -5%, rgba(255,80,120,.14), transparent 50%),
              radial-gradient(ellipse 1000px 600px at 12% 5%, rgba(240,61,47,.18), transparent 55%),
              radial-gradient(ellipse 800px 400px at 92% 8%, rgba(255,140,0,.18), transparent 50%),
              radial-gradient(ellipse 1200px 180px at 50% 38%, rgba(255,100,50,.07), transparent 60%),
              ${noiseSVG(0.035)}
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#F03D2F", 0.35)} transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 999,
              backgroundColor: alpha("#F03D2F", 0.28),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: alpha("#F03D2F", 0.45) },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#F03D2F", 0.2), color: "#1A0A00" },
          },
        },
      },
      // Warm glass — sunlight through a beach-house window
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            backgroundColor: "rgba(255,255,255,.92)",
            backdropFilter: "blur(12px)",
            border: `1px solid ${alpha("#F03D2F", 0.1)}`,
            boxShadow: `0 2px 12px ${alpha("#E84020", 0.1)}, 0 0 0 1px ${alpha("#F03D2F", 0.06)}`,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: `linear-gradient(180deg, ${alpha("#FF7050", 0.05)} 0%, transparent 35%)`,
            backgroundColor: "rgba(255,255,255,.94)",
            backdropFilter: "blur(10px)",
            border: `1px solid ${alpha("#F03D2F", 0.12)}`,
            borderRadius: 20,
            boxShadow: `0 4px 20px ${alpha("#D83520", 0.12)}, 0 0 0 1px ${alpha("#F03D2F", 0.07)}`,
            transition: "box-shadow 200ms ease, transform 200ms ease",
            "&:hover": {
              boxShadow: `0 8px 32px ${alpha("#D83520", 0.18)}, 0 0 0 1px ${alpha("#F03D2F", 0.1)}`,
              transform: "translateY(-2px)",
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 999,
            height: 36,
          },
          sizeSmall: {
            borderRadius: 999,
          },
          sizeLarge: {
            borderRadius: 999,
          },
          outlined: {
            borderRadius: 999,
            border: `1.5px solid ${alpha("#F03D2F", 0.5)}`,
            color: "#F03D2F",
            "&:hover": {
              backgroundColor: alpha("#F03D2F", 0.07),
              borderColor: "#F03D2F",
              boxShadow: `0 4px 14px ${alpha("#F03D2F", 0.2)}`,
            },
          },
          text: {
            borderRadius: 999,
            color: "#F03D2F",
            "&:hover": {
              backgroundColor: alpha("#F03D2F", 0.08),
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundImage: `linear-gradient(135deg, #F03D2F 0%, #FF6035 45%, #FF8C00 100%)`,
              boxShadow: `0 4px 20px ${alpha("#F03D2F", 0.4)}, inset 0 1px 0 rgba(255,255,255,.18)`,
              "&:hover": {
                backgroundImage: `linear-gradient(135deg, #F54D40 0%, #FF7040 45%, #FF9A10 100%)`,
                boxShadow: `0 6px 28px ${alpha("#F03D2F", 0.52)}`,
                transform: "translateY(-1px)",
              },
              "&:active": {
                transform: "translateY(0)",
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 999,
            backgroundColor: "rgba(255,255,255,.8)",
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#F03D2F", 0.5),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#F03D2F",
              boxShadow: `0 0 0 3px ${alpha("#F03D2F", 0.14)}`,
            },
          },
          notchedOutline: { borderColor: alpha("#F03D2F", 0.2), borderRadius: 999 },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 999,
            fontWeight: 700,
            backgroundImage: `linear-gradient(135deg, ${alpha("#F03D2F", 0.12)}, ${alpha("#FF8C00", 0.1)})`,
            border: `1px solid ${alpha("#F03D2F", 0.22)}`,
            color: "#C4200F",
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontFamily: roundedStack,
            fontSize: 11.5,
            fontWeight: 800,
            textTransform: "uppercase",
            letterSpacing: 0.4,
            color: alpha("#F03D2F", 0.75),
            backgroundColor: alpha("#F03D2F", 0.04),
            borderBottom: `2px solid ${alpha("#F03D2F", 0.14)}`,
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: { "&:hover": { backgroundColor: alpha("#F03D2F", 0.04) } },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: alpha("#F03D2F", 0.12) },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 999, backgroundColor: alpha("#F03D2F", 0.12), height: 6 },
          bar: {
            borderRadius: 999,
            backgroundImage: `linear-gradient(90deg, #F03D2F, #FF8C00)`,
            boxShadow: `0 0 8px ${alpha("#F03D2F", 0.4)}`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#F03D2F",
              "& + .MuiSwitch-track": {
                backgroundImage: `linear-gradient(90deg, ${alpha("#F03D2F", 0.7)}, ${alpha("#FF8C00", 0.6)})`,
                opacity: 1,
              },
            },
          },
          track: { backgroundColor: alpha("#1A0A00", 0.18), opacity: 1, borderRadius: 999 },
          thumb: { boxShadow: `0 2px 6px ${alpha("#F03D2F", 0.3)}` },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            backgroundImage: `linear-gradient(90deg, #F03D2F, #FF8C00)`,
            height: 3,
            borderRadius: 999,
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontFamily: roundedStack,
            fontSize: 12,
            fontWeight: 700,
            borderRadius: 12,
            backgroundColor: "#1A0A00",
            color: "#FFF0E8",
            boxShadow: `0 4px 16px ${alpha("#D83520", 0.3)}`,
          },
          arrow: { color: "#1A0A00" },
        },
      },
    },
  }),

  // ── 8. VALENTINE — dark ──────────────────────────────────────────────
  // Crimson-to-magenta gradients, glass cards, dark corners.
  valentine: mkLight({
    bg: "#FBF0F4",
    paper: "#FFFFFF",
    primary: "#C2185B",
    secondary: "#E91E8C",
    info: "#7C3AED",
    success: "#15803D",
    warning: "#92400E",
    error: "#9B1B1B",
    text: "#1A0510",
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#FBF0F4",
            // Rose bloom at center, shadow creeping in from corners — the battlefield edge
            backgroundImage: `
              radial-gradient(ellipse 900px 600px at 18% -5%, rgba(194,24,91,.22), transparent 55%),
              radial-gradient(ellipse 700px 500px at 88% 12%, rgba(233,30,140,.18), transparent 50%),
              radial-gradient(ellipse 500px 400px at 50% 95%, rgba(80,0,30,.1), transparent 55%),
              radial-gradient(ellipse 350px 350px at 0% 100%, rgba(40,0,15,.07), transparent 50%),
              radial-gradient(ellipse 350px 350px at 100% 100%, rgba(40,0,15,.07), transparent 50%),
              ${noiseSVG(0.04)}
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#C2185B", 0.38)} transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 999,
              backgroundColor: alpha("#C2185B", 0.3),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: alpha("#C2185B", 0.5) },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#C2185B", 0.22), color: "#1A0510" },
          },
        },
      },
      // Crystal glass — petal-thin surfaces
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "linear-gradient(180deg, rgba(255,255,255,.92), rgba(255,255,255,.98))",
            backdropFilter: "blur(16px)",
            border: `1px solid ${alpha("#C2185B", 0.12)}`,
            boxShadow: `0 2px 16px ${alpha("#8B0030", 0.1)}, 0 0 0 1px ${alpha("#C2185B", 0.07)}`,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            // Crystal surface with rose bloom at the top
            backgroundImage: `linear-gradient(180deg, ${alpha("#E91E8C", 0.05)} 0%, rgba(255,255,255,.0) 30%)`,
            backgroundColor: "rgba(255,255,255,.93)",
            backdropFilter: "blur(18px)",
            border: `1px solid ${alpha("#C2185B", 0.14)}`,
            borderRadius: 20,
            // Rose-petal shadow — warm crimson, not cold grey
            boxShadow: `
              0 2px 8px ${alpha("#8B0030", 0.1)},
              0 8px 24px ${alpha("#8B0030", 0.1)},
              0 0 0 1px ${alpha("#C2185B", 0.08)}
            `,
            transition: "box-shadow 220ms ease, transform 220ms ease",
            "&:hover": {
              boxShadow: `
                0 4px 16px ${alpha("#8B0030", 0.16)},
                0 12px 36px ${alpha("#8B0030", 0.14)},
                0 0 0 1px ${alpha("#C2185B", 0.12)}
              `,
              transform: "translateY(-2px)",
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 14,
            height: 36,
          },
          outlined: {
            borderRadius: 14,
            border: `1.5px solid ${alpha("#C2185B", 0.45)}`,
            color: "#C2185B",
            "&:hover": {
              backgroundColor: alpha("#C2185B", 0.06),
              borderColor: "#C2185B",
              boxShadow: `0 4px 14px ${alpha("#C2185B", 0.2)}`,
            },
          },
          text: {
            borderRadius: 14,
            color: "#C2185B",
            "&:hover": {
              backgroundColor: alpha("#C2185B", 0.07),
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundImage: `linear-gradient(135deg, #A81048 0%, #C2185B 45%, #E91E8C 100%)`,
              boxShadow: `0 4px 20px ${alpha("#C2185B", 0.42)}, inset 0 1px 0 rgba(255,255,255,.15)`,
              "&:hover": {
                backgroundImage: `linear-gradient(135deg, #B81858 0%, #D2286B 45%, #F92E9C 100%)`,
                boxShadow: `0 6px 28px ${alpha("#C2185B", 0.55)}`,
                transform: "translateY(-1px)",
              },
              "&:active": {
                transform: "translateY(0)",
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 14,
            backgroundColor: "rgba(255,255,255,.75)",
            backdropFilter: "blur(8px)",
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#C2185B", 0.5),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#C2185B",
              boxShadow: `0 0 0 3px ${alpha("#C2185B", 0.15)}`,
            },
          },
          notchedOutline: { borderColor: alpha("#C2185B", 0.2) },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 10,
            fontWeight: 700,
            backgroundColor: alpha("#C2185B", 0.08),
            border: `1px solid ${alpha("#C2185B", 0.22)}`,
            color: "#8B0030",
            backdropFilter: "blur(6px)",
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontSize: 11.5,
            fontWeight: 800,
            textTransform: "uppercase",
            letterSpacing: 0.4,
            color: alpha("#C2185B", 0.78),
            backgroundColor: alpha("#C2185B", 0.04),
            borderBottom: `2px solid ${alpha("#C2185B", 0.15)}`,
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: { "&:hover": { backgroundColor: alpha("#C2185B", 0.04) } },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: alpha("#C2185B", 0.12) },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 999, backgroundColor: alpha("#C2185B", 0.12), height: 6 },
          bar: {
            borderRadius: 999,
            backgroundImage: `linear-gradient(90deg, #C2185B, #E91E8C)`,
            boxShadow: `0 0 8px ${alpha("#C2185B", 0.45)}`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#E91E8C",
              "& + .MuiSwitch-track": {
                backgroundImage: `linear-gradient(90deg, ${alpha("#C2185B", 0.65)}, ${alpha("#E91E8C", 0.55)})`,
                opacity: 1,
              },
            },
          },
          track: { backgroundColor: alpha("#1A0510", 0.18), opacity: 1 },
          thumb: { boxShadow: `0 2px 6px ${alpha("#C2185B", 0.35)}` },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            backgroundImage: `linear-gradient(90deg, #C2185B, #E91E8C)`,
            height: 3,
            borderRadius: 999,
            boxShadow: `0 0 8px ${alpha("#C2185B", 0.5)}`,
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontSize: 12,
            borderRadius: 12,
            backgroundColor: "#1A0510",
            color: "#FBF0F4",
            boxShadow: `0 4px 16px ${alpha("#8B0030", 0.4)}`,
            border: `1px solid ${alpha("#C2185B", 0.3)}`,
          },
          arrow: { color: "#1A0510" },
        },
      },
    },
  }),

  // ── 9. CYBER — dark ──────────────────────────────────────────────────
  // Black background, cyan + magenta neon, CRT scanlines, monospace, glow.
  cyber: mkDark({
    bg: "#020408",
    paper: "#040810",
    primary: "#00E5FF",
    secondary: "#FF00CC",
    info: "#00FF88",
    success: "#00FF88",
    warning: "#FFD600",
    error: "#FF1744",
    text: "#D0EEFF",
    typography: {
      fontFamily: monoStack,
      h1: { fontFamily: monoStack, fontWeight: 900, letterSpacing: -0.6, fontSize: 28 },
      h2: { fontFamily: monoStack, fontWeight: 900, letterSpacing: -0.4, fontSize: 22 },
      h3: { fontFamily: monoStack, fontWeight: 850, letterSpacing: -0.2, fontSize: 18 },
      h4: { fontFamily: monoStack, fontWeight: 800, fontSize: 16 },
      h5: { fontFamily: monoStack, fontWeight: 800, fontSize: 14 },
      body1: { fontFamily: monoStack, fontSize: 13, lineHeight: 1.65 },
      body2: { fontFamily: monoStack, fontSize: 12.5, lineHeight: 1.6 },
      caption: { fontFamily: monoStack, fontSize: 12 },
      button: { fontFamily: monoStack, letterSpacing: 1.4, fontWeight: 900, textTransform: "uppercase" },
    },
    shape: { borderRadius: 4 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#020408",
            backgroundImage: `
              radial-gradient(ellipse 1600px 700px at 50% -15%, rgba(0,229,255,.06), transparent 55%),
              radial-gradient(ellipse 600px 450px at 6% 6%, rgba(0,229,255,.18), transparent 48%),
              radial-gradient(ellipse 500px 380px at 94% 8%, rgba(255,0,204,.15), transparent 48%),
              radial-gradient(ellipse 900px 200px at 50% 100%, rgba(0,229,255,.05), transparent 55%),
              ${scanlines(0.025, 3)}
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#00E5FF", 0.45)} #000000`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 0,
              backgroundColor: alpha("#00E5FF", 0.38),
              border: "1px solid " + alpha("#00E5FF", 0.2),
              boxShadow: `0 0 6px ${alpha("#00E5FF", 0.4)}`,
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "#020408" },
            "::selection": { backgroundColor: alpha("#00E5FF", 0.35), color: "#000000" },
          },
          // Neon text-shadow on headings — phosphor glow
          "h1, h2, h3": {
            textShadow: `0 0 20px ${alpha("#00E5FF", 0.55)}, 0 0 40px ${alpha("#00E5FF", 0.2)}`,
          },
          "@keyframes neonPulse": {
            "0%, 100%": { opacity: 1 },
            "50%": { opacity: 0.78 },
          },
          "@keyframes cyberFlicker": {
            "0%, 95%, 100%": { opacity: 1 },
            "96%":   { opacity: 0.85 },
            "97%":   { opacity: 1 },
            "98%":   { opacity: 0.9 },
          },
          "@keyframes neonScan": {
            "0%":   { backgroundPosition: "0 0" },
            "100%": { backgroundPosition: "0 100px" },
          },
        },
      },
      // Dark terminal pane — scanlines inside, dual neon border
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            backgroundColor: alpha("#020408", 0.88),
            // Dual neon split: cyan top-left, magenta bottom-right
            border: `1px solid ${alpha("#00E5FF", 0.22)}`,
            boxShadow: `
              0 0 0 1px ${alpha("#FF00CC", 0.1)},
              0 0 20px ${alpha("#00E5FF", 0.06)},
              inset 0 0 30px ${alpha("#00E5FF", 0.03)}
            `,
            position: "relative",
            overflow: "hidden",
            "&::before": {
              content: '""',
              position: "absolute",
              inset: 0,
              backgroundImage: scanlines(0.018, 3),
              pointerEvents: "none",
              zIndex: 0,
            },
            // Top neon scan line — like CRT electron beam
            "&::after": {
              content: '""',
              position: "absolute",
              top: 0, left: 0, right: 0,
              height: 1,
              background: `linear-gradient(90deg, transparent 0%, ${alpha("#00E5FF", 0.7)} 40%, ${alpha("#FF00CC", 0.5)} 70%, transparent 100%)`,
              pointerEvents: "none",
            },
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            backgroundColor: "#040912",
            border: `1px solid ${alpha("#00E5FF", 0.25)}`,
            boxShadow: `
              0 0 0 1px ${alpha("#FF00CC", 0.1)},
              0 0 24px ${alpha("#00E5FF", 0.08)},
              0 0 48px ${alpha("#00E5FF", 0.04)},
              inset 0 0 30px ${alpha("#00E5FF", 0.03)}
            `,
            position: "relative",
            overflow: "hidden",
            "&::before": {
              content: '""',
              position: "absolute",
              inset: 0,
              backgroundImage: scanlines(0.016, 3),
              pointerEvents: "none",
              zIndex: 0,
            },
            "&::after": {
              content: '""',
              position: "absolute",
              top: 0, left: 0, right: 0,
              height: 1,
              background: `linear-gradient(90deg, transparent, ${alpha("#00E5FF", 0.8)}, ${alpha("#FF00CC", 0.6)}, transparent)`,
              pointerEvents: "none",
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 4,
            border: `1px solid ${alpha("#00E5FF", 0.4)}`,
            backgroundColor: alpha("#00E5FF", 0.05),
            color: "#00E5FF",
            letterSpacing: "0.1em",
            "&:hover": {
              backgroundColor: alpha("#00E5FF", 0.12),
              borderColor: alpha("#00E5FF", 0.7),
              boxShadow: `0 0 18px ${alpha("#00E5FF", 0.3)}, inset 0 0 12px ${alpha("#00E5FF", 0.05)}`,
            },
          },

          outlined: {
            borderRadius: 4,
            border: `1px solid ${alpha("#FF00CC", 0.45)}`,
            color: "#FF00CC",
            "&:hover": {
              backgroundColor: alpha("#FF00CC", 0.08),
              borderColor: alpha("#FF00CC", 0.7),
              boxShadow: `0 0 18px ${alpha("#FF00CC", 0.3)}`,
            },
          },

          text: {
            color: alpha("#00E5FF", 0.85),
            "&:hover": {
              backgroundColor: alpha("#00E5FF", 0.07),
              color: "#00E5FF",
              textShadow: `0 0 8px ${alpha("#00E5FF", 0.6)}`,
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundColor: "#00E5FF",
              backgroundImage: "none",
              color: "#000000",
              border: `1px solid ${alpha("#00E5FF", 0.6)}`,
              boxShadow: `0 0 24px ${alpha("#00E5FF", 0.5)}, inset 0 1px 0 rgba(255,255,255,.15)`,
              "&:hover": {
                backgroundColor: "#33ECFF",
                boxShadow: `0 0 36px ${alpha("#00E5FF", 0.7)}, 0 0 60px ${alpha("#00E5FF", 0.3)}`,
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 4,
            backgroundColor: alpha("#020408", 0.7),
            fontFamily: monoStack,
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#00E5FF", 0.6),
              boxShadow: `0 0 8px ${alpha("#00E5FF", 0.15)}`,
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#00E5FF",
              boxShadow: `0 0 0 3px ${alpha("#00E5FF", 0.18)}, 0 0 12px ${alpha("#00E5FF", 0.2)}`,
            },
          },
          notchedOutline: { borderColor: alpha("#00E5FF", 0.25), borderRadius: 4 },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 4,
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 800,
            letterSpacing: "0.08em",
            backgroundColor: alpha("#00E5FF", 0.07),
            border: `1px solid ${alpha("#00E5FF", 0.35)}`,
            color: "#00E5FF",
            boxShadow: `0 0 6px ${alpha("#00E5FF", 0.18)}`,
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 900,
            textTransform: "uppercase",
            letterSpacing: 1.2,
            color: "#00E5FF",
            backgroundColor: alpha("#00E5FF", 0.05),
            borderBottom: `1px solid ${alpha("#00E5FF", 0.3)}`,
            textShadow: `0 0 10px ${alpha("#00E5FF", 0.5)}`,
          },
          root: { fontFamily: monoStack, fontSize: 12.5, borderBottomColor: alpha("#00E5FF", 0.1) },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: {
            "&:hover": {
              backgroundColor: alpha("#00E5FF", 0.05),
              boxShadow: `inset 0 0 0 1px ${alpha("#00E5FF", 0.08)}`,
            },
          },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: {
            borderColor: alpha("#00E5FF", 0.15),
            boxShadow: `0 0 4px ${alpha("#00E5FF", 0.15)}`,
          },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 0, backgroundColor: alpha("#00E5FF", 0.1), height: 4 },
          bar: {
            borderRadius: 0,
            backgroundColor: "#00E5FF",
            boxShadow: `0 0 10px ${alpha("#00E5FF", 0.7)}, 0 0 20px ${alpha("#00E5FF", 0.4)}`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#00E5FF",
              "& + .MuiSwitch-track": {
                backgroundColor: alpha("#00E5FF", 0.35),
                opacity: 1,
                boxShadow: `0 0 8px ${alpha("#00E5FF", 0.4)}`,
              },
            },
          },
          thumb: {
            boxShadow: `0 0 8px ${alpha("#00E5FF", 0.5)}`,
          },
          track: { backgroundColor: alpha("#D0EEFF", 0.12), opacity: 1, borderRadius: 0 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            backgroundColor: "#00E5FF",
            height: 2,
            borderRadius: 0,
            boxShadow: `0 0 12px ${alpha("#00E5FF", 0.8)}, 0 0 24px ${alpha("#00E5FF", 0.4)}`,
          },
          root: { borderBottom: `1px solid ${alpha("#00E5FF", 0.18)}` },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            fontFamily: monoStack,
            fontSize: 11.5,
            fontWeight: 800,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            "&.Mui-selected": { textShadow: `0 0 10px ${alpha("#00E5FF", 0.6)}` },
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontFamily: monoStack,
            fontSize: 11.5,
            borderRadius: 4,
            backgroundColor: alpha("#020408", 0.97),
            border: `1px solid ${alpha("#00E5FF", 0.45)}`,
            color: "#00E5FF",
            boxShadow: `0 0 16px ${alpha("#00E5FF", 0.3)}, inset 0 0 20px ${alpha("#00E5FF", 0.05)}`,
            letterSpacing: "0.05em",
          },
          arrow: { color: alpha("#020408", 0.97) },
        },
      },
    },
  }),

  // ── 10. THE ONE — Escanor, Lion's Sin of Pride, noon sun absolute ─────
  // "Who decided that?" — At noon, for one minute, he is The One.
  // Molten gold blazing out of obsidian void. Solar radiance at its peak.
  // Not luxury for luxury's sake — this is the pinnacle because nothing
  // less is acceptable. Every surface, every shadow, every glow: maximum.
  // Signature: blazing solar backdrop + liquid gold gradients + crown shimmer.
  the_one: mkDark({
    bg: "#060606",
    paper: "#0C0C0C",
    primary: "#C9A84C",
    secondary: "#E8D5A3",
    info: "#6B9FD4",
    success: "#4CAF82",
    warning: "#E8A020",
    error: "#E05252",
    text: "#F2EDD8",
    typography: {
      h1: { fontWeight: 900, letterSpacing: -0.9, fontSize: 30 },
      h2: { fontWeight: 900, letterSpacing: -0.6, fontSize: 24 },
      h3: { fontWeight: 850, letterSpacing: -0.3, fontSize: 20 },
      h4: { fontWeight: 800, fontSize: 17 },
      h5: { fontWeight: 800, fontSize: 15 },
      body1: { lineHeight: 1.65 },
      caption: { fontStyle: "italic", lineHeight: 1.4 },
      button: { fontWeight: 900, letterSpacing: 0.6 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#060606",
            // The noon sun blazing from directly above — Escanor's solar corona
            backgroundImage: `
              radial-gradient(ellipse 700px 500px at 50% -8%, rgba(235,200,80,.24), transparent 52%),
              radial-gradient(ellipse 1400px 400px at 50% -4%, rgba(201,168,76,.12), transparent 58%),
              radial-gradient(ellipse 500px 500px at 4% 12%, rgba(201,168,76,.09), transparent 50%),
              radial-gradient(ellipse 500px 500px at 96% 12%, rgba(201,168,76,.09), transparent 50%),
              radial-gradient(ellipse 1000px 180px at 50% 100%, rgba(160,110,20,.07), transparent 55%),
              ${noiseSVG(0.055)}
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#C9A84C", 0.45)} transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 4,
              backgroundColor: alpha("#C9A84C", 0.38),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              boxShadow: `0 0 6px ${alpha("#C9A84C", 0.3)}`,
              "&:hover": { backgroundColor: alpha("#C9A84C", 0.6) },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#C9A84C", 0.38), color: "#060606" },
          },
          // Heading glow — the pride of The One
          "h1, h2": {
            textShadow: `0 0 30px ${alpha("#C9A84C", 0.4)}, 0 0 60px ${alpha("#C9A84C", 0.15)}`,
          },
          // Solar radiance animation — Escanor's power building
          "@keyframes solarRadiance": {
            "0%, 100%": { boxShadow: `0 0 20px ${alpha("#C9A84C", 0.18)}, inset 0 0 25px ${alpha("#C9A84C", 0.04)}` },
            "50%":       { boxShadow: `0 0 45px ${alpha("#C9A84C", 0.32)}, inset 0 0 40px ${alpha("#C9A84C", 0.08)}` },
          },
          "@keyframes goldShimmer": {
            "0%":   { backgroundPosition: "-200% center" },
            "100%": { backgroundPosition: "200% center" },
          },
        },
      },
      // Obsidian surface — absorbs everything, reflects gold
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: `linear-gradient(180deg, ${alpha("#C9A84C", 0.05)} 0%, ${alpha("#C9A84C", 0.015)} 40%, transparent 100%)`,
            backgroundColor: "#0C0C0C",
            border: `1px solid ${alpha("#C9A84C", 0.18)}`,
            boxShadow: `
              0 4px 24px rgba(6,6,6,.7),
              0 0 0 1px ${alpha("#C9A84C", 0.08)},
              inset 0 1px 0 ${alpha("#E8D5A3", 0.06)}
            `,
          },
        },
      },
      // The throne — every card is a seat of power
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: `linear-gradient(180deg, ${alpha("#C9A84C", 0.07)} 0%, ${alpha("#C9A84C", 0.02)} 30%, transparent 100%)`,
            backgroundColor: "#0A0A0A",
            border: `1px solid ${alpha("#C9A84C", 0.22)}`,
            borderRadius: 16,
            boxShadow: `
              0 6px 32px rgba(6,6,6,.75),
              0 0 0 1px ${alpha("#C9A84C", 0.1)},
              inset 0 1px 0 ${alpha("#E8D5A3", 0.1)}
            `,
            position: "relative",
            overflow: "hidden",
            transition: "box-shadow 250ms ease, transform 250ms ease",
            // Crown shimmer — gold light across the top
            "&::after": {
              content: '""',
              position: "absolute",
              top: 0, left: "5%", right: "5%",
              height: 1,
              background: `linear-gradient(90deg, transparent, ${alpha("#E8D080", 0.9)}, ${alpha("#C9A84C", 0.6)}, transparent)`,
              pointerEvents: "none",
            },
            "&:hover": {
              boxShadow: `
                0 10px 48px rgba(6,6,6,.8),
                0 0 0 1px ${alpha("#C9A84C", 0.18)},
                0 0 40px ${alpha("#C9A84C", 0.12)},
                inset 0 1px 0 ${alpha("#E8D5A3", 0.14)}
              `,
              transform: "translateY(-2px)",
            },
          },
        },
      },
      // Liquid gold buttons — the absolute
      MuiButton: {
        styleOverrides: {
          outlined: {
            border: `1px solid ${alpha("#C9A84C", 0.45)}`,
            color: "#E8D5A3",
            backgroundColor: alpha("#C9A84C", 0.05),
            "&:hover": {
              backgroundColor: alpha("#C9A84C", 0.1),
              borderColor: alpha("#C9A84C", 0.7),
              boxShadow: `0 0 20px ${alpha("#C9A84C", 0.2)}`,
            },
          },

          text: {
            color: alpha("#E8D5A3", 0.85),
            "&:hover": {
              backgroundColor: alpha("#C9A84C", 0.08),
              color: "#E8D5A3",
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              color: "#060606",
              backgroundImage: `linear-gradient(180deg, #E0C060 0%, #C9A84C 50%, #A88830 100%)`,
              border: `1px solid ${alpha("#E8D5A3", 0.35)}`,
              boxShadow: `
                0 4px 20px ${alpha("#C9A84C", 0.4)},
                inset 0 1px 0 rgba(255,255,255,.2),
                inset 0 -1px 0 rgba(0,0,0,.2)
              `,
              fontWeight: 900,
              "&:hover": {
                backgroundImage: `linear-gradient(180deg, #EAC868 0%, #D9B85A 50%, #B89840 100%)`,
                boxShadow: `
                  0 6px 32px ${alpha("#C9A84C", 0.58)},
                  0 0 60px ${alpha("#C9A84C", 0.2)},
                  inset 0 1px 0 rgba(255,255,255,.25)
                `,
                transform: "translateY(-1px)",
              },
              "&:active": {
                transform: "translateY(0)",
                boxShadow: `inset 0 2px 6px rgba(0,0,0,.25)`,
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#C9A84C", 0.5),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#C9A84C",
              boxShadow: `0 0 0 3px ${alpha("#C9A84C", 0.15)}, 0 0 12px ${alpha("#C9A84C", 0.12)}`,
            },
          },
          notchedOutline: { borderColor: alpha("#C9A84C", 0.22) },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            backgroundColor: alpha("#C9A84C", 0.1),
            border: `1px solid ${alpha("#C9A84C", 0.28)}`,
            color: "#E8D5A3",
            fontWeight: 700,
            boxShadow: `0 0 6px ${alpha("#C9A84C", 0.15)}`,
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontSize: 11,
            fontWeight: 900,
            textTransform: "uppercase",
            letterSpacing: 0.9,
            color: alpha("#C9A84C", 0.9),
            backgroundColor: alpha("#C9A84C", 0.06),
            borderBottom: `1px solid ${alpha("#C9A84C", 0.22)}`,
            textShadow: `0 0 12px ${alpha("#C9A84C", 0.35)}`,
          },
          root: { borderBottomColor: alpha("#C9A84C", 0.1) },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: {
            "&:hover": {
              backgroundColor: alpha("#C9A84C", 0.05),
              boxShadow: `inset 0 0 0 1px ${alpha("#C9A84C", 0.08)}`,
            },
          },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: {
            borderColor: "transparent",
            backgroundImage: `linear-gradient(90deg, transparent, ${alpha("#C9A84C", 0.3)}, transparent)`,
            height: 1,
            border: "none",
          },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 999, backgroundColor: alpha("#C9A84C", 0.14), height: 5 },
          bar: {
            borderRadius: 999,
            backgroundImage: `linear-gradient(90deg, #A88830, #C9A84C, #E0C060)`,
            boxShadow: `0 0 10px ${alpha("#C9A84C", 0.6)}, 0 0 20px ${alpha("#C9A84C", 0.3)}`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#C9A84C",
              "& + .MuiSwitch-track": {
                backgroundColor: alpha("#C9A84C", 0.45),
                opacity: 1,
                boxShadow: `0 0 8px ${alpha("#C9A84C", 0.4)}`,
              },
            },
          },
          thumb: { boxShadow: `0 0 8px ${alpha("#C9A84C", 0.4)}` },
          track: { backgroundColor: alpha("#F2EDD8", 0.15), opacity: 1 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            backgroundImage: `linear-gradient(90deg, #A88830, #C9A84C, #E0C060)`,
            height: 2,
            borderRadius: 999,
            boxShadow: `0 0 12px ${alpha("#C9A84C", 0.7)}, 0 0 24px ${alpha("#C9A84C", 0.35)}`,
          },
          root: { borderBottom: `1px solid ${alpha("#C9A84C", 0.15)}` },
        },
      },
      // Royal decree — dark velvet with gold seal
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontSize: 12,
            fontStyle: "italic",
            borderRadius: 10,
            backgroundColor: alpha("#0A0A0A", 0.97),
            border: `1px solid ${alpha("#C9A84C", 0.35)}`,
            color: "#E8D5A3",
            boxShadow: `0 4px 20px rgba(6,6,6,.7), 0 0 16px ${alpha("#C9A84C", 0.15)}`,
          },
          arrow: { color: alpha("#0A0A0A", 0.97) },
        },
      },
    },
  }),

  // ── 11. METAL — Metal Gear Solid, Hideo Kojima ────────────────────────
  //
  //  "Kept you waiting, huh?"
  //
  //  FOXHOUND tactical HUD. Codec frequency 140.85 MHz. Red ALERT /
  //  yellow CAUTION system. Scanlines on every surface. Stealth camo.
  //  Cardboard box. Radar sweep. Nanomachines, son. Shadow Moses.
  //
  metal: createTheme({
    ...base,
    shape: { borderRadius: 4 },
    typography: {
      fontFamily: sansStack,
      fontSize: 13,
      h1: { fontSize: 28, fontWeight: 900, letterSpacing: -0.8, fontFamily: monoStack },
      h2: { fontSize: 22, fontWeight: 900, letterSpacing: -0.6, fontFamily: monoStack },
      h3: { fontSize: 18, fontWeight: 850, letterSpacing: -0.3, fontFamily: monoStack },
      h4: { fontSize: 16, fontWeight: 800, fontFamily: monoStack },
      h5: { fontSize: 14, fontWeight: 750, fontFamily: monoStack },
      body1: { fontSize: 13, lineHeight: 1.6 },
      body2: { fontSize: 12.5, lineHeight: 1.55 },
      caption: { fontSize: 12, lineHeight: 1.35, fontFamily: monoStack },
      button: { textTransform: "uppercase", letterSpacing: 1.1, fontWeight: 900, fontFamily: monoStack },
    },
    palette: {
      mode: "dark",
      background: { default: "#06080C", paper: "#0A0F15" },
      primary:   { main: "#E1061B" },   // ALERT — red
      secondary: { main: "#EDEDED" },   // HUD white
      info:      { main: "#37D6C7" },   // CODEC teal — 140.85 MHz
      success:   { main: "#2DE39A" },   // MISSION COMPLETE
      warning:   { main: "#F2C94C" },   // CAUTION — yellow
      error:     { main: "#E1061B" },
      text: { primary: "#EDEDED", secondary: alpha("#EDEDED", 0.7) },
    },
    components: {
      ...base.components,
      MuiCssBaseline: {
        styleOverrides: {
          ":root": {
            "--mgs-codec-snake":   "140.85",
            "--mgs-codec-otacon":  "141.12",
            "--mgs-alert":         "#E1061B",
            "--mgs-caution":       "#F2C94C",
            "--mgs-codec":         "#37D6C7",
          },
          body: {
            backgroundColor: "#06080C",
            backgroundImage: `
              radial-gradient(ellipse 1000px 500px at 50% -8%, rgba(55,214,199,.08), transparent 52%),
              radial-gradient(ellipse 700px 500px at 8%  18%, rgba(225,6,27,.1),   transparent 50%),
              radial-gradient(ellipse 500px 400px at 92% 22%, rgba(242,201,76,.05), transparent 48%),
              ${scanlines(0.022, 4)},
              ${grid(0.013, 28)}
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#37D6C7", 0.4)} #06080C`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 0,
              backgroundColor: alpha("#37D6C7", 0.32),
              border: `1px solid ${alpha("#37D6C7", 0.18)}`,
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "#06080C" },
            "::selection": { backgroundColor: alpha("#37D6C7", 0.35), color: "#06080C" },
          },
          // ── Alert / Caution system ───────────────────────────────────
          "@keyframes alertPulse": {
            "0%, 100%": { boxShadow: "none" },
            "50%": { boxShadow: `0 0 0 1px ${alpha("#E1061B", 0.3)}, 0 0 28px ${alpha("#E1061B", 0.14)}` },
          },
          "@keyframes cautionPulse": {
            "0%, 100%": { boxShadow: "none" },
            "50%": { boxShadow: `0 0 0 1px ${alpha("#F2C94C", 0.35)}, 0 0 20px ${alpha("#F2C94C", 0.12)}` },
          },
          // The "!" moment
          "@keyframes exclamation": {
            "0%":   { transform: "scaleY(0)", opacity: 0 },
            "60%":  { transform: "scaleY(1.15)", opacity: 1 },
            "100%": { transform: "scaleY(1)",    opacity: 1 },
          },
          // Codec static interference
          "@keyframes codecStatic": {
            "0%, 100%": { opacity: 1 },
            "93%": { opacity: 0.7 }, "94%": { opacity: 1 },
            "96%": { opacity: 0.85 }, "97%": { opacity: 1 },
          },
          // Radar sweep
          "@keyframes radarSweep": {
            "0%": { transform: "rotate(0deg)" },
            "100%": { transform: "rotate(360deg)" },
          },
          ".hud-alertable": { transition: "box-shadow 160ms ease" },
          'body[data-alert="on"] .hud-alertable': {
            animation: "alertPulse 1400ms ease-in-out infinite",
          },
          'body[data-caution="on"] .hud-alertable': {
            animation: "cautionPulse 1800ms ease-in-out infinite",
          },
          // ── Cardboard Box — the ultimate stealth technique ───────────
          ".cardboard-box": {
            backgroundColor: "#7A5C18 !important",
            backgroundImage: [
              `repeating-linear-gradient(0deg,  rgba(0,0,0,.06), rgba(0,0,0,.06) 1px, transparent 1px, transparent 8px)`,
              `repeating-linear-gradient(90deg, rgba(0,0,0,.06), rgba(0,0,0,.06) 1px, transparent 1px, transparent 8px)`,
              `repeating-linear-gradient(0deg,  rgba(0,0,0,.1),  rgba(0,0,0,.1)  1px, transparent 1px, transparent 40px)`,
              `repeating-linear-gradient(90deg, rgba(0,0,0,.1),  rgba(0,0,0,.1)  1px, transparent 1px, transparent 60px)`,
            ].join(",") + " !important",
            border: "2px solid #5A3E08 !important",
            color: "#2A1800 !important",
            boxShadow: "inset 0 2px 8px rgba(0,0,0,.3) !important",
          },
          // ── Stealth camo — infiltration mode ────────────────────────
          ".stealth-camo": {
            opacity: "0.18 !important",
            filter: "blur(0.5px)",
            transition: "opacity 400ms ease, filter 400ms ease",
            "&:hover": { opacity: "0.9 !important", filter: "none" },
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            borderRadius: 6,
            backgroundColor: "#0A0F15",
            border: `1px solid ${alpha("#EDEDED", 0.1)}`,
            boxShadow: `inset 0 1px 0 ${alpha("#37D6C7", 0.06)}`,
            position: "relative",
            overflow: "hidden",
            "&::before": {
              content: '""',
              position: "absolute",
              inset: 0,
              backgroundImage: scanlines(0.016, 4),
              pointerEvents: "none",
              mixBlendMode: "overlay",
              zIndex: 0,
            },
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            backgroundColor: "#080D12",
            border: `1px solid ${alpha("#EDEDED", 0.1)}`,
            boxShadow: `0 4px 20px rgba(6,8,12,.7), inset 0 1px 0 ${alpha("#37D6C7", 0.08)}`,
            position: "relative",
            overflow: "hidden",
            "&::before": {
              content: '""',
              position: "absolute",
              inset: 0,
              backgroundImage: scanlines(0.014, 4),
              pointerEvents: "none",
              mixBlendMode: "overlay",
              zIndex: 0,
            },
            // Codec top indicator — teal channel active
            "&::after": {
              content: '""',
              position: "absolute",
              top: 0, left: 0, right: 0,
              height: 2,
              background: `linear-gradient(90deg, ${alpha("#37D6C7", 0.6)}, ${alpha("#37D6C7", 0.2)}, transparent)`,
              pointerEvents: "none",
            },
          },
        },
      },
      MuiButton: {
        defaultProps: {
          disableElevation: true,
        },

        styleOverrides: {
          root: {
            borderRadius: 4,
            border: `1px solid ${alpha("#EDEDED", 0.2)}`,
            backgroundImage: `linear-gradient(180deg, ${alpha("#EDEDED", 0.07)}, ${alpha("#EDEDED", 0.02)})`,
            transition: "all 120ms ease",
          },

          outlined: {
            borderColor: alpha("#37D6C7", 0.45),
            color: "#37D6C7",
            backgroundColor: alpha("#37D6C7", 0.05),
            "&:hover": {
              backgroundColor: alpha("#37D6C7", 0.1),
              borderColor: alpha("#37D6C7", 0.7),
              boxShadow: `0 0 16px ${alpha("#37D6C7", 0.22)}`,
            },
          },

          text: {
            color: alpha("#EDEDED", 0.75),
            "&:hover": {
              backgroundColor: alpha("#EDEDED", 0.06),
              color: "#EDEDED",
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              borderColor: alpha("#E1061B", 0.65),
              backgroundImage: `linear-gradient(180deg, #E8202E, #C0040E)`,
              color: "#FFFFFF",
              boxShadow: `0 0 20px ${alpha("#E1061B", 0.35)}, inset 0 1px 0 rgba(255,255,255,.1)`,
              "&:hover": {
                backgroundImage: `linear-gradient(180deg, #F03040, #D00818)`,
                boxShadow: `0 0 32px ${alpha("#E1061B", 0.55)}`,
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 4,
            fontFamily: monoStack,
            backgroundColor: alpha("#06080C", 0.6),
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#37D6C7", 0.5),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#37D6C7",
              boxShadow: `0 0 0 2px ${alpha("#37D6C7", 0.15)}, 0 0 10px ${alpha("#37D6C7", 0.12)}`,
            },
          },
          notchedOutline: { borderColor: alpha("#EDEDED", 0.18), borderRadius: 4 },
        },
      },
      MuiChip: {
        defaultProps: { size: "small" },
        styleOverrides: {
          root: {
            borderRadius: 4,
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 800,
            letterSpacing: "0.07em",
            height: 24,
            backgroundColor: alpha("#37D6C7", 0.08),
            border: `1px solid ${alpha("#37D6C7", 0.3)}`,
            color: "#37D6C7",
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontFamily: monoStack,
            fontSize: 11,
            fontWeight: 900,
            textTransform: "uppercase",
            letterSpacing: 0.9,
            color: "#37D6C7",
            backgroundColor: alpha("#37D6C7", 0.05),
            borderBottom: `1px solid ${alpha("#37D6C7", 0.25)}`,
          },
          root: { fontFamily: monoStack, fontSize: 12.5, borderBottomColor: alpha("#EDEDED", 0.08) },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: {
            transition: "background 120ms ease",
            "&:hover": { backgroundColor: alpha("#37D6C7", 0.04) },
          },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: alpha("#EDEDED", 0.1) },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 0, backgroundColor: alpha("#37D6C7", 0.12), height: 4 },
          bar: {
            borderRadius: 0,
            backgroundColor: "#37D6C7",
            boxShadow: `0 0 8px ${alpha("#37D6C7", 0.5)}`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            color: alpha("#EDEDED", 0.4),
            "&.Mui-checked": {
              color: "#37D6C7",
              "& + .MuiSwitch-track": {
                backgroundColor: alpha("#37D6C7", 0.42),
                opacity: 1,
                boxShadow: `0 0 8px ${alpha("#37D6C7", 0.35)}`,
              },
            },
          },
          thumb: { boxShadow: "none" },
          track: { backgroundColor: alpha("#EDEDED", 0.15), opacity: 1, borderRadius: 0 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            backgroundColor: "#E1061B",
            height: 2,
            borderRadius: 0,
            boxShadow: `0 0 10px ${alpha("#E1061B", 0.6)}`,
          },
          root: { borderBottom: `1px solid ${alpha("#EDEDED", 0.12)}` },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            fontFamily: monoStack,
            fontWeight: 800,
            fontSize: 12,
            letterSpacing: "0.07em",
            textTransform: "uppercase",
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontFamily: monoStack,
            fontSize: 11.5,
            letterSpacing: "0.05em",
            borderRadius: 4,
            backgroundColor: alpha("#0A0F15", 0.97),
            border: `1px solid ${alpha("#37D6C7", 0.4)}`,
            color: "#37D6C7",
            boxShadow: `0 0 14px ${alpha("#37D6C7", 0.22)}, inset 0 0 20px ${alpha("#37D6C7", 0.04)}`,
          },
          arrow: { color: alpha("#0A0F15", 0.97) },
        },
      },
      MuiAlert: {
        defaultProps: {
          variant: "outlined",
        },

        styleOverrides: {
          root: {
            borderRadius: 4,
            fontFamily: monoStack,
            fontSize: 12.5,
            backgroundColor: alpha("#06080C", 0.7),
          },
        },

        variants: [
          {
            props: { variant: "outlined", severity: "error" },
            style: {
              borderColor: alpha("#E1061B", 0.6),
              color: "#FF4050",
            },
          },
          {
            props: { variant: "outlined", severity: "warning" },
            style: {
              borderColor: alpha("#F2C94C", 0.5),
              color: "#F2C94C",
            },
          },
          {
            props: { variant: "outlined", severity: "info" },
            style: {
              borderColor: alpha("#37D6C7", 0.4),
              color: "#37D6C7",
            },
          },
          {
            props: { variant: "outlined", severity: "success" },
            style: {
              borderColor: alpha("#2DE39A", 0.4),
              color: "#2DE39A",
            },
          },
        ],
      },
      MuiSlider: {
        styleOverrides: {
          root: { color: "#37D6C7" },
          rail: { backgroundColor: alpha("#37D6C7", 0.18), borderRadius: 0 },
          track: { backgroundImage: `linear-gradient(90deg, #2DE39A, #37D6C7)`, border: "none", borderRadius: 0 },
          thumb: {
            borderRadius: 2,
            backgroundColor: "#37D6C7",
            border: `2px solid ${alpha("#37D6C7", 0.5)}`,
            boxShadow: `0 0 0 3px ${alpha("#37D6C7", 0.15)}, 0 0 8px ${alpha("#37D6C7", 0.4)}`,
            "&:hover, &.Mui-active": {
              boxShadow: `0 0 0 5px ${alpha("#37D6C7", 0.2)}, 0 0 16px ${alpha("#37D6C7", 0.55)}`,
            },
          },
        },
      },
    },
  }),

  // ── 12–15. SEASONAL ──────────────────────────────────────────────────

  // WINTER — Christmas Eve: Santa, chimney, cookies, tree ──────────────
  // Midnight outside, fireplace inside. The cold frost on the window
  // against the warm amber glow of the hearth. Gold ornaments, Christmas
  // red, tree green, snow white. Cozy surfaces lit from below by the fire.
  // Signature: fireplace-glow backdrop + frost-crystal borders + Christmas animations.
  winter: mkDark({
    bg: "#05091A",
    paper: "#0B1230",
    primary: "#F5C030",      // gold star on the tree
    secondary: "#CC2828",    // Santa red
    info: "#7DD3FC",         // frost blue
    success: "#22A84A",      // Christmas tree green
    warning: "#F5A623",      // amber candlelight
    error: "#FF4040",
    text: "#EEF4FF",
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#05091A",
            backgroundImage: `
              radial-gradient(ellipse 1000px 400px at 50% -5%,  rgba(125,211,252,.12), transparent 52%),
              radial-gradient(ellipse 400px 400px at 2%   2%,   rgba(165,180,252,.08), transparent 45%),
              radial-gradient(ellipse 400px 400px at 98%  2%,   rgba(165,180,252,.08), transparent 45%),
              radial-gradient(ellipse 900px 450px at 50%  102%, rgba(245,192,48,.22),  transparent 55%),
              radial-gradient(ellipse 500px 300px at 28%  98%,  rgba(204,40,40,.1),    transparent 45%),
              ${noiseSVG(0.038)}
            `,
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#F5C030", 0.4)} transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 4,
              backgroundColor: alpha("#F5C030", 0.32),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: alpha("#F5C030", 0.55) },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#F5C030", 0.35), color: "#05091A" },
          },
          // ── Christmas animations ─────────────────────────────────────
          // Star twinkling on top of the tree
          "@keyframes twinkle": {
            "0%, 100%": { opacity: 1, transform: "scale(1)" },
            "50%":      { opacity: 0.45, transform: "scale(0.88)" },
          },
          // Fireplace flicker — warm light pulsing
          "@keyframes fireplaceFlicker": {
            "0%, 100%": { boxShadow: `inset 0 -2px 0 ${alpha("#F5C030", 0.08)}` },
            "33%":      { boxShadow: `inset 0 -2px 0 ${alpha("#F5A623", 0.14)}` },
            "66%":      { boxShadow: `inset 0 -2px 0 ${alpha("#CC2828", 0.08)}` },
          },
          // Christmas lights cycling through the four colours
          "@keyframes christmasLights": {
            "0%":   { boxShadow: `0 0 7px 1px rgba(245,192,48,.9)`  },
            "25%":  { boxShadow: `0 0 7px 1px rgba(204,40,40,.9)`   },
            "50%":  { boxShadow: `0 0 7px 1px rgba(34,168,74,.9)`   },
            "75%":  { boxShadow: `0 0 7px 1px rgba(125,211,252,.9)` },
            "100%": { boxShadow: `0 0 7px 1px rgba(245,192,48,.9)`  },
          },
          // Snowfall — use on small absolute elements
          "@keyframes snowfall": {
            "0%":   { transform: "translateY(-20px) rotate(0deg)",    opacity: 0 },
            "10%":  { opacity: 1 },
            "90%":  { opacity: 0.8 },
            "100%": { transform: "translateY(100vh) rotate(720deg)", opacity: 0 },
          },
          // Utility classes
          ".christmas-lights": {
            animation: "christmasLights 2s ease-in-out infinite",
          },
          ".twinkle": {
            animation: "twinkle 1.8s ease-in-out infinite",
          },
        },
      },
      // Frost-crystal surface — cold border, warm bottom glow
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: `linear-gradient(180deg, ${alpha("#7DD3FC", 0.04)}, transparent 40%)`,
            backgroundColor: "#0B1230",
            border: `1px solid ${alpha("#7DD3FC", 0.16)}`,
            boxShadow: `
              0 4px 20px rgba(5,9,26,.65),
              inset 0 1px 0 ${alpha("#7DD3FC", 0.08)},
              inset 0 -1px 0 ${alpha("#F5C030", 0.06)}
            `,
          },
        },
      },
      // Cozy card — frost top, fireplace warmth at the bottom
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: `linear-gradient(180deg,
              ${alpha("#7DD3FC", 0.05)} 0%,
              transparent 40%,
              ${alpha("#F5C030", 0.04)} 100%
            )`,
            backgroundColor: "#08102A",
            border: `1px solid ${alpha("#7DD3FC", 0.18)}`,
            borderRadius: 16,
            boxShadow: `
              0 6px 28px rgba(5,9,26,.7),
              inset 0 1px 0 ${alpha("#7DD3FC", 0.1)},
              inset 0 -1px 0 ${alpha("#F5C030", 0.1)}
            `,
            transition: "box-shadow 220ms ease, transform 220ms ease",
            "&:hover": {
              boxShadow: `
                0 8px 36px rgba(5,9,26,.75),
                inset 0 1px 0 ${alpha("#7DD3FC", 0.14)},
                inset 0 -1px 0 ${alpha("#F5C030", 0.16)}
              `,
              transform: "translateY(-2px)",
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          outlined: {
            border: `1px solid ${alpha("#CC2828", 0.45)}`,
            color: "#FF6060",
            "&:hover": {
              backgroundColor: alpha("#CC2828", 0.1),
              borderColor: alpha("#CC2828", 0.7),
              boxShadow: `0 4px 14px ${alpha("#CC2828", 0.22)}`,
            },
          },

          text: {
            color: alpha("#EEF4FF", 0.75),
            "&:hover": {
              backgroundColor: alpha("#7DD3FC", 0.08),
              color: "#EEF4FF",
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundImage: `linear-gradient(180deg, #FCCF40, #E8A820)`,
              color: "#05091A",
              boxShadow: `0 4px 18px ${alpha("#F5C030", 0.4)}, inset 0 1px 0 rgba(255,255,255,.2)`,
              "&:hover": {
                backgroundImage: `linear-gradient(180deg, #FFD845, #F0B025)`,
                boxShadow: `0 6px 26px ${alpha("#F5C030", 0.56)}`,
                transform: "translateY(-1px)",
              },
              "&:active": {
                transform: "translateY(0)",
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#7DD3FC", 0.5),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#F5C030",
              boxShadow: `0 0 0 3px ${alpha("#F5C030", 0.15)}`,
            },
          },
          notchedOutline: { borderColor: alpha("#7DD3FC", 0.22) },
        },
      },
      // Ornament chips — small decorations on the tree
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 999,
            fontWeight: 700,
            backgroundColor: alpha("#F5C030", 0.1),
            border: `1px solid ${alpha("#F5C030", 0.28)}`,
            color: "#F5C030",
            boxShadow: `0 0 6px ${alpha("#F5C030", 0.2)}`,
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontSize: 11,
            fontWeight: 750,
            textTransform: "uppercase",
            letterSpacing: 0.6,
            color: alpha("#F5C030", 0.85),
            backgroundColor: alpha("#F5C030", 0.05),
            borderBottom: `1px solid ${alpha("#F5C030", 0.18)}`,
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: { "&:hover": { backgroundColor: alpha("#F5C030", 0.04) } },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: alpha("#7DD3FC", 0.14) },
        },
      },
      // Garland progress — gold bar with warm glow
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 999, backgroundColor: alpha("#F5C030", 0.14), height: 5 },
          bar: {
            borderRadius: 999,
            backgroundImage: `linear-gradient(90deg, #CC2828, #F5C030, #22A84A, #7DD3FC)`,
            boxShadow: `0 0 10px ${alpha("#F5C030", 0.5)}`,
          },
        },
      },
      // Christmas light switch — gold when on
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#F5C030",
              "& + .MuiSwitch-track": {
                backgroundColor: alpha("#F5C030", 0.45),
                opacity: 1,
                boxShadow: `0 0 8px ${alpha("#F5C030", 0.4)}`,
              },
            },
          },
          thumb: { boxShadow: `0 0 6px ${alpha("#F5C030", 0.3)}` },
          track: { backgroundColor: alpha("#EEF4FF", 0.18), opacity: 1 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            backgroundImage: `linear-gradient(90deg, #CC2828, #F5C030, #22A84A)`,
            height: 3,
            borderRadius: 999,
            boxShadow: `0 0 10px ${alpha("#F5C030", 0.6)}`,
          },
        },
      },
      // Eggnog tooltip — warm and creamy
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontSize: 12,
            borderRadius: 10,
            backgroundColor: alpha("#08102A", 0.97),
            border: `1px solid ${alpha("#F5C030", 0.3)}`,
            color: "#EEF4FF",
            boxShadow: `0 4px 20px rgba(5,9,26,.7), 0 0 12px ${alpha("#F5C030", 0.12)}`,
          },
          arrow: { color: alpha("#08102A", 0.97) },
        },
      },
    },
  }),

  // SPRING — botanical, morning dew, blossoms, meadow at 8 AM ──────────
  // Sunlight filtering through new leaves. Cherry blossoms drifting.
  // Wildflower purple in the distance. Dew still on everything.
  // Organic, rounded, alive. The world waking up after winter.
  // Signature: dot-grid nature journal + dewy glass cards + botanical gradients.
  spring: mkLight({
    bg: "#F0FDF4",
    paper: "#FFFFFF",
    primary: "#15803D",
    secondary: "#5B21B6",
    info: "#0284C7",
    success: "#16A34A",
    warning: "#B45309",
    error: "#B91C1C",
    text: "#0B1A10",
    typography: {
      fontFamily: roundedStack,
      h1: { fontFamily: roundedStack, fontWeight: 800, letterSpacing: -0.4 },
      h2: { fontFamily: roundedStack, fontWeight: 800, letterSpacing: -0.2 },
      h3: { fontFamily: roundedStack, fontWeight: 700 },
      h4: { fontFamily: roundedStack, fontWeight: 700 },
      h5: { fontFamily: roundedStack, fontWeight: 700 },
      body1: { fontFamily: roundedStack, lineHeight: 1.65 },
      button: { fontFamily: roundedStack, fontWeight: 700 },
    },
    shape: { borderRadius: 12 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#F0FDF4",
            backgroundImage: `
              radial-gradient(ellipse 900px 500px at 12% -2%, rgba(21,128,61,.16), transparent 55%),
              radial-gradient(ellipse 700px 400px at 88% 12%, rgba(91,33,182,.09), transparent 50%),
              radial-gradient(ellipse 600px 400px at 50% 18%, rgba(251,182,206,.08), transparent 50%),
              radial-gradient(ellipse 1200px 200px at 50% 102%, rgba(21,128,61,.06), transparent 55%),
              radial-gradient(circle, rgba(11,26,16,.04) 1.5px, transparent 1.5px)
            `,
            backgroundSize: "auto, auto, auto, auto, 22px 22px",
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#15803D", 0.35)} transparent`,
            "&::-webkit-scrollbar": { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 999,
              backgroundColor: alpha("#15803D", 0.28),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: alpha("#15803D", 0.45) },
            },
            "&::-webkit-scrollbar-track": { backgroundColor: "transparent" },
            "::selection": { backgroundColor: alpha("#15803D", 0.2), color: "#0B1A10" },
          },
          // ── Spring animations ────────────────────────────────────────
          // Bloom — element opens like a flower
          "@keyframes bloom": {
            "0%":   { transform: "scale(0.85)", opacity: 0 },
            "70%":  { transform: "scale(1.03)" },
            "100%": { transform: "scale(1)",    opacity: 1 },
          },
          // Dew pulse — morning dew shimmer
          "@keyframes dewPulse": {
            "0%, 100%": { boxShadow: `0 2px 12px ${alpha("#15803D", 0.1)}` },
            "50%":      { boxShadow: `0 4px 20px ${alpha("#15803D", 0.18)}` },
          },
          // Petal drift — for decorative elements
          "@keyframes petalDrift": {
            "0%":   { transform: "translateY(-10px) rotate(-8deg)", opacity: 0 },
            "10%":  { opacity: 0.9 },
            "90%":  { opacity: 0.7 },
            "100%": { transform: "translateY(100vh) rotate(15deg)", opacity: 0 },
          },
          ".bloom": { animation: "bloom 350ms cubic-bezier(.34,1.56,.64,1) forwards" },
          ".dew-pulse": { animation: "dewPulse 3s ease-in-out infinite" },
        },
      },
      // Morning glass — dewy, fresh, slightly translucent
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            backgroundColor: "rgba(255,255,255,.94)",
            backdropFilter: "blur(8px)",
            border: `1px solid ${alpha("#15803D", 0.1)}`,
            boxShadow: `0 2px 12px ${alpha("#0B3D1A", 0.08)}, 0 0 0 1px ${alpha("#15803D", 0.06)}`,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            // Sunlight-through-leaves: subtle green at top, white body
            backgroundImage: `linear-gradient(180deg, ${alpha("#15803D", 0.04)} 0%, transparent 30%)`,
            backgroundColor: "rgba(255,255,255,.96)",
            backdropFilter: "blur(6px)",
            border: `1px solid ${alpha("#15803D", 0.12)}`,
            borderRadius: 18,
            boxShadow: `
              0 2px 8px ${alpha("#0B3D1A", 0.07)},
              0 6px 20px ${alpha("#0B3D1A", 0.07)},
              0 0 0 1px ${alpha("#15803D", 0.07)}
            `,
            transition: "box-shadow 220ms ease, transform 220ms ease",
            "&:hover": {
              boxShadow: `
                0 4px 16px ${alpha("#0B3D1A", 0.1)},
                0 10px 30px ${alpha("#0B3D1A", 0.09)},
                0 0 0 1px ${alpha("#15803D", 0.1)}
              `,
              transform: "translateY(-2px)",
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 999,
          },
          sizeSmall: {
            borderRadius: 999,
          },
          sizeLarge: {
            borderRadius: 999,
          },

          outlined: {
            borderRadius: 999,
            border: `1.5px solid ${alpha("#15803D", 0.4)}`,
            color: "#15803D",
            "&:hover": {
              backgroundColor: alpha("#15803D", 0.07),
              borderColor: "#15803D",
              boxShadow: `0 4px 14px ${alpha("#15803D", 0.18)}`,
            },
          },

          text: {
            borderRadius: 999,
            color: "#15803D",
            "&:hover": {
              backgroundColor: alpha("#15803D", 0.08),
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundImage: `linear-gradient(180deg, #1A9648, #146830)`,
              color: "#FFFFFF",
              boxShadow: `0 4px 16px ${alpha("#15803D", 0.38)}, inset 0 1px 0 rgba(255,255,255,.15)`,
              "&:hover": {
                backgroundImage: `linear-gradient(180deg, #20A050, #178538)`,
                boxShadow: `0 6px 24px ${alpha("#15803D", 0.5)}`,
                transform: "translateY(-1px)",
              },
              "&:active": {
                transform: "translateY(0)",
              },
            },
          },
        ],
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: {
            borderRadius: 12,
            backgroundColor: "rgba(255,255,255,.85)",
            "&:hover .MuiOutlinedInput-notchedOutline": {
              borderColor: alpha("#15803D", 0.5),
            },
            "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
              borderColor: "#15803D",
              boxShadow: `0 0 0 3px ${alpha("#15803D", 0.13)}`,
            },
          },
          notchedOutline: { borderColor: alpha("#15803D", 0.18) },
        },
      },
      // Botanical tags — wildflower variety
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 999,
            fontWeight: 700,
            backgroundColor: alpha("#15803D", 0.08),
            border: `1px solid ${alpha("#15803D", 0.22)}`,
            color: "#166534",
            "&:nth-of-type(3n+1)": {
              backgroundColor: alpha("#5B21B6", 0.07),
              borderColor: alpha("#5B21B6", 0.2),
              color: "#4C1D95",
            },
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: {
            fontSize: 11.5,
            fontWeight: 800,
            textTransform: "uppercase",
            letterSpacing: 0.4,
            color: alpha("#15803D", 0.78),
            backgroundColor: alpha("#15803D", 0.04),
            borderBottom: `2px solid ${alpha("#15803D", 0.14)}`,
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: { "&:hover": { backgroundColor: alpha("#15803D", 0.04) } },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: {
            borderColor: "transparent",
            backgroundImage: `linear-gradient(90deg, transparent, ${alpha("#15803D", 0.18)}, transparent)`,
            height: 1,
            border: "none",
          },
        },
      },
      // Fresh growth bar
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 999, backgroundColor: alpha("#15803D", 0.12), height: 5 },
          bar: {
            borderRadius: 999,
            backgroundImage: `linear-gradient(90deg, #84CC7C, #15803D)`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#15803D",
              "& + .MuiSwitch-track": {
                backgroundImage: `linear-gradient(90deg, ${alpha("#15803D", 0.6)}, ${alpha("#16A34A", 0.5)})`,
                opacity: 1,
              },
            },
          },
          track: { backgroundColor: alpha("#0B1A10", 0.18), opacity: 1, borderRadius: 999 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            backgroundImage: `linear-gradient(90deg, #15803D, #5B21B6)`,
            height: 3,
            borderRadius: 999,
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            fontSize: 12,
            fontWeight: 700,
            borderRadius: 12,
            backgroundColor: "#0B1A10",
            color: "#F0FDF4",
            boxShadow: `0 4px 16px ${alpha("#0B3D1A", 0.3)}`,
          },
          arrow: { color: "#0B1A10" },
        },
      },
    },
  }),

  // SUMMER — blazing sun, heat shimmer, Miami bleach, amber & coral
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
          "@keyframes heatHaze": {
            "0%, 100%": { transform: "translateY(0px) scaleX(1)", opacity: 1 },
            "33%":       { transform: "translateY(-3px) scaleX(1.006)", opacity: 0.88 },
            "66%":       { transform: "translateY(2px) scaleX(0.995)", opacity: 0.92 },
          },
          "@keyframes sunPulse": {
            "0%, 100%": { boxShadow: "0 0 60px 20px rgba(217,119,6,.28), 0 0 120px 60px rgba(220,38,38,.09)" },
            "50%":      { boxShadow: "0 0 90px 36px rgba(217,119,6,.38), 0 0 180px 90px rgba(220,38,38,.14)" },
          },
          "@keyframes shimmer": {
            "0%":   { backgroundPosition: "-400px 0" },
            "100%": { backgroundPosition: "400px 0" },
          },
          body: {
            backgroundColor: "#FFFBEA",
            backgroundImage: [
              // blazing sun corona top-right
              `radial-gradient(ellipse 700px 700px at 92% -8%, rgba(217,119,6,.22), transparent 60%)`,
              // amber heat wash left
              `radial-gradient(ellipse 900px 500px at 5% 20%, rgba(251,191,36,.14), transparent 60%)`,
              // coral heat bloom center
              `radial-gradient(ellipse 600px 300px at 50% 110%, rgba(220,38,38,.08), transparent 55%)`,
              // bleached horizon
              `linear-gradient(180deg, rgba(255,255,255,0) 0%, rgba(255,251,235,.6) 100%)`,
            ].join(","),
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#D97706", 0.4)} transparent`,
            "&::-webkit-scrollbar":       { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 8,
              backgroundColor: alpha("#D97706", 0.32),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
            },
            "::selection": { backgroundColor: alpha("#D97706", 0.35), color: "#1A1000" },
          },
          // Utility: heat-haze shimmer overlay on any element
          ".heat-shimmer": {
            position: "relative",
            "&::after": {
              content: '""',
              position: "absolute",
              inset: 0,
              borderRadius: "inherit",
              backgroundImage: `linear-gradient(90deg, transparent 0%, rgba(255,255,255,.55) 50%, transparent 100%)`,
              backgroundSize: "200% 100%",
              animation: "shimmer 2.8s ease-in-out infinite",
              pointerEvents: "none",
            },
          },
          // Utility: pulsing sun orb class
          ".sun-orb": {
            animation: "sunPulse 4s ease-in-out infinite",
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            border: `1px solid ${alpha("#D97706", 0.13)}`,
            backgroundImage: "none",
            // top golden accent bar
            "&::before": {
              content: '""',
              position: "absolute",
              top: 0, left: "10%", right: "10%",
              height: 2,
              borderRadius: 1,
              background: `linear-gradient(90deg, transparent, ${alpha("#D97706", 0.7)}, ${alpha("#DC2626", 0.5)}, transparent)`,
              pointerEvents: "none",
            },
          },
          elevation1: {
            boxShadow: `0 2px 12px ${alpha("#D97706", 0.1)}, 0 1px 3px ${alpha("#D97706", 0.08)}`,
          },
          elevation2: {
            boxShadow: `0 4px 20px ${alpha("#D97706", 0.13)}, 0 2px 6px ${alpha("#D97706", 0.1)}`,
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            textTransform: "none",
            fontWeight: 650,
          },

          text: {
            "&:hover": {
              backgroundColor: alpha("#D97706", 0.08),
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              background: `linear-gradient(135deg, #FBBF24 0%, #D97706 50%, #B45309 100%)`,
              boxShadow: `0 2px 8px ${alpha("#D97706", 0.4)}`,
              color: "#fff",
              "&:hover": {
                background: `linear-gradient(135deg, #FCD34D 0%, #D97706 50%, #92400E 100%)`,
                boxShadow: `0 4px 16px ${alpha("#D97706", 0.55)}`,
              },
            },
          },

          {
            props: { variant: "contained", color: "secondary" },
            style: {
              background: `linear-gradient(135deg, #F87171 0%, #DC2626 60%, #991B1B 100%)`,
              color: "#fff",
              boxShadow: `0 2px 8px ${alpha("#DC2626", 0.4)}`,
              "&:hover": {
                boxShadow: `0 4px 16px ${alpha("#DC2626", 0.55)}`,
              },
            },
          },

          {
            props: { variant: "outlined", color: "primary" },
            style: {
              borderColor: alpha("#D97706", 0.55),
              color: "#D97706",
              "&:hover": {
                borderColor: "#D97706",
                backgroundColor: alpha("#D97706", 0.07),
              },
            },
          },
        ],
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 20,
            fontWeight: 600,
            fontSize: "0.75rem",
          },
          colorPrimary: {
            backgroundColor: alpha("#D97706", 0.14),
            color: "#92400E",
            border: `1px solid ${alpha("#D97706", 0.3)}`,
          },
          colorSecondary: {
            backgroundColor: alpha("#DC2626", 0.12),
            color: "#991B1B",
            border: `1px solid ${alpha("#DC2626", 0.28)}`,
          },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: {
            borderImage: `linear-gradient(90deg, transparent, ${alpha("#D97706", 0.5)}, ${alpha("#DC2626", 0.3)}, transparent) 1`,
          },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            backgroundColor: alpha("#D97706", 0.14),
            height: 5,
          },
          bar: {
            borderRadius: 8,
            backgroundImage: `linear-gradient(90deg, #FBBF24, #D97706, #DC2626)`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#D97706",
              "& + .MuiSwitch-track": { backgroundColor: alpha("#D97706", 0.5), opacity: 1 },
            },
          },
          track: { backgroundColor: alpha("#1A1000", 0.18), opacity: 1 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            height: 2,
            backgroundImage: `linear-gradient(90deg, #FBBF24, #D97706, #DC2626)`,
          },
        },
      },
      MuiTextField: {
        styleOverrides: {
          root: {
            "& .MuiOutlinedInput-root": {
              borderRadius: 8,
              "&:hover .MuiOutlinedInput-notchedOutline": {
                borderColor: alpha("#D97706", 0.6),
              },
              "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
                borderColor: "#D97706",
                boxShadow: `0 0 0 3px ${alpha("#D97706", 0.15)}`,
              },
            },
          },
        },
      },
    },
  }),

  // AUTUMN — dying embers, fallen leaves, woodsmoke, deep terracotta dusk
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
          "@keyframes emberDrift": {
            "0%":   { transform: "translateY(0px) rotate(0deg)", opacity: 0.9 },
            "40%":  { transform: "translateY(-12px) rotate(8deg)", opacity: 0.6 },
            "100%": { transform: "translateY(-28px) rotate(-4deg)", opacity: 0 },
          },
          "@keyframes hearthGlow": {
            "0%, 100%": { opacity: 1, filter: "brightness(1)" },
            "30%":      { opacity: 0.85, filter: "brightness(0.88)" },
            "70%":      { opacity: 0.92, filter: "brightness(0.94)" },
          },
          "@keyframes leafSway": {
            "0%, 100%": { transform: "rotate(-3deg) translateX(0px)" },
            "50%":      { transform: "rotate(3deg) translateX(4px)" },
          },
          body: {
            backgroundColor: "#0C0805",
            backgroundImage: [
              // ember bloom — upper left
              `radial-gradient(ellipse 1000px 700px at 10% -5%, rgba(249,115,22,.22), transparent 55%)`,
              // golden canopy — upper right
              `radial-gradient(ellipse 800px 500px at 90% 10%, rgba(234,179,8,.15), transparent 55%)`,
              // deep soot glow — lower center
              `radial-gradient(ellipse 900px 400px at 50% 100%, rgba(180,53,8,.18), transparent 60%)`,
              // woodsmoke noise
              noiseSVG(0.09),
            ].join(","),
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#F97316", 0.4)} transparent`,
            "&::-webkit-scrollbar":       { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 8,
              backgroundColor: alpha("#F97316", 0.32),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
            },
            "::selection": { backgroundColor: alpha("#F97316", 0.4), color: "#F5EDE0" },
          },
          // Utility: hearth-flicker animation
          ".hearth-glow": {
            animation: "hearthGlow 3s ease-in-out infinite",
          },
          // Utility: swaying leaf
          ".leaf-sway": {
            animation: "leafSway 4s ease-in-out infinite",
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            border: `1px solid ${alpha("#F97316", 0.16)}`,
            backgroundImage: "none",
            background: `linear-gradient(160deg, #1C100A 0%, #170D09 100%)`,
            // warm amber top bar
            "&::before": {
              content: '""',
              position: "absolute",
              top: 0, left: "8%", right: "8%",
              height: 1,
              borderRadius: 1,
              background: `linear-gradient(90deg, transparent, ${alpha("#F97316", 0.65)}, ${alpha("#EAB308", 0.5)}, transparent)`,
              pointerEvents: "none",
            },
          },
          elevation1: {
            boxShadow: `0 2px 12px ${alpha("#F97316", 0.12)}, 0 1px 4px ${alpha("#0C0805", 0.5)}`,
          },
          elevation2: {
            boxShadow: `0 4px 24px ${alpha("#F97316", 0.18)}, 0 2px 8px ${alpha("#0C0805", 0.6)}`,
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            textTransform: "none",
            fontWeight: 650,
          },

          text: {
            "&:hover": {
              backgroundColor: alpha("#F97316", 0.1),
            },
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              background: `linear-gradient(135deg, #FDBA74 0%, #F97316 45%, #C2410C 100%)`,
              color: "#fff",
              boxShadow: `0 2px 10px ${alpha("#F97316", 0.45)}`,
              "&:hover": {
                background: `linear-gradient(135deg, #FB923C 0%, #EA6007 45%, #9A3412 100%)`,
                boxShadow: `0 4px 18px ${alpha("#F97316", 0.6)}`,
              },
            },
          },

          {
            props: { variant: "contained", color: "secondary" },
            style: {
              background: `linear-gradient(135deg, #FDE68A 0%, #EAB308 60%, #A16207 100%)`,
              color: "#1C0A00",
              fontWeight: 700,
              boxShadow: `0 2px 10px ${alpha("#EAB308", 0.4)}`,
              "&:hover": {
                boxShadow: `0 4px 18px ${alpha("#EAB308", 0.55)}`,
              },
            },
          },

          {
            props: { variant: "outlined", color: "primary" },
            style: {
              borderColor: alpha("#F97316", 0.5),
              color: "#F97316",
              "&:hover": {
                borderColor: "#F97316",
                backgroundColor: alpha("#F97316", 0.1),
              },
            },
          },
        ],
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            fontWeight: 600,
          },
          colorPrimary: {
            backgroundColor: alpha("#F97316", 0.16),
            color: "#FDBA74",
            border: `1px solid ${alpha("#F97316", 0.3)}`,
          },
          colorSecondary: {
            backgroundColor: alpha("#EAB308", 0.14),
            color: "#FDE68A",
            border: `1px solid ${alpha("#EAB308", 0.28)}`,
          },
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: {
            borderImage: `linear-gradient(90deg, transparent, ${alpha("#F97316", 0.5)}, ${alpha("#EAB308", 0.35)}, transparent) 1`,
          },
        },
      },
      MuiLinearProgress: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            backgroundColor: alpha("#F97316", 0.14),
            height: 5,
          },
          bar: {
            borderRadius: 6,
            backgroundImage: `linear-gradient(90deg, #EAB308, #F97316, #C2410C)`,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          switchBase: {
            "&.Mui-checked": {
              color: "#F97316",
              "& + .MuiSwitch-track": { backgroundColor: alpha("#F97316", 0.5), opacity: 1 },
            },
          },
          track: { backgroundColor: alpha("#F5EDE0", 0.18), opacity: 1 },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            height: 2,
            backgroundImage: `linear-gradient(90deg, #EAB308, #F97316, #C2410C)`,
          },
        },
      },
      MuiTextField: {
        styleOverrides: {
          root: {
            "& .MuiOutlinedInput-root": {
              borderRadius: 6,
              "&:hover .MuiOutlinedInput-notchedOutline": {
                borderColor: alpha("#F97316", 0.55),
              },
              "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
                borderColor: "#F97316",
                boxShadow: `0 0 0 3px ${alpha("#F97316", 0.15)}`,
              },
            },
          },
        },
      },
    },
  }),


  // ── 16. FUTURE ────────────────────────────────
  //
  // «Here's what's gonna happen... A new Theme !»
  // LE VISITEUR DU FUTUR — a homage to François Descraques' web series & film
  //   Colour lore:
  //     #E8720C  — Visitor's coat, scorched amber, Fennec's fur
  //     #F5A623  — Fennec ear-tips & paw pads, small warm hope
  //     #4A90D9  — Brigade armour, temporal-portal flash, cold authority
  //     #5CB85C  — contamination glow, irradiated zones, mission-survived green
  //     #C42B0A  — Brigade alert siren, ember deep-fire, error state
  //     #0D0905  — burnt char — the floor of 2555 Paris
  //     #160E08  — scorched timber — walls still standing
  // ─────────────────────────────────────────────────────────────────────────
  future: createTheme({
    ...base,
    shape: { borderRadius: 6 }, // slightly rounded — survival tech, not sterile Brigade
    typography: {
      fontFamily: sansStack,
      fontSize: 13,
      // Headings: stencil mono — Brigade field documents & Visitor's hand-coded notes
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
      primary:   { main: "#E8720C" }, // scorched amber — Visitor's coat, Fennec's fur
      secondary: { main: "#4A90D9" }, // Brigade steel blue — their armour, portal flash
      info:      { main: "#5CB85C" }, // irradiated green — contamination glow
      success:   { main: "#5CB85C" }, // same: green = mission survived
      warning:   { main: "#F5A623" }, // Fennec amber — ear tips, paw pads, small hope
      error:     { main: "#C42B0A" }, // ember red — Brigade alert, deep fire
      text: {
        primary:   "#E8DED0",               // ash bone — warm rubble dust
        secondary: alpha("#8FA8C0", 0.9),   // Brigade ghost — cold grey-blue smoke
      },
    },
    components: {
      ...base.components,

      // ── Body ────────────────────────────────────────────────────────────
      MuiCssBaseline: {
        styleOverrides: {
          // ── CSS lore tokens ────────────────────────────────────────────
          ":root": {
            // Visitor palette
            "--visitor-coat":    "#E8720C",
            "--visitor-fennec":  "#F5A623",
            "--visitor-ash":     "#E8DED0",
            // Brigade palette
            "--brigade-blue":    "#4A90D9",
            "--brigade-ghost":   "#8FA8C0",
            "--brigade-alert":   "#C42B0A",
            // Environment
            "--future-char":     "#0D0905",
            "--future-timber":   "#160E08",
            "--future-copper":   "#C87941",
            "--future-green":    "#5CB85C",
            // Bracelet charge states
            "--bracelet-off":    alpha("#E8720C", 0.15),
            "--bracelet-on":     "#E8720C",
            "--bracelet-full":   "#F5A623",
          },

          // ── Burned headings — ash print on scorched paper ──────────────
          "h1, h2, h3, h4, h5, h6": {
            textShadow: `0 1px 3px rgba(0,0,0,.7), 0 0 12px ${alpha("#E8720C", 0.12)}`,
          },

          body: {
            backgroundColor: "#0D0905",
            backgroundImage: [
              // Visitor's amber bloom — upper right, his coat catching light
              `radial-gradient(ellipse 1100px 700px at 82% -6%, ${alpha("#E8720C", 0.22)}, transparent 55%)`,
              // Brigade blue — upper left, their searchlights sweeping ruins
              `radial-gradient(ellipse 900px 600px at 4% 8%, ${alpha("#4A90D9", 0.16)}, transparent 50%)`,
              // Ember below — the fires still burn in 2555
              `radial-gradient(ellipse 700px 400px at 50% 102%, ${alpha("#C42B0A", 0.12)}, transparent 52%)`,
              // Contamination pocket — irradiated corner
              `radial-gradient(ellipse 400px 300px at 95% 90%, ${alpha("#5CB85C", 0.06)}, transparent 55%)`,
              // Woodsmoke noise — rubble dust, ash, broken concrete
              noiseSVG(0.13),
            ].join(","),
            scrollbarWidth: "thin",
            scrollbarColor: `${alpha("#E8720C", 0.4)} transparent`,
            "&::-webkit-scrollbar":       { width: 8, height: 8 },
            "&::-webkit-scrollbar-thumb": {
              borderRadius: 6,
              backgroundColor: alpha("#E8720C", 0.32),
              border: "2px solid transparent",
              backgroundClip: "padding-box",
              "&:hover": { backgroundColor: alpha("#E8720C", 0.5) },
            },
            "::selection": { backgroundColor: alpha("#E8720C", 0.42), color: "#E8DED0" },
          },

          // ── Keyframes ──────────────────────────────────────────────────

          // The moment the Visitor steps out of the temporal portal
          "@keyframes temporalArrive": {
            "0%":   { opacity: 0, transform: "scale(0.96) translateY(8px)", filter: "blur(4px) sepia(0.6)" },
            "55%":  { opacity: 1, filter: "blur(0) sepia(0)" },
            "100%": { opacity: 1, transform: "scale(1) translateY(0)", filter: "none" },
          },

          // Fennec heartbeat — warm amber glow on primary interactive elements
          "@keyframes fennecPulse": {
            "0%, 100%": { boxShadow: `0 0 8px ${alpha("#E8720C", 0.2)}` },
            "50%":      { boxShadow: `0 0 22px ${alpha("#E8720C", 0.52)}, 0 0 44px ${alpha("#F5A623", 0.18)}` },
          },

          // Brigade sweep — cold blue scan line / radar ping
          "@keyframes brigadeSweep": {
            "0%, 100%": { boxShadow: `0 0 6px ${alpha("#4A90D9", 0.15)}` },
            "50%":      { boxShadow: `0 0 20px ${alpha("#4A90D9", 0.42)}, 0 0 40px ${alpha("#4A90D9", 0.15)}` },
          },

          // Portal flash — the blue-white burst of temporal displacement
          "@keyframes portalFlash": {
            "0%":   { opacity: 0, transform: "scale(0.6)", filter: "blur(6px) brightness(3)" },
            "15%":  { opacity: 1, transform: "scale(1.04)", filter: "blur(1px) brightness(2.5)" },
            "40%":  { opacity: 0.9, transform: "scale(1)", filter: "blur(0) brightness(1.2)" },
            "100%": { opacity: 0, transform: "scale(1.1)", filter: "blur(4px) brightness(0.8)" },
          },

          // Temporal glitch — the bracelet misfiring, timeline corrupting
          "@keyframes temporalGlitch": {
            "0%, 90%, 100%": { transform: "translate(0,0)", filter: "none", opacity: 1 },
            "92%": { transform: "translate(-2px, 0)",  filter: `hue-rotate(40deg)  saturate(2)`, opacity: 0.9 },
            "94%": { transform: "translate( 2px, 1px)", filter: `hue-rotate(-40deg) saturate(1.8)`, opacity: 0.85 },
            "96%": { transform: "translate(0, -1px)", filter: "none", opacity: 1 },
          },

          // Contamination pulse — irradiated zones, green sickness
          "@keyframes contaminationPulse": {
            "0%, 100%": { boxShadow: `0 0 8px ${alpha("#5CB85C", 0.2)}, inset 0 0 4px ${alpha("#5CB85C", 0.05)}` },
            "50%":      { boxShadow: `0 0 20px ${alpha("#5CB85C", 0.45)}, inset 0 0 10px ${alpha("#5CB85C", 0.12)}` },
          },

          // Bracelet charge — the temporal bracelet powering up
          "@keyframes braceletCharge": {
            "0%":   { backgroundPosition: "-200% 0", opacity: 0.5 },
            "50%":  { opacity: 1 },
            "100%": { backgroundPosition: "200% 0", opacity: 0.7 },
          },

          // ── Utility classes ────────────────────────────────────────────

          // .temporal-arrive — animate an element in as if arriving through a portal
          ".temporal-arrive": {
            animation: "temporalArrive 0.65s cubic-bezier(0.22,1,0.36,1) both",
          },

          // .portal-flash — the moment of temporal displacement
          ".portal-flash": {
            position: "relative",
            "&::before": {
              content: '""',
              position: "absolute",
              inset: -4,
              borderRadius: "inherit",
              background: `radial-gradient(circle, ${alpha("#4A90D9", 0.8)} 0%, ${alpha("#4A90D9", 0)} 70%)`,
              animation: "portalFlash 0.8s ease-out both",
              pointerEvents: "none",
              zIndex: 0,
            },
          },

          // .contaminated — irradiated element, green pulsing border
          ".contaminated": {
            border: `1px solid ${alpha("#5CB85C", 0.45)} !important`,
            animation: "contaminationPulse 2.5s ease-in-out infinite",
            color: "#80D880 !important",
          },

          // .brigade-scan — element under Brigade surveillance, cold blue sweep
          ".brigade-scan": {
            border: `1px solid ${alpha("#4A90D9", 0.4)} !important`,
            animation: "brigadeSweep 2s ease-in-out infinite",
            position: "relative",
            overflow: "hidden",
            "&::after": {
              content: '""',
              position: "absolute",
              top: 0, left: "-100%",
              width: "60%", height: "100%",
              background: `linear-gradient(90deg, transparent, ${alpha("#4A90D9", 0.12)}, transparent)`,
              animation: "braceletCharge 3s linear infinite",
              pointerEvents: "none",
            },
          },

          // .temporal-glitch — bracelet misfire, timeline instability
          ".temporal-glitch": {
            animation: "temporalGlitch 4s ease-in-out infinite",
          },

          // .visitor-briefing — styled like the Visitor's scrawled notes
          // on scorched paper, amber ink on char background
          ".visitor-briefing": {
            fontFamily: monoStack,
            fontSize: "12px !important",
            lineHeight: "1.7 !important",
            backgroundColor: `${alpha("#1C0F08", 0.9)} !important`,
            border: `1px solid ${alpha("#E8720C", 0.35)} !important`,
            borderLeft: `3px solid #E8720C !important`,
            borderRadius: "6px !important",
            padding: "12px 14px !important",
            color: `${alpha("#E8DED0", 0.88)} !important`,
            boxShadow: `inset 0 1px 0 ${alpha("#E8720C", 0.1)}, 0 4px 16px ${alpha("#0D0905", 0.5)}`,
            "&::before": {
              content: '"// VISITOR_NOTE"',
              display: "block",
              fontFamily: monoStack,
              fontSize: "10px",
              color: alpha("#E8720C", 0.6),
              marginBottom: "6px",
              letterSpacing: "0.1em",
            },
          },

          // .fennec — warm amber glow, Fennec is nearby and approves
          ".fennec": {
            animation: "fennecPulse 3.5s ease-in-out infinite",
          },
        },
      },

      // ── Paper — scorched timber surfaces ───────────────────────────────
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
          elevation1: {
            boxShadow: `0 2px 12px ${alpha("#0D0905", 0.6)}, inset 0 1px 0 ${alpha("#E8720C", 0.1)}`,
          },
          elevation2: {
            boxShadow: `0 6px 28px ${alpha("#0D0905", 0.7)}, inset 0 1px 0 ${alpha("#E8720C", 0.12)}`,
          },
        },
      },

      // ── Cards — survival shelter panels ────────────────────────────────
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
            transition: "border-color 180ms ease, box-shadow 180ms ease",
            "&:hover": {
              borderColor: alpha("#E8720C", 0.35),
              boxShadow: `
                0 8px 36px ${alpha("#0D0905", 0.75)},
                0 0 0 1px ${alpha("#E8720C", 0.12)},
                inset 0 1px 0 ${alpha("#E8720C", 0.18)},
                inset 0 -1px 0 ${alpha("#4A90D9", 0.1)}
              `,
            },
            // Visitor coat gradient — firelight streaming across the top
            "&::after": {
              content: '""',
              position: "absolute",
              top: 0, left: 0, right: 0,
              height: 2,
              background: `linear-gradient(90deg, ${alpha("#E8720C", 0.7)}, ${alpha("#F5A623", 0.4)}, ${alpha("#4A90D9", 0.25)})`,
              pointerEvents: "none",
            },
          },
        },
      },

      // ── Dividers — ash line between worlds ─────────────────────────────
      // The gradient runs amber (Visitor) → blue (Brigade): the divide
      // between the two forces that define 2555 Paris.
      MuiDivider: {
        styleOverrides: {
          root: {
            height: 1,
            border: "none",
            backgroundImage: `linear-gradient(90deg, transparent, ${alpha("#E8720C", 0.3)}, ${alpha("#4A90D9", 0.2)}, transparent)`,
          },
        },
      },

      // ── Buttons ─────────────────────────────────────────────────────────
      MuiButton: {
        defaultProps: {
          disableElevation: true,
        },

        styleOverrides: {
          root: {
            borderRadius: 6,
            height: 34,
            paddingInline: 14,
            fontFamily: monoStack,
            letterSpacing: "0.08em",
            transition: "all 150ms ease",
          },

          outlined: {
            border: `1px solid ${alpha("#4A90D9", 0.45)}`,
            backgroundColor: alpha("#4A90D9", 0.06),
            color: "#8FC4E8",
            "&:hover": {
              backgroundColor: alpha("#4A90D9", 0.12),
              borderColor: alpha("#4A90D9", 0.7),
              boxShadow: `0 0 14px ${alpha("#4A90D9", 0.22)}`,
            },
          },

          text: {
            color: alpha("#E8DED0", 0.75),
            "&:hover": {
              backgroundColor: alpha("#E8720C", 0.07),
              color: "#E8DED0",
            },
          },

          sizeSmall: {
            height: 28,
            paddingInline: 10,
            fontSize: 11,
          },

          sizeLarge: {
            height: 42,
            paddingInline: 18,
          },
        },

        variants: [
          {
            props: { variant: "contained", color: "primary" },
            style: {
              backgroundColor: "#E8720C",
              color: "#0D0905",
              fontWeight: 900,
              border: `1px solid ${alpha("#F5A623", 0.4)}`,
              boxShadow: `0 4px 16px ${alpha("#E8720C", 0.4)}`,
              backgroundImage: `linear-gradient(180deg, #F08030, #D4600A)`,
              animation: "fennecPulse 3s ease-in-out infinite",
              "&:hover": {
                backgroundImage: `linear-gradient(180deg, #F59030, #E8720C)`,
                boxShadow: `0 6px 24px ${alpha("#E8720C", 0.58)}`,
                transform: "translateY(-1px)",
              },
              "&:active": {
                transform: "translateY(0)",
              },
            },
          },

          {
            props: { variant: "contained", color: "secondary" },
            style: {
              backgroundColor: "#4A90D9",
              color: "#0D0905",
              fontWeight: 900,
              backgroundImage: `linear-gradient(180deg, #5BA0E9, #3A80C9)`,
              boxShadow: `0 4px 16px ${alpha("#4A90D9", 0.38)}`,
              animation: "brigadeSweep 3s ease-in-out infinite",
              "&:hover": {
                backgroundImage: `linear-gradient(180deg, #6BB0F9, #4A90D9)`,
                boxShadow: `0 6px 24px ${alpha("#4A90D9", 0.5)}`,
                transform: "translateY(-1px)",
              },
            },
          },
        ],
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

      // ── Input fields — survivor terminal ───────────────────────────────
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

      // ── Chips — hazard tags, temporal coordinates, ID badges ───────────
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
          // Filled: active hazard zone — Fennec amber
          filled: {
            backgroundColor: "#E8720C",
            color: "#0D0905",
            border: "none",
          },
          // colorSecondary chip: Brigade clearance tag — steel blue
          colorSecondary: {
            backgroundColor: alpha("#4A90D9", 0.12),
            border: `1px solid ${alpha("#4A90D9", 0.3)}`,
            color: "#8FC4E8",
            "&:hover": { backgroundColor: alpha("#4A90D9", 0.2) },
          },
          // colorSuccess / colorInfo: contamination badge — irradiated green
          colorSuccess: {
            backgroundColor: alpha("#5CB85C", 0.1),
            border: `1px solid ${alpha("#5CB85C", 0.3)}`,
            color: "#80D880",
          },
          colorError: {
            backgroundColor: alpha("#C42B0A", 0.12),
            border: `1px solid ${alpha("#C42B0A", 0.35)}`,
            color: "#FF7060",
          },
        },
      },

      // ── Tabs — timeline selector ────────────────────────────────────────
      // Left tabs: Visitor's amber. The gradient crossing to Brigade blue
      // represents the two timelines in tension.
      MuiTabs: {
        styleOverrides: {
          root: {
            borderBottom: `1px solid ${alpha("#E8720C", 0.15)}`,
          },
          indicator: {
            height: 2,
            backgroundImage: `linear-gradient(90deg, #E8720C, #F5A623, #4A90D9)`,
          },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            fontFamily: monoStack,
            fontWeight: 800,
            fontSize: 11,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: alpha("#E8DED0", 0.5),
            minHeight: 40,
            "&.Mui-selected": { color: "#E8720C" },
            "&:hover": { color: alpha("#E8DED0", 0.85) },
          },
        },
      },

      // ── Tooltips — scrawled wasteland notes ────────────────────────────
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

      // ── Alerts — Brigade communiqué ────────────────────────────────────
      MuiAlert: {
        defaultProps: {
          variant: "outlined",
        },

        styleOverrides: {
          root: {
            borderRadius: 8,
            fontFamily: sansStack,
            fontSize: 12.5,
            backgroundColor: alpha("#0D0905", 0.65),
          },
        },

        variants: [
          {
            props: { variant: "outlined", severity: "error" },
            style: {
              borderColor: alpha("#C42B0A", 0.6),
              backgroundColor: alpha("#C42B0A", 0.07),
              color: "#FF8070",
            },
          },
          {
            props: { variant: "outlined", severity: "warning" },
            style: {
              borderColor: alpha("#F5A623", 0.5),
              backgroundColor: alpha("#F5A623", 0.06),
              color: "#F5A623",
            },
          },
          {
            props: { variant: "outlined", severity: "info" },
            style: {
              borderColor: alpha("#5CB85C", 0.4),
              backgroundColor: alpha("#5CB85C", 0.06),
              color: "#80D880",
            },
          },
          {
            props: { variant: "outlined", severity: "success" },
            style: {
              borderColor: alpha("#5CB85C", 0.4),
              backgroundColor: alpha("#5CB85C", 0.06),
              color: "#80D880",
            },
          },
        ],
      },

      // ── Tables — survivor registry / Brigade dossier ───────────────────
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

      // ── Slider — bracelet temporal coordinate dial ──────────────────────
      MuiSlider: {
        styleOverrides: {
          root: { color: "#E8720C" },
          rail: { backgroundColor: alpha("#E8720C", 0.18) },
          track: {
            backgroundImage: `linear-gradient(90deg, #E8720C, #F5A623)`,
            border: "none",
          },
          // Fennec paw — warm amber thumb
          thumb: {
            backgroundColor: "#F5A623",
            border: `2px solid ${alpha("#E8720C", 0.6)}`,
            boxShadow: `0 0 0 3px ${alpha("#F5A623", 0.15)}, 0 0 10px ${alpha("#F5A623", 0.4)}`,
            "&:hover, &.Mui-active": {
              boxShadow: `0 0 0 5px ${alpha("#F5A623", 0.22)}, 0 0 18px ${alpha("#F5A623", 0.58)}`,
            },
          },
        },
      },

      // ── Switch — Fennec ear toggle ──────────────────────────────────────
      // The little fox twitches an ear when she hears the Brigade coming.
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
          thumb: { boxShadow: "none" },
          track: {
            backgroundColor: alpha("#E8DED0", 0.15),
            opacity: 1,
          },
        },
      },

      // ── Select ──────────────────────────────────────────────────────────
      MuiSelect: {
        defaultProps: { size: "small" },
        styleOverrides: {
          icon: { color: alpha("#E8720C", 0.65) },
        },
      },

      // ── Linear progress — bracelet charge indicator ─────────────────────
      // When the bar is half full, Fennec amber bleeds in from the right —
      // hope alongside the fire.
      MuiLinearProgress: {
        styleOverrides: {
          root: {
            backgroundColor: alpha("#E8720C", 0.15),
            borderRadius: 999,
            height: 5,
          },
          bar: {
            backgroundImage: `linear-gradient(90deg, #C42B0A, #E8720C, #F5A623)`,
            borderRadius: 999,
          },
        },
      },

      // ── Circular progress ───────────────────────────────────────────────
      MuiCircularProgress: {
        styleOverrides: {
          colorPrimary: { color: "#E8720C" },
        },
      },

      // ── Accordion — field report panels ────────────────────────────────
      MuiAccordion: {
        styleOverrides: {
          root: {
            backgroundColor: "#160E08",
            border: `1px solid ${alpha("#E8720C", 0.16)}`,
            borderRadius: "8px !important",
            "&::before": { display: "none" },
            "&.Mui-expanded": {
              borderColor: alpha("#E8720C", 0.28),
              boxShadow: `0 4px 20px ${alpha("#0D0905", 0.5)}`,
            },
          },
        },
      },
      MuiAccordionSummary: {
        styleOverrides: {
          root: {
            fontFamily: monoStack,
            fontWeight: 800,
            fontSize: 12,
            letterSpacing: "0.06em",
            color: alpha("#E8DED0", 0.85),
            "&.Mui-expanded": { color: "#E8720C" },
          },
        },
      },

      // ── Badge — hazard count marker ─────────────────────────────────────
      MuiBadge: {
        styleOverrides: {
          badge: {
            fontFamily: monoStack,
            fontWeight: 900,
            fontSize: 10,
            letterSpacing: "0.05em",
          },
          colorPrimary: {
            backgroundColor: "#E8720C",
            color: "#0D0905",
            boxShadow: `0 0 8px ${alpha("#E8720C", 0.55)}`,
          },
          colorError: {
            backgroundColor: "#C42B0A",
            boxShadow: `0 0 8px ${alpha("#C42B0A", 0.5)}`,
          },
        },
      },
    },
  }),
};