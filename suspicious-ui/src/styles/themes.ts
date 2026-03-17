// src/styles/themes.ts
import { createTheme, alpha, type ThemeOptions } from "@mui/material/styles";

const fontStack = [
  "Inter",
  "system-ui",
  "-apple-system",
  "Segoe UI",
  "Roboto",
  "Arial",
  "sans-serif",
].join(",");

const monoStack = [
  '"IBM Plex Mono"',
  "ui-monospace",
  "SFMono-Regular",
  "Menlo",
  "Monaco",
  "Consolas",
  '"Liberation Mono"',
  '"Courier New"',
  "monospace",
].join(",");

const serifStack = [
  '"Iowan Old Style"',
  '"Palatino Linotype"',
  "Palatino",
  "Georgia",
  "serif",
].join(",");

const roundedStack = [
  '"Nunito"',
  "Inter",
  "system-ui",
  "-apple-system",
  "Segoe UI",
  "Roboto",
  "Arial",
  "sans-serif",
].join(",");

const border = (hex: string, a: number) => `1px solid ${alpha(hex, a)}`;

/** Small background helpers (pure CSS strings). */
const scanlines = (a = 0.035, step = 4) =>
  `repeating-linear-gradient(0deg, rgba(255,255,255,${a}), rgba(255,255,255,${a}) 1px, transparent 1px, transparent ${step}px)`;

const grid = (a = 0.03, step = 18) =>
  `repeating-linear-gradient(0deg, rgba(255,255,255,${a}), rgba(255,255,255,${a}) 1px, transparent 1px, transparent ${step}px),
   repeating-linear-gradient(90deg, rgba(255,255,255,${a}), rgba(255,255,255,${a}) 1px, transparent 1px, transparent ${step}px)`;

const grain = (a = 0.06) =>
  `radial-gradient(1200px 700px at 30% -10%, rgba(255,255,255,${a}), transparent 60%),
   radial-gradient(900px 600px at 90% 10%, rgba(0,0,0,${a}), transparent 55%)`;

/** Tiny inline noise SVG for “paper/film grain” */
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

// ---- base stays as-is ----
const base: ThemeOptions = {
  shape: { borderRadius: 4 },
  typography: {
    fontFamily: fontStack,
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
          backgroundColor: theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.04) : alpha("#0B1220", 0.03),
          transition: "background-color 120ms ease, border-color 120ms ease",
          "&:hover": {
            backgroundColor: theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.06) : alpha("#0B1220", 0.045),
          },
          "&.Mui-focused": {
            backgroundColor: theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.05) : alpha("#0B1220", 0.035),
          },
        }),
        notchedOutline: ({ theme }) => ({
          borderColor: theme.palette.mode === "dark" ? alpha("#E5E7EB", 0.14) : alpha("#0B1220", 0.14),
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
          border: theme.palette.mode === "dark" ? border("#E5E7EB", 0.10) : border("#0B1220", 0.08),
        }),
      },
    },
    MuiCard: {
      styleOverrides: {
        root: ({ theme }) => ({
          borderRadius: 16,
          border: theme.palette.mode === "dark" ? border("#E5E7EB", 0.12) : border("#0B1220", 0.08),
          boxShadow: "none",
        }),
      },
    },
    MuiDivider: {
      styleOverrides: {
        root: ({ theme }) => ({
          borderColor: theme.palette.mode === "dark" ? alpha("#E5E7EB", 0.10) : alpha("#0B1220", 0.10),
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
          backgroundColor: theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.06) : alpha("#0B1220", 0.05),
          border: theme.palette.mode === "dark" ? border("#E5E7EB", 0.12) : border("#0B1220", 0.10),
        }),
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: ({ theme }) => ({
          fontSize: 12,
          padding: "8px 10px",
          borderRadius: 10,
          backgroundColor: theme.palette.mode === "dark" ? alpha("#0B1220", 0.92) : alpha("#0B1220", 0.90),
          border: border("#E5E7EB", theme.palette.mode === "dark" ? 0.12 : 0.10),
        }),
      },
    },
    MuiAlert: {
      defaultProps: { variant: "outlined" },
      styleOverrides: {
        root: ({ theme }) => ({
          borderRadius: 14,
          alignItems: "center",
          backgroundColor: theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.03) : alpha("#0B1220", 0.02),
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
          backgroundColor: theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.03) : alpha("#0B1220", 0.025),
        }),
      },
    },
    MuiTableRow: {
      styleOverrides: {
        root: ({ theme }) => ({
          "&:hover": {
            backgroundColor: theme.palette.mode === "dark" ? alpha("#FFFFFF", 0.04) : alpha("#0B1220", 0.03),
          },
        }),
      },
    },
    MuiLink: {
      defaultProps: { underline: "hover" },
      styleOverrides: { root: ({ theme }) => ({ fontWeight: 600, color: theme.palette.primary.main }) },
    },
  },
};

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
  | "metal";

export function getSeasonalThemeName(date = new Date()): ThemeName {
  const m = date.getMonth(); // 0..11
  if (m === 11 || m <= 1) return "winter"; // Dec-Jan-Feb
  if (m >= 2 && m <= 4) return "spring"; // Mar-Apr-May
  if (m >= 5 && m <= 7) return "summer"; // Jun-Jul-Aug
  if (m >= 8 && m <= 10) return "autumn"; // Sep-Oct-Nov
  return "graphite";
}

// Small helper to keep “variant themes” consistent with your base
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
    ...(opts.shape ? { shape: opts.shape } : null),
    ...(opts.typography ? { typography: { ...base.typography, ...opts.typography } } : null),
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
    components: {
      ...base.components,
      ...(opts.components ?? {}),
    },
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
    ...(opts.shape ? { shape: opts.shape } : null),
    ...(opts.typography ? { typography: { ...base.typography, ...opts.typography } } : null),
    palette: {
      mode: "light",
      background: { default: opts.bg, paper: opts.paper },
      primary: { main: opts.primary },
      secondary: { main: opts.secondary },
      info: { main: opts.info ?? "#2563EB" },
      success: { main: opts.success ?? "#067647" },
      warning: { main: opts.warning ?? "#B54708" },
      error: { main: opts.error ?? "#D92D20" },
      text: { primary: textPrimary, secondary: alpha(textPrimary, 0.70) },
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
      MuiPaper: { styleOverrides: { root: { boxShadow: "none", border: border("#0B1220", 0.08) } } },
      MuiCard: { styleOverrides: { root: { boxShadow: "none", border: border("#0B1220", 0.08) } } },
      ...(opts.components ?? {}),
    },
  });
}

export const themes: Record<ThemeName, ReturnType<typeof createTheme>> = {
  // 1) Midnight = “deep space glass”
  midnight: mkDark({
    bg: "#070A12",
    paper: "#0B1220",
    primary: "#5B8CFF",
    secondary: "#7AA7FF",
    error: "#F97066",
    warning: "#FBBF24",
    success: "#2BD576",
    info: "#60A5FA",
    text: "#E6EAF2",
    shape: { borderRadius: 4 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#070A12",
            backgroundImage: `
              radial-gradient(1200px 800px at 20% -10%, rgba(91,140,255,.22), transparent 60%),
              radial-gradient(1000px 700px at 90% 10%, rgba(122,167,255,.16), transparent 55%),
              radial-gradient(800px 600px at 50% 120%, rgba(45,227,154,.10), transparent 55%),
              ${noiseSVG(0.05)}
            `,
            backgroundBlendMode: "screen, screen, screen, overlay",
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            backgroundImage:
              "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02))",
            backdropFilter: "blur(10px)",
            border: `1px solid ${alpha(theme.palette.text.primary, 0.10)}`,
          }),
        },
      },
      MuiButton: {
        styleOverrides: {
          root: ({ theme }) => ({
            backgroundImage:
              "linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.02))",
            border: `1px solid ${alpha(theme.palette.text.primary, 0.14)}`,
          }),
          containedPrimary: ({ theme }) => ({
            backgroundImage: `linear-gradient(180deg, ${alpha(theme.palette.primary.main, 0.95)}, ${alpha(
              theme.palette.primary.main,
              0.72
            )})`,
          }),
        },
      },
    },
  }),

  // 2) Graphite = “industrial matte”
  graphite: mkDark({
    bg: "#090B0E",
    paper: "#0F141B",
    primary: "#4FB3FF",
    secondary: "#8AA4B2",
    error: "#FF6B6B",
    warning: "#F6C177",
    success: "#3DDC97",
    info: "#60A5FA",
    text: "#E8EDF4",
    shape: { borderRadius: 4 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#090B0E",
            backgroundImage: `${grain(0.10)}, ${noiseSVG(0.06)}`,
            backgroundBlendMode: "overlay, overlay",
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: () => ({
            borderRadius: 12,
            border: "1px solid rgba(229,231,235,.10)",
            backgroundImage: "none",
          }),
        },
      },
      MuiDivider: {
        styleOverrides: {
          root: { borderColor: "rgba(229,231,235,.14)" },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: () => ({
            borderRadius: 8,
            backgroundImage: "none",
          }),
        },
      },
    },
  }),

  // 3) Slate = “blueprint ops”
  slate: mkDark({
    bg: "#0B1020",
    paper: "#101A2E",
    primary: "#6EA8FF",
    secondary: "#74C0FC",
    error: "#FF6B6B",
    warning: "#FBBF24",
    success: "#34D399",
    info: "#60A5FA",
    text: "#E7ECF5",
    shape: { borderRadius: 4 },
    typography: {
      h1: { fontFamily: monoStack, fontWeight: 850, letterSpacing: -0.7 },
      h2: { fontFamily: monoStack, fontWeight: 850 },
      button: { fontFamily: monoStack, letterSpacing: 0.4, fontWeight: 800 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#0B1020",
            backgroundImage: `${grid(0.028, 22)}, radial-gradient(900px 600px at 70% -20%, rgba(110,168,255,.20), transparent 60%)`,
            backgroundBlendMode: "normal, screen",
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: ({ theme }) => ({
            fontFamily: monoStack,
            textTransform: "uppercase",
            letterSpacing: 0.7,
            backgroundColor: alpha("#FFFFFF", 0.03),
            color: alpha(theme.palette.text.primary, 0.80),
          }),
        },
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: () => ({ borderRadius: 8 }),
          notchedOutline: { borderColor: alpha("#E5E7EB", 0.18) },
        },
      },
    },
  }),

  // 4) Light = “clean product”
  light: mkLight({
    bg: "#F6F7FA",
    paper: "#FFFFFF",
    primary: "#1F5EFF",
    secondary: "#0F766E",
    error: "#D92D20",
    warning: "#B54708",
    success: "#067647",
    info: "#2563EB",
    text: "#0B1220",
    shape: { borderRadius: 4 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#F6F7FA",
            backgroundImage: `radial-gradient(900px 500px at 20% 0%, rgba(31,94,255,.10), transparent 60%)`,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: () => ({
            borderRadius: 18,
          }),
        },
      },
    },
  }),

  // 5) Paper = “print / archival”
  paper: mkLight({
    bg: "#F4F2EE",
    paper: "#FFFEFC",
    primary: "#0F4CFF",
    secondary: "#334155",
    error: "#B42318",
    warning: "#8A4B00",
    success: "#05603A",
    info: "#1D4ED8",
    text: "#111827",
    shape: { borderRadius: 4 },
    typography: {
      fontFamily: serifStack,
      h1: { fontFamily: serifStack, fontWeight: 800, letterSpacing: -0.4 },
      h2: { fontFamily: serifStack, fontWeight: 800 },
      button: { fontFamily: serifStack, fontWeight: 800 },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#F4F2EE",
            backgroundImage: `${noiseSVG(0.12)}`,
            backgroundBlendMode: "multiply",
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: () => ({
            backgroundImage: `linear-gradient(180deg, rgba(255,255,255,.75), rgba(255,255,255,.95)), ${noiseSVG(
              0.10
            )}`,
            backgroundBlendMode: "normal, multiply",
          }),
        },
      },
      MuiButton: {
        styleOverrides: {
          root: () => ({
            borderRadius: 6,
            boxShadow: "0 1px 0 rgba(17,24,39,.06)",
          }),
        },
      },
    },
  }),

  // 6) HighContrast = “accessibility / hard terminal”
  high_contrast: mkDark({
    bg: "#000000",
    paper: "#0A0A0A",
    primary: "#FFFFFF",
    secondary: "#FFFFFF",
    info: "#FFFFFF",
    success: "#FFFFFF",
    warning: "#FFFFFF",
    error: "#FFFFFF",
    text: "#FFFFFF",
    shape: { borderRadius: 0 },
    typography: {
      fontFamily: monoStack,
      button: { fontFamily: monoStack, fontWeight: 900, letterSpacing: 1.0, textTransform: "uppercase" },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: { backgroundColor: "#000000" },
          "*": { outlineColor: "#FFFFFF" },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: () => ({
            borderRadius: 0,
            border: "2px solid rgba(255,255,255,.85)",
          }),
        },
      },
      MuiButton: {
        styleOverrides: {
          root: () => ({
            borderRadius: 0,
            border: "2px solid rgba(255,255,255,.85)",
          }),
          containedPrimary: () => ({
            backgroundColor: "#FFFFFF",
            color: "#000000",
          }),
        },
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: () => ({
            borderRadius: 0,
            backgroundColor: "rgba(255,255,255,.06)",
          }),
          notchedOutline: { borderColor: "rgba(255,255,255,.85)", borderWidth: 2 as any },
        },
      },
    },
  }),

  // 7) Sunrise = “warm blobs + soft gloss”
  sunrise: mkLight({
    bg: "#FFF6F2",
    paper: "#FFFFFF",
    primary: "#FF4D2E",
    secondary: "#FFB020",
    text: "#1F2937",
    shape: { borderRadius: 4 },
    typography: { fontFamily: roundedStack },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#FFF6F2",
            backgroundImage: `
              radial-gradient(900px 600px at 15% 10%, rgba(255,77,46,.18), transparent 60%),
              radial-gradient(900px 600px at 85% 20%, rgba(255,176,32,.18), transparent 60%),
              ${noiseSVG(0.04)}
            `,
            backgroundBlendMode: "screen, screen, overlay",
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: () => ({ borderRadius: 999, height: 38 }),
          containedPrimary: ({ theme }) => ({
            backgroundImage: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
          }),
        },
      },
      MuiChip: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 999,
            backgroundImage: `linear-gradient(90deg, ${alpha(theme.palette.primary.main, 0.18)}, ${alpha(
              theme.palette.secondary.main,
              0.18
            )})`,
          }),
        },
      },
    },
  }),

  // 8) Valentine = “candy glass”
  valentine: mkLight({
    bg: "#FFF3F7",
    paper: "#FFFFFF",
    primary: "#E11D48",
    secondary: "#EC4899",
    text: "#1F2937",
    shape: { borderRadius: 4 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#FFF3F7",
            backgroundImage: `
              radial-gradient(900px 500px at 20% 0%, rgba(225,29,72,.14), transparent 60%),
              radial-gradient(900px 500px at 80% 10%, rgba(236,72,153,.14), transparent 60%),
              ${noiseSVG(0.04)}
            `,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: () => ({
            backdropFilter: "blur(10px)",
            backgroundImage: "linear-gradient(180deg, rgba(255,255,255,.85), rgba(255,255,255,.98))",
          }),
        },
      },
      MuiButton: {
        styleOverrides: {
          root: () => ({ borderRadius: 16, height: 38 }),
        },
      },
    },
  }),

  // 9) Cyber = “neon + scanlines”
  cyber: mkDark({
    bg: "#060615",
    paper: "#0B0B22",
    primary: "#00E5FF",
    secondary: "#FF3DFF",
    info: "#22C55E",
    success: "#2DE39A",
    warning: "#FBBF24",
    error: "#FF3B30",
    text: "#EAF2FF",
    shape: { borderRadius: 4 },
    typography: {
      fontFamily: monoStack,
      h1: { fontFamily: monoStack, fontWeight: 900, letterSpacing: -0.8 },
      button: { fontFamily: monoStack, letterSpacing: 1.1, fontWeight: 900, textTransform: "uppercase" },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#060615",
            backgroundImage: `
              radial-gradient(900px 600px at 15% 10%, rgba(0,229,255,.14), transparent 60%),
              radial-gradient(900px 600px at 85% 10%, rgba(255,61,255,.14), transparent 60%),
              ${scanlines(0.03, 4)}
            `,
            backgroundBlendMode: "screen, screen, overlay",
          },
          "@keyframes neonFlicker": {
            "0%, 100%": { filter: "drop-shadow(0 0 0 rgba(0,0,0,0))" },
            "50%": { filter: "drop-shadow(0 0 12px rgba(0,229,255,.18))" },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 6,
            border: `1px solid ${alpha(theme.palette.primary.main, 0.50)}`,
            boxShadow: `0 0 0 1px ${alpha(theme.palette.secondary.main, 0.14)}`,
          }),
          containedPrimary: ({ theme }) => ({
            backgroundImage: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
            color: "#001018",
            animation: "neonFlicker 2200ms ease-in-out infinite",
          }),
        },
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 6,
            backgroundColor: alpha("#FFFFFF", 0.03),
            boxShadow: `inset 0 0 0 1px ${alpha(theme.palette.primary.main, 0.12)}`,
          }),
        },
      },
    },
  }),

  // 10) TheOne = “luxury / gold foil”
  the_one: mkDark({
    bg: "#070707",
    paper: "#101010",
    primary: "#D4AF37",
    secondary: "#EDEDED",
    info: "#7DB2FF",
    success: "#34D399",
    warning: "#F59E0B",
    error: "#EF4444",
    text: "#F5F5F5",
    shape: { borderRadius: 4 },
    typography: {
      h1: { fontWeight: 900, letterSpacing: -0.7 },
      button: { fontWeight: 900, letterSpacing: 0.6, textTransform: "uppercase" },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#070707",
            backgroundImage: `
              radial-gradient(900px 600px at 30% 0%, rgba(212,175,55,.16), transparent 60%),
              ${noiseSVG(0.05)}
            `,
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          containedPrimary: ({ theme }) => ({
            color: "#0A0A0A",
            backgroundImage: `linear-gradient(180deg, ${alpha(theme.palette.primary.main, 0.95)}, ${alpha(
              theme.palette.primary.main,
              0.60
            )})`,
            border: `1px solid ${alpha(theme.palette.primary.main, 0.55)}`,
          }),
          outlined: ({ theme }) => ({
            borderColor: alpha(theme.palette.primary.main, 0.30),
          }),
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            border: `1px solid ${alpha(theme.palette.primary.main, 0.16)}`,
          }),
        },
      },
    },
  }),

  // 11) Winter = “frost”
  winter: mkDark({
    bg: "#050B12",
    paper: "#0B1624",
    primary: "#7DD3FC",
    secondary: "#A5B4FC",
    info: "#38BDF8",
    success: "#34D399",
    warning: "#FBBF24",
    error: "#FB7185",
    text: "#EAF2FF",
    shape: { borderRadius: 4 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#050B12",
            backgroundImage: `
              radial-gradient(900px 600px at 20% 0%, rgba(125,211,252,.16), transparent 60%),
              radial-gradient(900px 600px at 80% 10%, rgba(165,180,252,.14), transparent 60%),
              ${noiseSVG(0.04)}
            `,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            border: `1px solid ${alpha(theme.palette.primary.main, 0.14)}`,
          }),
        },
      },
    },
  }),

  // 12) Spring = “botanical”
  spring: mkLight({
    bg: "#F5FFF8",
    paper: "#FFFFFF",
    primary: "#16A34A",
    secondary: "#22C55E",
    text: "#0B1220",
    shape: { borderRadius: 4 },
    typography: { fontFamily: roundedStack },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#F5FFF8",
            backgroundImage: `
              radial-gradient(900px 600px at 20% 0%, rgba(22,163,74,.14), transparent 60%),
              radial-gradient(900px 600px at 85% 10%, rgba(34,197,94,.12), transparent 60%),
              radial-gradient(circle at 20px 20px, rgba(11,18,32,.05) 2px, transparent 2px)
            `,
            backgroundSize: "auto, auto, 24px 24px",
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: () => ({ borderRadius: 999, height: 38 }),
        },
      },
    },
  }),

  // 13) Summer = “halftone”
  summer: mkLight({
    bg: "#FFFBEA",
    paper: "#FFFFFF",
    primary: "#F59E0B",
    secondary: "#FB7185",
    text: "#0B1220",
    shape: { borderRadius: 4 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#FFFBEA",
            backgroundImage: `
              radial-gradient(900px 600px at 20% 0%, rgba(245,158,11,.16), transparent 60%),
              radial-gradient(900px 600px at 85% 10%, rgba(251,113,133,.14), transparent 60%),
              radial-gradient(circle, rgba(11,18,32,.05) 1px, transparent 1px)
            `,
            backgroundSize: "auto, auto, 10px 10px",
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 999,
            backgroundImage: `linear-gradient(90deg, ${alpha(theme.palette.primary.main, 0.15)}, ${alpha(
              theme.palette.secondary.main,
              0.15
            )})`,
          }),
        },
      },
    },
  }),

  // 14) Autumn = “ember + soot”
  autumn: mkDark({
    bg: "#0B0706",
    paper: "#140D0A",
    primary: "#F97316",
    secondary: "#FBBF24",
    info: "#60A5FA",
    success: "#34D399",
    warning: "#FBBF24",
    error: "#EF4444",
    text: "#F5EFE6",
    shape: { borderRadius: 4 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: "#0B0706",
            backgroundImage: `
              radial-gradient(900px 600px at 25% 0%, rgba(249,115,22,.18), transparent 60%),
              radial-gradient(900px 600px at 80% 10%, rgba(251,191,36,.12), transparent 60%),
              ${noiseSVG(0.07)}
            `,
            backgroundBlendMode: "screen, screen, overlay",
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            border: `1px solid ${alpha(theme.palette.primary.main, 0.14)}`,
          }),
        },
      },
    },
  }),
  metal: createTheme({
    ...base,
    shape: { borderRadius: 4 },
    typography: {
      // on repart du fontStack global
      fontFamily: fontStack,
      fontSize: 13,

      // on redéfinit explicitement (pas de base.typography?.xxx)
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
      background: { default: "#06080B", paper: "#0A0F14" },
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
          ":root": {
            "--hud-alert": "#E1061B",
            "--hud-ink": "#EDEDED",
            "--hud-teal": "#37D6C7",
            "--hud-bg": "#06080B",
            "--hud-paper": "#0A0F14",
          },
          body: {
            backgroundColor: "var(--hud-bg)",
            backgroundImage: `
              radial-gradient(1200px 700px at 50% -10%, rgba(55,214,199,.10), transparent 55%),
              radial-gradient(900px 600px at 10% 10%, rgba(225,6,27,.10), transparent 60%),
              ${scanlines(0.028, 4)},
              ${grid(0.018, 24)}
            `,
            backgroundBlendMode: "screen, screen, overlay, normal",
          },
          "@keyframes hudAlertPulse": {
            "0%": { boxShadow: "0 0 0 rgba(0,0,0,0)" },
            "50%": { boxShadow: "0 0 0 1px rgba(225,6,27,.28), 0 0 24px rgba(225,6,27,.12)" },
            "100%": { boxShadow: "0 0 0 rgba(0,0,0,0)" },
          },
          ".hud-alertable": { transition: "box-shadow 160ms ease" },
          'body[data-alert="on"] .hud-alertable': { animation: "hudAlertPulse 1400ms ease-in-out infinite" },
          "::selection": { backgroundColor: "rgba(225,6,27,.35)" },
        },
      },

      MuiPaper: {
        styleOverrides: {
          root: ({ theme }) => ({
            backgroundImage: "none",
            borderRadius: 10,
            backgroundColor: theme.palette.background.paper,
            border: `1px solid ${alpha("#EDEDED", 0.10)}`,
            position: "relative",
            overflow: "hidden",
            "&:before": {
              content: '""',
              position: "absolute",
              inset: 0,
              pointerEvents: "none",
              backgroundImage: scanlines(0.02, 4),
              opacity: 0.35,
              mixBlendMode: "overlay",
            },
          }),
        },
      },

      MuiOutlinedInput: {
        styleOverrides: {
          root: () => ({
            borderRadius: 6,
            backgroundColor: alpha("#EDEDED", 0.04),
            "&:hover": { backgroundColor: alpha("#EDEDED", 0.06) },
            "&.Mui-focused": { backgroundColor: alpha("#EDEDED", 0.055) },
          }),
          notchedOutline: { borderColor: alpha("#EDEDED", 0.20) },
        },
      },

      MuiButton: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 6,
            height: 36,
            paddingInline: 14,
            border: `1px solid ${alpha("#EDEDED", 0.20)}`,
            backgroundImage: `linear-gradient(180deg, ${alpha("#EDEDED", 0.06)}, ${alpha("#EDEDED", 0.02)})`,
          }),
          containedPrimary: ({ theme }) => ({
            borderColor: alpha(theme.palette.primary.main, 0.65),
            backgroundImage: `linear-gradient(180deg, ${alpha(theme.palette.primary.main, 0.92)}, ${alpha(
              theme.palette.primary.main,
              0.70
            )})`,
            color: "#FFFFFF",
            "&:active": { transform: "translateY(1px)" },
          }),
        },
      },

      MuiChip: {
        styleOverrides: {
          root: () => ({
            borderRadius: 6,
            height: 24,
            fontWeight: 900,
            letterSpacing: 0.8,
            textTransform: "uppercase",
          }),
        },
      },

      MuiTableCell: {
        styleOverrides: {
          head: ({ theme }) => ({
            fontFamily: monoStack,
            fontSize: 11.5,
            letterSpacing: 0.9,
            textTransform: "uppercase",
            color: alpha(theme.palette.text.primary, 0.78),
          }),
        },
      },
    },
  }),
}