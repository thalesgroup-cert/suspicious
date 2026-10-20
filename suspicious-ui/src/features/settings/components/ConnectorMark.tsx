import { Box } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { CONNECTOR_LOGOS } from "../logos/logos";
import { ConnectorLogo } from "./ConnectorLogo";
import type { StatusTone } from "./StatusLabel";
import { useToneColor } from "./useToneColor";

/**
 * The logo tile with a soft glow behind it and, when a tone is given, a small status dot on its corner.
 * Both are decoration (aria-hidden): the status is always written as a word beside it.
 */
export function ConnectorMark({ name, size = 48, tone }: { name: string; size?: number; tone?: StatusTone }) {
  const theme = useTheme();
  const toneColor = useToneColor();
  const glow = CONNECTOR_LOGOS[name]?.accent ?? theme.palette.primary.main;
  const dark = theme.palette.mode === "dark";
  return (
    <Box sx={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
      <Box
        aria-hidden
        data-testid="connector-glow"
        sx={{
          position: "absolute",
          inset: -Math.round(size * 0.22),
          borderRadius: "50%",
          background: `radial-gradient(circle, ${glow} 0%, transparent 70%)`,
          opacity: dark ? 0.32 : 0.22,
          filter: "blur(6px)",
          pointerEvents: "none",
        }}
      />
      <Box sx={{ position: "relative" }}>
        <ConnectorLogo name={name} size={size} />
      </Box>
      {tone && (
        <Box
          aria-hidden
          data-testid="status-ring"
          sx={{
            position: "absolute",
            right: -4,
            bottom: -4,
            width: 14,
            height: 14,
            boxSizing: "border-box",
            borderRadius: "50%",
            bgcolor: toneColor(tone, 3),
            border: `2px solid ${theme.palette.background.paper}`,
          }}
        />
      )}
    </Box>
  );
}
