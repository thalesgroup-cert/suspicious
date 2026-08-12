import * as React from "react";
import { Box, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";

import type { SubCategoryProbability } from "@/shared/lib/scoreUtils";

const READABLE_LABELS: Record<string, string> = {
  INTERNAL: "Interne",
  EXTERNAL: "Externe",
  SPAM: "Spam",
  NEWSLETTER: "Newsletter",
  CLASSIC_PHISHING: "Phishing classique",
  WHALING_PHISHING: "Whaling",
  CLONE_PHISHING: "Clone phishing",
  BLACKMAILING_PHISHING: "Chantage",
};

/**
 * Horizontal bar chart for a mail's per-sub-category probabilities.
 *
 * Nominal categorical data (swapping the category order wouldn't change its
 * meaning) - so every bar shares one accent hue rather than a rainbow, per
 * dataviz skill's color-formula. The predicted category (highest probability,
 * data is pre-sorted descending) carries that accent as an emphasis mark;
 * the rest sit in a muted track so the one answer that matters - "what did
 * the model decide, and how sure was it relative to the alternatives" -
 * reads at a glance. Values sit at the bar tip in a text token, never in
 * the bar's own color.
 */
export function SubCategoryBarChart({ data }: { data: SubCategoryProbability[] }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const accent = isDark ? "#3987e5" : "#2a78d6";
  const track = isDark ? "rgba(255,255,255,.07)" : alpha(theme.palette.divider, 0.4);
  const mutedFill = isDark ? "rgba(255,255,255,.18)" : alpha(theme.palette.text.secondary, 0.24);

  return (
    <Stack spacing={0.85}>
      {data.map(({ label, pct }, index) => {
        const isTop = index === 0;
        const width = Math.min(100, Math.max(0, pct));
        return (
          <Stack key={label} direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <Typography
              sx={{
                fontSize: 11,
                width: 118,
                flexShrink: 0,
                fontWeight: isTop ? 800 : 500,
                color: isTop ? "text.primary" : "text.secondary",
              }}
              noWrap
            >
              {READABLE_LABELS[label] ?? label}
            </Typography>
            <Box
              sx={{
                flex: 1,
                height: 14,
                borderRadius: 999,
                background: track,
                position: "relative",
                overflow: "hidden",
              }}
            >
              <Box
                sx={{
                  position: "absolute",
                  inset: 0,
                  width: `${width}%`,
                  borderRadius: 999,
                  background: isTop ? accent : mutedFill,
                  transition: "width .3s ease",
                }}
              />
            </Box>
            <Typography
              sx={{
                fontSize: 11,
                fontWeight: isTop ? 800 : 600,
                width: 42,
                textAlign: "right",
                color: isTop ? "text.primary" : "text.secondary",
                fontVariantNumeric: "tabular-nums",
              }}
            >
              {pct.toFixed(1)}%
            </Typography>
          </Stack>
        );
      })}
    </Stack>
  );
}
