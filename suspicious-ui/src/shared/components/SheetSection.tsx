import * as React from "react";
import { Box, LinearProgress, Typography } from "@mui/material";
import { alpha } from "@mui/material/styles";

/** Building blocks shared by the case sheets (Submissions and Investigation drawers). */

export function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <Typography variant="subtitle2" component="h3" color="text.secondary" sx={{ mb: 1 }}>
      {children}
    </Typography>
  );
}

export function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Box component="section" sx={{ px: 2.25, py: 2 }}>
      <SectionTitle>{title}</SectionTitle>
      {children}
    </Box>
  );
}

export function Stat({ label, value, pct, hex }: { label: string; value: string | null; pct: number; hex?: string }) {
  return (
    <Box>
      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{label}</Typography>
      <Typography variant="h3" component="p" sx={{ my: 0.5 }}>{value ?? "—"}</Typography>
      {value != null ? (
        <LinearProgress
          variant="determinate"
          value={pct}
          aria-label={label}
          // Themes paint bars with their accent gradient; the verdict colour replaces it here.
          sx={hex ? {
            height: 4, borderRadius: 999, bgcolor: alpha(hex, 0.2),
            "& .MuiLinearProgress-bar": { bgcolor: hex, backgroundImage: "none", boxShadow: "none" },
          } : { height: 4, borderRadius: 999 }}
        />
      ) : null}
    </Box>
  );
}
