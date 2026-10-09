import * as React from "react";
import { Box, CardContent, Stack, ToggleButton, ToggleButtonGroup, Typography } from "@mui/material";
import { CheckCircleOutlined } from "@mui/icons-material";
import { alpha } from "@mui/material/styles";

import { SoftCard } from "@/shared/components/SoftCard";

export { SoftCard };

export type ModeOption<T extends string> = {
  value: T;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
};

export function ModeToggle<T extends string>(props: {
  value: T;
  options: ModeOption<T>[];
  onChange: (next: T) => void;
}) {
  return (
    <ToggleButtonGroup
      exclusive
      fullWidth
      aria-label="Submission type"
      value={props.value}
      // null = the active button was clicked again: keep the current mode.
      onChange={(_, next: T | null) => next && props.onChange(next)}
      sx={{
        flexDirection: { xs: "column", md: "row" },
        gap: 1.5,
        "& .MuiToggleButtonGroup-grouped": {
          m: 0,
          borderRadius: 3,
          border: 1,
          borderColor: "divider",
          "&.Mui-selected": {
            borderColor: "primary.main",
            bgcolor: (t) => alpha(t.palette.primary.main, 0.1),
          },
          "&.Mui-selected:hover": {
            bgcolor: (t) => alpha(t.palette.primary.main, 0.16),
          },
        },
        "& .MuiToggleButtonGroup-grouped:not(:first-of-type), & .MuiToggleButtonGroup-grouped:not(:last-of-type)":
          { borderRadius: 3, border: 1, borderColor: "divider" },
        "& .MuiToggleButtonGroup-grouped.Mui-selected:not(:first-of-type), & .MuiToggleButtonGroup-grouped.Mui-selected:not(:last-of-type)":
          { borderColor: "primary.main" },
      }}
    >
      {props.options.map((o) => (
        <ToggleButton
          key={o.value}
          value={o.value}
          sx={{ p: 2, textTransform: "none", color: "text.primary", justifyContent: "flex-start", textAlign: "left" }}
        >
          <Stack direction="row" spacing={1.5} sx={{ alignItems: "flex-start", width: "100%" }}>
            <Box sx={{ display: "grid", placeItems: "center", width: 40, height: 40, flexShrink: 0, color: "primary.main" }}>
              {o.icon}
            </Box>
            <Box sx={{ minWidth: 0, flex: 1 }}>
              <Typography sx={{ fontWeight: 700 }}>{o.title}</Typography>
              <Typography variant="body2" color="text.secondary">
                {o.subtitle}
              </Typography>
            </Box>
            {props.value === o.value ? (
              <CheckCircleOutlined color="primary" aria-hidden sx={{ flexShrink: 0 }} />
            ) : null}
          </Stack>
        </ToggleButton>
      ))}
    </ToggleButtonGroup>
  );
}

export function SectionHeader(props: { title: string; subtitle: string }) {
  return (
    <Stack spacing={0.5}>
      <Typography variant="h5" sx={{ fontWeight: 850, letterSpacing: -0.4 }} >
        {props.title}
      </Typography>
      <Typography color="text.secondary">{props.subtitle}</Typography>
    </Stack>
  );
}

export function SidePanel(
  props: React.PropsWithChildren<{ title: string; icon: React.ReactNode }>
) {
  return (
    <SoftCard>
      <CardContent sx={{ p: 2.25 }}>
        <Stack spacing={1.25}>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
            {props.icon}
            <Typography sx={{ fontWeight: 850 }} >{props.title}</Typography>
          </Stack>
          {props.children}
        </Stack>
      </CardContent>
    </SoftCard>
  );
}
