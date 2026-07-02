import * as React from "react";
import { Box, CardContent, Chip, Stack, Typography } from "@mui/material";
import { CheckCircleOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";

import { SoftCard } from "@/shared/components/SoftCard";

export { SoftCard };

export function ModeSelectorCard(props: {
  active: boolean;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  helper?: string;
  onClick: () => void;
}) {
  const theme = useTheme();

  return (
    <Box
      role="button"
      tabIndex={0}
      onClick={props.onClick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          props.onClick();
        }
      }}
      sx={{
        cursor: "pointer",
        borderRadius: 3,
        p: 2,
        border: `1px solid ${
          props.active
            ? alpha(theme.palette.primary.main, 0.42)
            : alpha(theme.palette.divider, 0.9)
        }`,
        background: props.active
          ? alpha(
              theme.palette.primary.main,
              theme.palette.mode === "dark" ? 0.1 : 0.06
            )
          : "rgba(255,255,255,.02)",
        transition: "all .16s ease",
        "&:hover": {
          borderColor: alpha(theme.palette.primary.main, 0.35),
          background: alpha(
            theme.palette.primary.main,
            theme.palette.mode === "dark" ? 0.08 : 0.045
          ),
        },
      }}
    >
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "flex-start" }} >
        <Box
          sx={{
            width: 42,
            height: 42,
            borderRadius: 2,
            display: "grid",
            placeItems: "center",
            border: "1px solid rgba(255,255,255,.10)",
            background:
              "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
            flexShrink: 0,
          }}
        >
          {props.icon}
        </Box>

        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack
            direction="row"
            spacing={1}
            useFlexGap
            sx={{ alignItems: "center", flexWrap: "wrap" }}
>
            <Typography sx={{ fontWeight: 850 }} >{props.title}</Typography>

            {props.helper ? (
              <Chip
                size="small"
                label={props.helper}
                variant="outlined"
                sx={{ height: 24, "& .MuiChip-label": { px: 1, fontWeight: 700 } }}
              />
            ) : null}

            {props.active ? (
              <Chip
                size="small"
                icon={<CheckCircleOutlined sx={{ fontSize: 16 }} />}
                label="Selected"
                variant="outlined"
                sx={{ height: 24, "& .MuiChip-label": { px: 1, fontWeight: 700 } }}
              />
            ) : null}
          </Stack>

          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {props.subtitle}
          </Typography>
        </Box>
      </Stack>
    </Box>
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
