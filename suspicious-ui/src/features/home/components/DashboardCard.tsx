import * as React from "react";
import { Box, CardContent, Divider, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";

import { useThemeMode } from "@/styles/ThemeStore";
import { SoftCard } from "@/features/home/components/SoftCard";

export function DashboardCard(
  props: React.PropsWithChildren<{
    title: string;
    icon?: React.ReactNode;
    right?: React.ReactNode;
    titleBadge?: React.ReactNode;
    sx?: object;
    contentSx?: object;
    className?: string;
  }>
) {
  const { title, icon, right, titleBadge, sx, contentSx, className, children } = props;
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const { capabilities } = useThemeMode();
  const isMetal = capabilities.effects.hasAlertStates;

  const [hovered, setHovered] = React.useState(false);
  const [showExcl, setShowExcl] = React.useState(false);
  const timerRef = React.useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  React.useEffect(() => {
    if (!isMetal || !hovered) {
      clearTimeout(timerRef.current);
      return;
    }

    function schedule() {
      const delay = 600 + Math.random() * 180;
      timerRef.current = setTimeout(() => {
        setShowExcl(true);
        timerRef.current = setTimeout(() => {
          setShowExcl(false);
          schedule();
        }, 1100);
      }, delay);
    }

    schedule();
    return () => {
      clearTimeout(timerRef.current);
      setShowExcl(false);
    };
  }, [isMetal, hovered]);

  return (
    <SoftCard
      sx={sx}
      className={className}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <CardContent sx={{ p: { xs: 1.5, md: 2 }, ...contentSx }}>
        <Stack
          direction="row"
          sx={{ mb: 1, alignItems: "center", justifyContent: "space-between" }}
        >
          <Stack direction="row" spacing={0.9} sx={{ alignItems: "center" }} >
            {icon ? (
              <Box
                sx={{
                  width: 34,
                  height: 34,
                  borderRadius: 2,
                  display: "grid",
                  placeItems: "center",
                  border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
                  background:
                    "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                  "& svg": { fontSize: 18 },
                }}
              >
                {icon}
              </Box>
            ) : null}

            <Typography sx={{ fontWeight: 900, fontSize: 15 }} >
              {title}
            </Typography>
            {titleBadge}
            {showExcl && (
              <Box
                component="span"
                aria-hidden
                sx={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 18,
                  height: 18,
                  borderRadius: "3px",
                  fontSize: 11,
                  fontWeight: 900,
                  fontFamily: '"IBM Plex Mono", monospace',
                  backgroundColor: "var(--mgs-alert, #E1061B)",
                  color: "#fff",
                  ml: 0.75,
                  flexShrink: 0,
                  animation: "exclamation 300ms cubic-bezier(.34,1.56,.64,1) both",
                }}
              >
                !
              </Box>
            )}
          </Stack>

          {right}
        </Stack>

        <Divider sx={{ opacity: 0.25, mb: 1.5 }} />
        {children}
      </CardContent>
    </SoftCard>
  );
}
