import * as React from "react";
import { Box, Button, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { HomeOutlined, ArrowBackOutlined, SearchOffOutlined } from "@mui/icons-material";
import { useNavigate, useLocation } from "react-router-dom";

type Props = {
  /**
   * When true the component renders as a full-screen page with its own
   * background (used for top-level unmatched routes outside AppLayout).
   * When false (default) it renders inline inside the authenticated shell.
   */
  standalone?: boolean;
};

export default function NotFound({ standalone = false }: Props) {
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const p = theme.palette.primary.main;

  const content = (
    <Stack
      spacing={3}
      sx={{ textAlign: "center",
        maxWidth: 480,
        mx: "auto",
        px: 3,
        py: standalone ? 0 : 8, alignItems: "center" }}
    >
      {/* Icon badge */}
      <Box
        sx={{
          width: 80,
          height: 80,
          borderRadius: 4,
          display: "grid",
          placeItems: "center",
          background: `linear-gradient(135deg, ${alpha(p, isDark ? 0.18 : 0.1)}, ${alpha(p, isDark ? 0.08 : 0.05)})`,
          border: `1px solid ${alpha(p, isDark ? 0.28 : 0.2)}`,
          boxShadow: `0 8px 32px ${alpha(p, isDark ? 0.18 : 0.1)}`,
        }}
      >
        <SearchOffOutlined sx={{ fontSize: 38, color: p, opacity: 0.85 }} />
      </Box>

      {/* Headline */}
      <Stack spacing={0.75}>
        <Typography
          variant="h3"
          sx={{ fontSize: { xs: 40, sm: 56 },
            lineHeight: 1,
            background: isDark
              ? `linear-gradient(135deg, ${theme.palette.text.primary}, ${alpha(theme.palette.text.primary, 0.55)})`
              : `linear-gradient(135deg, ${theme.palette.text.primary}, ${alpha(theme.palette.text.primary, 0.5)})`,
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text", fontWeight: 950, letterSpacing: -0.8 }}
        >
          404
        </Typography>

        <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: -0.3 }} >
          Page not found
        </Typography>

        <Typography variant="body2" color="text.secondary" sx={{ fontSize: 14, lineHeight: 1.65 }}>
          The path{" "}
          <Box
            component="code"
            sx={{
              px: 0.75,
              py: 0.2,
              borderRadius: 1.5,
              fontSize: 13,
              fontFamily: "monospace",
              bgcolor: alpha(theme.palette.text.primary, isDark ? 0.08 : 0.06),
              border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.2 : 0.5)}`,
              color: "text.primary",
            }}
          >
            {location.pathname}
          </Box>{" "}
          doesn't exist or you don't have access to it.
        </Typography>
      </Stack>

      {/* Actions */}
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25}>
        <Button
          variant="contained"
          startIcon={<HomeOutlined />}
          onClick={() => navigate("/", { replace: true })}
          sx={{
            borderRadius: 2.5,
            textTransform: "none",
            fontWeight: 900,
            px: 2.5,
            background: `linear-gradient(135deg, ${p}, ${alpha(p, 0.8)})`,
            boxShadow: `0 4px 16px ${alpha(p, 0.3)}`,
            "&:hover": {
              boxShadow: `0 6px 22px ${alpha(p, 0.42)}`,
              transform: "translateY(-1px)",
            },
            transition: "all 150ms ease",
          }}
        >
          Go to home
        </Button>

        <Button
          variant="outlined"
          startIcon={<ArrowBackOutlined />}
          onClick={() => navigate(-1)}
          sx={{
            borderRadius: 2.5,
            textTransform: "none",
            fontWeight: 800,
            px: 2.5,
            borderColor: alpha(theme.palette.divider, isDark ? 0.35 : 0.8),
            color: "text.primary",
            "&:hover": {
              borderColor: alpha(p, 0.4),
              background: alpha(p, isDark ? 0.06 : 0.04),
              transform: "translateY(-1px)",
            },
            transition: "all 150ms ease",
          }}
        >
          Go back
        </Button>
      </Stack>
    </Stack>
  );

  // Standalone mode: full-screen centred layout with ambient background
  if (standalone) {
    return (
      <Box
        sx={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          bgcolor: "background.default",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Ambient orbs */}
        <Box
          aria-hidden
          sx={{
            position: "absolute",
            inset: 0,
            background: isDark
              ? `radial-gradient(ellipse 700px 500px at 20% 20%, ${alpha(p, 0.12)}, transparent 55%),
                 radial-gradient(ellipse 600px 400px at 80% 70%, ${alpha(theme.palette.error.main, 0.08)}, transparent 55%)`
              : `radial-gradient(ellipse 700px 500px at 20% 20%, ${alpha(p, 0.07)}, transparent 55%),
                 radial-gradient(ellipse 600px 400px at 80% 70%, ${alpha(theme.palette.error.main, 0.05)}, transparent 55%)`,
            pointerEvents: "none",
          }}
        />
        <Box sx={{ position: "relative", zIndex: 1 }}>{content}</Box>
      </Box>
    );
  }

  // Inline mode: renders inside AppLayout, no outer wrapper needed
  return content;
}