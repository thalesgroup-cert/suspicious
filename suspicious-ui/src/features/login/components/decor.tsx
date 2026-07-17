import { Box, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { BoltOutlined, HubOutlined, ShieldOutlined } from "@mui/icons-material";
import { motion, useReducedMotion, type Variants } from "framer-motion";

import { COMPANY_NAME } from "@/features/login/config";

const MotionBox = motion(Box);

// ─── Background: drifting mesh gradient + grain + vignette ────────────────
export function Background() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const reduce = useReducedMotion();

  const p = theme.palette.primary.main;
  const s = (theme.palette as any).secondary?.main ?? p;
  const success = theme.palette.success?.main ?? "#22C55E";
  const info = theme.palette.info?.main ?? p;

  const blobs = [
    { color: p,       size: 720, x: "-10%", y: "-20%", dx: 60,  dy: 40,  d: 0  },
    { color: s,       size: 560, x: "75%",  y: "10%",  dx: -50, dy: 60,  d: 4  },
    { color: success, size: 640, x: "50%",  y: "85%",  dx: 40,  dy: -50, d: 8  },
    { color: info,    size: 480, x: "20%",  y: "60%",  dx: -40, dy: -40, d: 12 },
  ];

  return (
    <Box
      aria-hidden
      sx={{
        position: "fixed",
        inset: 0,
        zIndex: 0,
        overflow: "hidden",
        pointerEvents: "none",
        bgcolor: "background.default",
      }}
    >
      {blobs.map((b, i) => (
        <MotionBox
          key={i}
          sx={{
            position: "absolute",
            top: b.y,
            left: b.x,
            width: b.size,
            height: b.size,
            borderRadius: "50%",
            background: `radial-gradient(circle at 50% 50%, ${alpha(
              b.color,
              isDark ? 0.38 : 0.22
            )} 0%, transparent 60%)`,
            filter: "blur(60px)",
            willChange: "transform",
          }}
          animate={
            reduce
              ? undefined
              : {
                  x: [0, b.dx, -b.dx / 2, 0],
                  y: [0, b.dy, -b.dy / 2, 0],
                }
          }
          transition={{
            duration: 24,
            repeat: Infinity,
            ease: "easeInOut",
            delay: b.d,
          }}
        />
      ))}

      <Box
        sx={{
          position: "absolute",
          inset: 0,
          backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='4' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='200' height='200' filter='url(%23n)' opacity='${
            isDark ? ".15" : ".05"
          }'/%3E%3C/svg%3E")`,
          mixBlendMode: isDark ? "overlay" : "multiply",
          opacity: 0.4,
        }}
      />

      <Box
        sx={{
          position: "absolute",
          inset: 0,
          background: isDark
            ? `radial-gradient(ellipse at center, transparent 40%, ${alpha("#000", 0.35)} 100%)`
            : `radial-gradient(ellipse at center, transparent 50%, ${alpha("#000", 0.05)} 100%)`,
        }}
      />
    </Box>
  );
}

// ─── System-health pill ───────────────────────────────────────────────────
export function StatusPill() {
  const theme = useTheme();
  const ok = theme.palette.success.main;
  const reduce = useReducedMotion();

  return (
    <Stack
      direction="row"
      spacing={1}
      sx={{ alignItems: "center" }}
      role="status"
      aria-live="polite"
    >
      <Box sx={{ position: "relative", width: 8, height: 8 }}>
        <Box
          sx={{
            position: "absolute",
            inset: 0,
            borderRadius: "50%",
            bgcolor: ok,
            boxShadow: `0 0 8px ${alpha(ok, 0.7)}`,
          }}
        />
        {!reduce && (
          <MotionBox
            aria-hidden
            sx={{
              position: "absolute",
              inset: 0,
              borderRadius: "50%",
              bgcolor: ok,
            }}
            animate={{ scale: [1, 2.4, 1], opacity: [0.5, 0, 0.5] }}
            transition={{ duration: 2.2, repeat: Infinity, ease: "easeOut" }}
          />
        )}
      </Box>
      <Typography
        variant="caption"
        sx={{
          fontWeight: 600,
          fontSize: 11.5,
          color: "text.secondary",
          letterSpacing: "0.02em",
        }}
      >
        All systems operational
      </Typography>
    </Stack>
  );
}

// ─── Brand stamp ──────────────────────────────────────────────────────────
export function BrandStamp({ size = "lg" }: { size?: "lg" | "sm" }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const p = theme.palette.primary.main;
  const big = size === "lg";

  return (
    <Stack direction="row" spacing={big ? 2 : 1.25} sx={{ alignItems: "center" }}>
      <Box
        component="img"
        src="/icons/suspicious-logo.png"
        alt=""
        aria-hidden
        sx={{
          width: big ? 56 : 32,
          height: big ? 56 : 32,
          objectFit: "contain",
          filter: isDark
            ? `drop-shadow(0 4px 14px ${alpha(p, 0.5)})`
            : `drop-shadow(0 3px 10px ${alpha(p, 0.32)})`,
        }}
      />
      <Box>
        <Typography
          component="span"
          sx={{
            display: "block",
            fontWeight: 950,
            fontSize: big ? 26 : 17,
            lineHeight: 1,
            letterSpacing: "-0.04em",
            color: "text.primary",
          }}
        >
          Suspicious
        </Typography>
        <Typography
          component="span"
          sx={{
            display: "block",
            mt: 0.6,
            fontWeight: 700,
            fontSize: big ? 11 : 9.5,
            letterSpacing: "0.18em",
            textTransform: "uppercase",
            color: alpha(theme.palette.text.secondary, 0.7),
          }}
        >
          {COMPANY_NAME} Phishing Analysis Platform
        </Typography>
      </Box>
    </Stack>
  );
}

// ─── Feature mosaic (desktop only) ────────────────────────────────────────
export function FeatureMosaic({ itemVariants }: { itemVariants: Variants }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const p = theme.palette.primary.main;
  const reduce = useReducedMotion();

  const tiles = [
    {
      icon: <ShieldOutlined sx={{ fontSize: 22 }} />,
      label: "Protected by your IT team",
      detail: "Trusted by the security group.",
    },
    {
      icon: <BoltOutlined sx={{ fontSize: 22 }} />,
      label: "Quick to use",
      detail: "Forward a suspicious email we handle the rest.",
    },
    {
      icon: <HubOutlined sx={{ fontSize: 22 }} />,
      label: "Get an answer back",
      detail: "You'll receive a verdict and clear next steps.",
    },
  ];

  return (
    <Stack spacing={1.5}>
      {tiles.map((t) => (
        <MotionBox
          key={t.label}
          variants={itemVariants}
          whileHover={reduce ? undefined : { x: 4 }}
          transition={{ type: "spring", stiffness: 300, damping: 24 }}
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 1.75,
            p: 1.75,
            borderRadius: 2.5,
            border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.2 : 0.6)}`,
            background: isDark
              ? alpha(theme.palette.background.paper, 0.3)
              : alpha("#fff", 0.5),
            backdropFilter: "blur(8px)",
            position: "relative",
            overflow: "hidden",
            "&::before": {
              content: '""',
              position: "absolute",
              left: 0,
              top: "20%",
              bottom: "20%",
              width: 2,
              borderRadius: 2,
              bgcolor: p,
              opacity: 0.6,
            },
          }}
        >
          <Box
            sx={{
              width: 40,
              height: 40,
              borderRadius: 2,
              flexShrink: 0,
              display: "grid",
              placeItems: "center",
              color: p,
              background: alpha(p, isDark ? 0.15 : 0.1),
              border: `1px solid ${alpha(p, isDark ? 0.25 : 0.2)}`,
            }}
          >
            {t.icon}
          </Box>
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography
              sx={{
                fontWeight: 800,
                fontSize: 14,
                lineHeight: 1.2,
                color: "text.primary",
              }}
            >
              {t.label}
            </Typography>
            <Typography
              sx={{
                mt: 0.5,
                fontSize: 12.5,
                color: "text.secondary",
                fontWeight: 500,
                lineHeight: 1.45,
              }}
            >
              {t.detail}
            </Typography>
          </Box>
        </MotionBox>
      ))}
    </Stack>
  );
}
