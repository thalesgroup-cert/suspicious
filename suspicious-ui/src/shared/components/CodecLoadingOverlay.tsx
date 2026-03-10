// src/shared/components/CodecLoadingOverlay.tsx
import * as React from "react";
import { Backdrop, Box, Stack, Typography, useTheme } from "@mui/material";
import { alpha, keyframes } from "@mui/material/styles";

type Props = {
  open: boolean;
  title?: string;
  subtitle?: string;
};

export function CodecLoadingOverlay({
  open,
  title = "CODEC",
  subtitle = "Uploading… secure channel established",
}: Props) {
  const theme = useTheme();
  const codecLed = keyframes`
  0%,100% { transform: scale(1); opacity: 0.85; }
  50% { transform: scale(1.22); opacity: 1; }
  `;

  const codecSweep = keyframes`
  0% { transform: translateX(-60%); }
  100% { transform: translateX(60%); }
  `;

  const codecBar = keyframes`
  0%,100% { opacity: .35; transform: scaleY(.55); }
  50% { opacity: 1; transform: scaleY(1.15); }
  `;

  const codecBlink = keyframes`
  0% { opacity: 1; }
  50% { opacity: .3; }
  100% { opacity: 1; }
  `;
  const ink = theme.palette.text.primary;
  const dim = theme.palette.text.secondary;
  const primary = theme.palette.primary.main;
  const paper = theme.palette.background.paper;

  return (
    <Backdrop
      open={open}
      sx={{
        zIndex: (t) => t.zIndex.modal + 2,
        bgcolor: alpha("#000", theme.palette.mode === "dark" ? 0.72 : 0.55),
      }}
    >
      <Box
        className="hud-alertable"
        sx={{
          width: { xs: "92vw", sm: 520 },
          borderRadius: 2,
          border: `1px solid ${alpha(ink, theme.palette.mode === "dark" ? 0.18 : 0.14)}`,
          backgroundColor: alpha(paper, theme.palette.mode === "dark" ? 0.92 : 0.98),
          position: "relative",
          overflow: "hidden",

          // frame corners
          "&:before": {
            content: '""',
            position: "absolute",
            inset: 0,
            pointerEvents: "none",
            backgroundImage: `
              linear-gradient(${alpha(primary, 0.9)}, ${alpha(primary, 0.9)}),
              linear-gradient(${alpha(primary, 0.9)}, ${alpha(primary, 0.9)}),
              linear-gradient(${alpha(primary, 0.9)}, ${alpha(primary, 0.9)}),
              linear-gradient(${alpha(primary, 0.9)}, ${alpha(primary, 0.9)})
            `,
            backgroundSize: "14px 2px, 2px 14px, 14px 2px, 2px 14px",
            backgroundPosition:
              "12px 12px, 12px 12px, calc(100% - 12px) 12px, calc(100% - 12px) 12px",
            backgroundRepeat: "no-repeat",
            opacity: 0.85,
          },

          // scanlines + subtle noise
          "&:after": {
            content: '""',
            position: "absolute",
            inset: 0,
            pointerEvents: "none",
            backgroundImage: `
              repeating-linear-gradient(0deg, ${alpha("#fff", 0.06)}, ${alpha("#fff", 0.06)} 1px, transparent 1px, transparent 4px),
              radial-gradient(900px 380px at 30% 0%, ${alpha(primary, 0.16)}, transparent 60%)
            `,
            mixBlendMode: "overlay",
            opacity: theme.palette.mode === "dark" ? 0.35 : 0.22,
          },
        }}
      >
        {/* Header strip */}
        <Stack
          direction="row"
          alignItems="center"
          justifyContent="space-between"
          sx={{
            px: 2,
            py: 1.25,
            borderBottom: `1px solid ${alpha(ink, 0.12)}`,
            position: "relative",
          }}
        >
          <Stack spacing={0.2} sx={{ minWidth: 0 }}>
            <Typography sx={{ fontWeight: 950, letterSpacing: 0.6 }} noWrap>
              {title}
            </Typography>
            <Typography variant="caption" color="text.secondary" noWrap>
              {subtitle}
            </Typography>
          </Stack>

          {/* “signal LED” */}
          <Box
            aria-hidden
            sx={{
              width: 10,
              height: 10,
              borderRadius: 99,
              bgcolor: theme.palette.info.main,
              boxShadow: `0 0 0 1px ${alpha(ink, 0.18)}, 0 0 18px ${alpha(theme.palette.info.main, 0.28)}`,
              animation: `${codecLed} 950ms ease-in-out infinite`,
              "@keyframes codecLed": {
                "0%, 100%": { transform: "scale(1)", opacity: 0.85 },
                "50%": { transform: "scale(1.22)", opacity: 1 },
              },
            }}
          />
        </Stack>

        {/* Body */}
        <Box sx={{ px: 2, py: 2 }}>
          {/* animated “frequency bars” */}
          <Box
            sx={{
              height: 58,
              borderRadius: 1.5,
              border: `1px solid ${alpha(ink, 0.12)}`,
              backgroundColor: alpha("#000", theme.palette.mode === "dark" ? 0.22 : 0.04),
              overflow: "hidden",
              position: "relative",
            }}
          >
            {/* moving sweep */}
            <Box
              sx={{
                position: "absolute",
                inset: 0,
                backgroundImage: `linear-gradient(90deg,
                  transparent 0%,
                  ${alpha(primary, 0.0)} 30%,
                  ${alpha(primary, 0.25)} 50%,
                  ${alpha(primary, 0.0)} 70%,
                  transparent 100%
                )`,
                transform: "translateX(-60%)",
                animation: `${codecSweep} 1200ms linear infinite`,
                "@keyframes codecSweep": {
                  "0%": { transform: "translateX(-60%)" },
                  "100%": { transform: "translateX(60%)" },
                },
              }}
            />

            {/* bars */}
            <Box
              sx={{
                position: "absolute",
                inset: 0,
                display: "grid",
                gridTemplateColumns: "repeat(20, 1fr)",
                gap: 0.5,
                px: 1,
                py: 1,
              }}
            >
              {Array.from({ length: 20 }).map((_, i) => (
                <Box
                  key={i}
                  sx={{
                    borderRadius: 999,
                    alignSelf: "end",
                    height: `${18 + ((i * 13) % 36)}px`,
                    bgcolor: alpha(primary, 0.26),
                    animation: `${codecBar} 900ms ease-in-out ${i * 45}ms infinite`,
                    "@keyframes codecBar": {
                      "0%, 100%": { opacity: 0.35, transform: "scaleY(0.55)" },
                      "50%": { opacity: 1, transform: "scaleY(1.15)" },
                    },
                  }}
                />
              ))}
            </Box>
          </Box>

          {/* ticks + status line */}
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mt: 1.25 }}>
            <Typography variant="caption" sx={{ color: dim }}>
              CH: 140.85 • ENCRYPT: ON
            </Typography>

            <Typography
              variant="caption"
              sx={{
                color: ink,
                fontWeight: 850,
                letterSpacing: 0.6,
                animation: `${codecBlink} 900ms steps(2,end) infinite`,
                "@keyframes codecBlink": {
                  "0%": { opacity: 1 },
                  "50%": { opacity: 0.3 },
                  "100%": { opacity: 1 },
                },
              }}
            >
              TRANSFERRING
            </Typography>
          </Stack>
        </Box>
      </Box>
    </Backdrop>
  );
}
