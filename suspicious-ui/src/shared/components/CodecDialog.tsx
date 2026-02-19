// src/shared/components/CodecDialog.tsx
import * as React from "react";
import {
  Dialog,
  DialogProps,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  IconButton,
  Stack,
  Typography,
  useTheme,
} from "@mui/material";
import CloseRounded from "@mui/icons-material/CloseRounded";
import { alpha } from "@mui/material/styles";

type Props = DialogProps & {
  title?: string;
  subtitle?: string;
  onCloseClick?: () => void;
  actions?: React.ReactNode;
};

export function CodecDialog(props: Props) {
  const { title, subtitle, onCloseClick, actions, children, ...dialogProps } = props;
  const theme = useTheme();

  const isMetal = (theme as any)?.palette?.primary?.main?.toLowerCase?.() === "#e1061b"
    || (theme as any)?.palette?.background?.default?.toLowerCase?.() === "#06080b";

  const frameBorder = alpha(theme.palette.text.primary, theme.palette.mode === "dark" ? 0.18 : 0.12);
  const corner = alpha(theme.palette.primary.main, 0.8);

  return (
    <Dialog
      {...dialogProps}
      PaperProps={{
        className: "hud-alertable",
        sx: {
          overflow: "hidden",
          borderRadius: 2,
          border: `1px solid ${frameBorder}`,
          backgroundImage: "none",
          position: "relative",

          // “codec frame” corners
          "&:before, &:after": { content: '""', position: "absolute", inset: 0, pointerEvents: "none" },
          "&:before": {
            backgroundImage: `
              linear-gradient(${corner}, ${corner}),
              linear-gradient(${corner}, ${corner}),
              linear-gradient(${corner}, ${corner}),
              linear-gradient(${corner}, ${corner})
            `,
            backgroundSize: "14px 2px, 2px 14px, 14px 2px, 2px 14px",
            backgroundPosition: "12px 12px, 12px 12px, calc(100% - 12px) 12px, calc(100% - 12px) 12px",
            backgroundRepeat: "no-repeat",
            opacity: isMetal ? 0.9 : 0.6,
          },
          "&:after": {
            // subtle scanlines inside dialog
            backgroundImage: `repeating-linear-gradient(0deg, rgba(255,255,255,.018), rgba(255,255,255,.018) 1px, transparent 1px, transparent 4px)`,
            opacity: theme.palette.mode === "dark" ? 0.35 : 0.18,
            mixBlendMode: "overlay",
          },
        },
      }}
    >
      {(title || subtitle) && (
        <DialogTitle
          sx={{
            py: 1,
            px: 2,
            borderBottom: `1px solid ${alpha(theme.palette.text.primary, 0.12)}`,
            background:
              theme.palette.mode === "dark"
                ? `linear-gradient(180deg, ${alpha(theme.palette.primary.main, 0.18)}, ${alpha(
                    theme.palette.background.paper,
                    0.0
                  )})`
                : undefined,
          }}
        >
          <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={1}>
            <Stack spacing={0.25} sx={{ minWidth: 0 }}>
              {title ? (
                <Typography variant="subtitle1" sx={{ fontWeight: 950 }} noWrap>
                  {title}
                </Typography>
              ) : null}
              {subtitle ? (
                <Typography variant="caption" color="text.secondary" noWrap>
                  {subtitle}
                </Typography>
              ) : null}
            </Stack>

            <Stack direction="row" spacing={1} alignItems="center">
              {/* “signal LED” */}
              <Box
                aria-hidden
                sx={{
                  width: 10,
                  height: 10,
                  borderRadius: 99,
                  bgcolor: theme.palette.info.main,
                  boxShadow: `0 0 0 1px ${alpha(theme.palette.text.primary, 0.18)}, 0 0 18px ${alpha(
                    theme.palette.info.main,
                    0.18
                  )}`,
                }}
              />
              {onCloseClick ? (
                <IconButton size="small" onClick={onCloseClick}>
                  <CloseRounded fontSize="small" />
                </IconButton>
              ) : null}
            </Stack>
          </Stack>
        </DialogTitle>
      )}

      <DialogContent sx={{ px: 2, py: 2 }}>{children}</DialogContent>

      {actions ? (
        <DialogActions
          sx={{
            px: 2,
            py: 1.25,
            borderTop: `1px solid ${alpha(theme.palette.text.primary, 0.12)}`,
            justifyContent: "space-between",
          }}
        >
          {actions}
        </DialogActions>
      ) : null}
    </Dialog>
  );
}
