import { useId, type ReactNode } from "react";
import { Box, Stack, Typography } from "@mui/material";
import type { SxProps, Theme } from "@mui/material/styles";

type Props = {
  title: string;
  purpose?: string;
  toolbar?: ReactNode;
  /** Rendered as a sticky bottom bar; omit it on read-only panels. */
  actions?: ReactNode;
  children?: ReactNode;
};

/** Sticky bottom bar for a panel's primary actions; panels with their own frame (connector detail) reuse it. */
export function ActionBar({ children, sx }: { children: ReactNode; sx?: SxProps<Theme> }) {
  return (
    <Box
      data-panel-actions
      sx={[
        {
          position: "sticky",
          bottom: 0,
          zIndex: 2,
          display: "flex",
          flexWrap: "wrap",
          gap: 1,
          py: 1.5,
          bgcolor: "background.paper",
          borderTop: 1,
          borderColor: "divider",
        },
        ...(Array.isArray(sx) ? sx : [sx]),
      ]}
    >
      {children}
    </Box>
  );
}

/** Shared panel frame: h2 title, one-line purpose, toolbar, content, optional sticky action bar. */
export function PanelSection({ title, purpose, toolbar, actions, children }: Props) {
  const titleId = useId();
  return (
    <Stack component="section" aria-labelledby={titleId} spacing={2}>
      <Box>
        <Typography id={titleId} variant="h6" component="h2">{title}</Typography>
        {purpose && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>{purpose}</Typography>
        )}
      </Box>
      {toolbar && <Box sx={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 1 }}>{toolbar}</Box>}
      {children}
      {actions && <ActionBar>{actions}</ActionBar>}
    </Stack>
  );
}
