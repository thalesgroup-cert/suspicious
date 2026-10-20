import { Box } from "@mui/material";
import type { ReactNode } from "react";
import type { SxProps, Theme } from "@mui/material/styles";

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
