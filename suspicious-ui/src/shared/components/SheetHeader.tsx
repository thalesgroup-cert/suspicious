import type { ReactNode } from "react";
import { Box } from "@mui/material";
import { alpha } from "@mui/material/styles";

/** Sticky header row for page-level side sheets (drawers); stays above scrolling content. */
export function SheetHeader({ children }: { children: ReactNode }) {
  return (
    <Box
      data-testid="sheet-header"
      sx={(theme) => ({
        position: "sticky",
        top: 0,
        zIndex: 1,
        px: 2.25,
        pb: 1.75,
        pt: "calc(env(safe-area-inset-top, 0px) + 14px)",
        borderBottom: `1px solid ${theme.palette.divider}`,
        backgroundColor: theme.palette.background.paper,
        backgroundImage: `linear-gradient(180deg, ${alpha(theme.palette.action.hover, 0.22)} 0%, ${alpha(theme.palette.background.paper, 0)} 100%)`,
      })}
    >
      {children}
    </Box>
  );
}
