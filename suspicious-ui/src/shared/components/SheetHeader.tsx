import type { ReactNode, Ref } from "react";
import { Box, IconButton, Tooltip, type SxProps, type Theme } from "@mui/material";
import { alpha } from "@mui/material/styles";

/**
 * Top colour of the header gradient: a barely-there tint of the text colour. (`alpha()` replaces a colour's alpha, so
 * `alpha(action.hover, 0.22)` was a 22% wash, not 22% of the hover tint.)
 */
// eslint-disable-next-line react-refresh/only-export-components
export const headerTint = (theme: Theme) => alpha(theme.palette.text.primary, 0.04);

/** Sticky header row for page-level side sheets (drawers); stays above scrolling content. */
export function SheetHeader({ children, sx }: { children: ReactNode; sx?: SxProps<Theme> }) {
  return (
    <Box
      data-testid="sheet-header"
      sx={[(theme) => ({
        position: "sticky",
        top: 0,
        zIndex: 1,
        px: 2.25,
        pb: 1.75,
        pt: "calc(env(safe-area-inset-top, 0px) + 14px)",
        borderBottom: `1px solid ${theme.palette.divider}`,
        backgroundColor: theme.palette.background.paper,
        backgroundImage: `linear-gradient(180deg, ${headerTint(theme)} 0%, ${alpha(theme.palette.background.paper, 0)} 100%)`,
      }), ...(Array.isArray(sx) ? sx : [sx])]}
    >
      {children}
    </Box>
  );
}

/** Verdict accent: the one colour cue for the case, a 3px line along the top of the header. */
export function SheetAccent({ hex }: { hex?: string }) {
  return <Box aria-hidden data-testid="verdict-accent" sx={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, bgcolor: hex ?? "divider" }} />;
}

/** Previous/next case arrow; disabled when there is no neighbour (`target` null). */
export function StepButton({ label, target, onNavigate, onStep, btnRef, children }: {
  label: string; onStep: () => void; btnRef: Ref<HTMLButtonElement>; target: number | string | null; onNavigate?: (id: number | string) => void; children: ReactNode;
}) {
  return (
    <Tooltip title={label}>
      {/* span: a disabled button can't host the tooltip's listeners */}
      <span>
        <IconButton ref={btnRef} size="small" aria-label={label} disabled={target == null} onClick={() => { if (target == null) return; onStep(); onNavigate?.(target); }}>
          {children}
        </IconButton>
      </span>
    </Tooltip>
  );
}
