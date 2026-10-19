import type { ReactNode } from "react";
import { Box, Link, Typography } from "@mui/material";

export type Fact = {
  key: string;
  value: ReactNode;
  action?: { label: string; hiddenName: string; onClick(): void };
};

// Screen readers hear "<label> <hiddenName>" instead of a bare "Change" repeated per row.
const hidden = {
  position: "absolute", width: "1px", height: "1px", overflow: "hidden", clip: "rect(0 0 0 0)", whiteSpace: "nowrap",
} as const;

/** Key/value rows as a real description list (GOV.UK summary list pattern). */
export function FactList({ items }: { items: Fact[] }) {
  return (
    <Box component="dl" sx={{ m: 0 }}>
      {items.map((it, i) => (
        <Box
          key={it.key}
          sx={{
            display: "grid",
            gridTemplateColumns: { xs: "1fr", sm: "minmax(120px, 30%) 1fr auto" },
            columnGap: 2,
            rowGap: 0.25,
            py: 1.25,
            borderTop: i === 0 ? 0 : 1,
            borderColor: "divider",
          }}
        >
          <Typography component="dt" variant="body2" color="text.secondary">{it.key}</Typography>
          <Typography component="dd" variant="body2" sx={{ m: 0, minWidth: 0, overflowWrap: "anywhere" }}>{it.value}</Typography>
          {it.action && (
            <Box component="dd" sx={{ m: 0 }}>
              <Link component="button" type="button" variant="body2" underline="always" onClick={it.action.onClick}>
                {it.action.label}
                <Box component="span" sx={hidden}>{" "}{it.action.hiddenName}</Box>
              </Link>
            </Box>
          )}
        </Box>
      ))}
    </Box>
  );
}
