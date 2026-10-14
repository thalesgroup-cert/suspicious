import { Box, Stack, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { SoftCard } from "./SoftCard";
import type { ByType, LabelValue } from "@/features/dashboard/api";
import { onCard, plural } from "@/features/dashboard/format";

const LABELS: Record<keyof ByType, string> = {
  MAIL: "Emails",
  FILE: "Files",
  URL: "URLs",
  IP: "IP addresses",
  HASH: "Hashes",
  IOC: "Indicator groups",
  UNKNOWN: "Other",
};

/** Label, count and a thin bar of `value / scale`; the count carries the meaning, the bar only the proportion. */
export function BarList(props: { rows: LabelValue[]; scale: number; ordered?: boolean; wideColumns?: boolean }) {
  const { rows, scale, ordered } = props;
  const theme = useTheme();
  const bar = onCard(theme.palette.primary.main, theme.palette, 3);
  return (
    <Box sx={{ containerType: "inline-size" }}>
      <Box
        component={ordered ? "ol" : "ul"}
        sx={{
          m: 0,
          p: 0,
          listStyle: "none",
          // A long list in a wide panel splits into two columns, so each count stays near its label.
          ...(props.wideColumns ? { "@container (min-width: 640px)": { columns: 2, columnGap: 6 } } : {}),
        }}
      >
        {rows.map((r) => (
          <Box component="li" key={r.label} sx={{ breakInside: "avoid", pb: 1.25, "&:last-child": { pb: 0 } }}>
            <Stack direction="row" spacing={1} sx={{ alignItems: "baseline" }}>
              <Typography variant="body2" sx={{ flex: 1, minWidth: 0, overflowWrap: "anywhere" }}>
                {r.label}
              </Typography>
              <Typography variant="body2" sx={{ fontVariantNumeric: "tabular-nums", fontWeight: 600 }}>
                {r.value.toLocaleString()}
              </Typography>
            </Stack>
            <Box aria-hidden sx={{ mt: 0.5, height: 4, borderRadius: 2, bgcolor: "action.hover" }}>
              <Box
                sx={{ height: "100%", borderRadius: 2, bgcolor: bar, width: `${scale > 0 ? (r.value / scale) * 100 : 0}%` }}
              />
            </Box>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

export default function ByTypePanel({ byType }: { byType: ByType }) {
  const rows = (Object.keys(LABELS) as Array<keyof ByType>)
    .filter((k) => byType[k] > 0)
    .map((k) => ({ label: LABELS[k], value: byType[k] }));
  if (rows.length === 0) return null;
  const total = rows.reduce((a, r) => a + r.value, 0);
  return (
    <SoftCard title="What was reported" caption={`Share of ${plural(total, "report")}`}>
      <BarList rows={rows} scale={total} />
    </SoftCard>
  );
}
