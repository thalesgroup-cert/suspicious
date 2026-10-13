import { Box, Stack, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { SoftCard } from "./SoftCard";
import type { ByType, LabelValue } from "@/features/dashboard/api";
import { onCard } from "@/features/dashboard/format";

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
export function BarList({ rows, scale, ordered }: { rows: LabelValue[]; scale: number; ordered?: boolean }) {
  const theme = useTheme();
  const bar = onCard(theme.palette.primary.main, theme.palette, 3);
  return (
    <Stack component={ordered ? "ol" : "ul"} spacing={1.25} sx={{ m: 0, p: 0, listStyle: "none" }}>
      {rows.map((r) => (
        <li key={r.label}>
          <Stack direction="row" spacing={1} sx={{ alignItems: "baseline" }}>
            <Typography variant="body2" sx={{ flex: 1, minWidth: 0, overflowWrap: "anywhere" }}>
              {r.label}
            </Typography>
            <Typography variant="body2" sx={{ fontVariantNumeric: "tabular-nums", fontWeight: 600 }}>
              {r.value.toLocaleString()}
            </Typography>
          </Stack>
          <Box aria-hidden sx={{ mt: 0.5, height: 4, borderRadius: 2, bgcolor: "action.hover" }}>
            <Box sx={{ height: "100%", borderRadius: 2, bgcolor: bar, width: `${scale > 0 ? (r.value / scale) * 100 : 0}%` }} />
          </Box>
        </li>
      ))}
    </Stack>
  );
}

export default function ByTypePanel({ byType }: { byType: ByType }) {
  const rows = (Object.keys(LABELS) as Array<keyof ByType>)
    .filter((k) => byType[k] > 0)
    .map((k) => ({ label: LABELS[k], value: byType[k] }));
  if (rows.length === 0) return null;
  const total = rows.reduce((a, r) => a + r.value, 0);
  return (
    <SoftCard title="What was reported" caption={`Share of ${total.toLocaleString()} reports`}>
      <BarList rows={rows} scale={total} />
    </SoftCard>
  );
}
