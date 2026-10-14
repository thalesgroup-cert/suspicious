import { Box, Stack, Typography } from "@mui/material";

import { percents, plural } from "@/features/dashboard/format";
import type { ClassificationCounts } from "@/features/campaigns/api";
import { CLASSES, useClassColors } from "@/features/campaigns/utils";

/** Classification mix of the period: one stacked bar, the meaning carried by the text rows below it. */
export default function MixBar({ mix, unclassified }: { mix: ClassificationCounts; unclassified: number }) {
  const colors = useClassColors();
  const counts = CLASSES.map(([k]) => mix[k]);
  const classified = counts.reduce((a, b) => a + b, 0);
  const pct = percents(counts);

  return (
    <>
      {classified === 0 ? (
        <Typography variant="body2" color="text.secondary">
          No classified messages in this period.
        </Typography>
      ) : (
        <>
          <Box
            role="img"
            aria-label={`Classification of ${plural(classified, "message")}: ${CLASSES.map(([, l], i) => `${l} ${counts[i]}`).join(", ")}`}
            sx={{ display: "flex", gap: "2px", height: 12, borderRadius: 1, overflow: "hidden", mb: 2 }}
          >
            {CLASSES.map(([k], i) =>
              counts[i] > 0 ? <Box key={k} sx={{ flexGrow: counts[i], minWidth: 4, bgcolor: colors[k] }} /> : null
            )}
          </Box>
          <Stack component="ul" spacing={0.75} sx={{ m: 0, p: 0, listStyle: "none", maxWidth: 420 }}>
            {CLASSES.map(([k, label], i) => (
              <Stack key={k} component="li" direction="row" spacing={1} sx={{ alignItems: "center" }}>
                <Box aria-hidden sx={{ width: 10, height: 10, borderRadius: 0.5, flexShrink: 0, bgcolor: colors[k] }} />
                <Typography variant="body2" sx={{ flex: 1 }}>
                  {label}
                </Typography>
                <Typography variant="body2" sx={{ fontVariantNumeric: "tabular-nums", fontWeight: 600 }}>
                  {counts[i].toLocaleString()}
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ width: "3.5em", textAlign: "right", fontVariantNumeric: "tabular-nums" }}
                >
                  {counts[i] > 0 && pct[i] === 0 ? "<1" : pct[i]}%
                </Typography>
              </Stack>
            ))}
          </Stack>
        </>
      )}
      {unclassified > 0 ? (
        <Typography variant="body2" sx={{ mt: 1.5 }}>
          Unclassified: {unclassified.toLocaleString()} (not in the percentages)
        </Typography>
      ) : null}
    </>
  );
}
