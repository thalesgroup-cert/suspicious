import { Box, Divider, Stack, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { SoftCard } from "./SoftCard";
import type { Outcomes } from "@/features/dashboard/api";
import { onCard, percents, plural } from "@/features/dashboard/format";
import { useResultColors } from "@/styles/colorStore";
import { useThemeMode } from "@/styles/ThemeStore";

const ROWS = [
  ["safe", "Safe"],
  ["inconclusive", "Inconclusive"],
  ["suspicious", "Suspicious"],
  ["dangerous", "Dangerous"],
  ["failure", "Failure"],
] as const;

export default function OutcomesPanel(props: { outcomes: Outcomes; inProgress: number; reports: number }) {
  const { outcomes, inProgress, reports } = props;
  const theme = useTheme();
  const result = useResultColors();
  const { effects } = useThemeMode().capabilities;

  const counts = ROWS.map(([k]) => outcomes[k]);
  const finished = counts.reduce((a, b) => a + b, 0);
  const pct = percents(counts);
  // Finished cases whose result is none of the five (allow-listed, mostly): counted, never hidden.
  const other = Math.max(0, reports - inProgress - finished);
  // Failure is an analysis that did not finish, not a verdict: neutral hatching, never a verdict colour.
  const neutral = onCard(theme.palette.text.secondary, theme.palette, 3);
  const hatch = `repeating-linear-gradient(135deg, ${neutral} 0 1.5px, transparent 1.5px 4px)`;
  const fill = (k: (typeof ROWS)[number][0]) =>
    k === "failure"
      ? { backgroundImage: hatch, border: `1px solid ${neutral}` }
      : { backgroundColor: onCard(result[k].main, theme.palette, 3) };

  return (
    <SoftCard title="Outcomes" caption={`${plural(finished, "case")} with a verdict`}>
      {finished === 0 ? (
        <Typography variant="body2" color="text.secondary">
          {other > 0 ? "No cases with an outcome yet" : "No finished cases yet"}
        </Typography>
      ) : (
        <>
          <Box
            role="img"
            aria-label={`Outcomes of ${plural(finished, "case")} with a verdict: ${ROWS.map(([, l], i) => `${l} ${counts[i]}`).join(", ")}`}
            sx={{ display: "flex", gap: "2px", height: 12, borderRadius: 1, overflow: "hidden", mb: 2 }}
          >
            {ROWS.map(([k], i) =>
              counts[i] > 0 ? (
                <Box key={k} sx={{ flexGrow: counts[i], minWidth: 4, boxSizing: "border-box", ...fill(k) }} />
              ) : null
            )}
          </Box>

          {/* Capped width: in a wide panel the counts stay close to their labels. */}
          <Stack component="ul" spacing={0.75} sx={{ m: 0, p: 0, listStyle: "none", maxWidth: 420 }}>
            {ROWS.map(([k, label], i) => (
              <Stack
                key={k}
                component="li"
                direction="row"
                spacing={1}
                className={effects.hasContaminationEffect && k === "dangerous" ? "contaminated" : undefined}
                sx={{ alignItems: "center" }}
              >
                <Box
                  aria-hidden
                  data-outcome-marker={k}
                  sx={{ width: 10, height: 10, borderRadius: 0.5, flexShrink: 0, boxSizing: "border-box", ...fill(k) }}
                />
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

      <Divider sx={{ opacity: 0.25, my: 1.5 }} />
      {other > 0 ? (
        <Typography variant="body2" sx={{ mb: 0.5 }}>
          Allow-listed / other: {other.toLocaleString()} (not counted in the outcomes)
        </Typography>
      ) : null}
      <Typography variant="body2">In progress: {inProgress.toLocaleString()}</Typography>
      <Typography variant="caption" color="text.secondary">
        Reported in this period and still being analysed; not counted in the outcomes.
      </Typography>
    </SoftCard>
  );
}
