import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Chip,
  Stack,
  Typography,
} from "@mui/material";
import { ExpandMoreOutlined } from "@mui/icons-material";

import type { ObservableGroup, Observable } from "./observableGroup";
import { SourceTable } from "./SourceTable";

const BAND_COLOR: Record<string, "error" | "warning" | "success" | "default"> = {
  Dangerous: "error",
  Suspicious: "warning",
  Safe: "success",
  Inconclusive: "default",
};

const BAND_ORDER = ["Dangerous", "Suspicious", "Safe", "Inconclusive"];

function bandColor(band: string) {
  return BAND_COLOR[band] ?? "default";
}

function worstBand(observables: Observable[]): string {
  const bands = observables
    .map((o) => o.verdict?.band)
    .filter((b): b is string => !!b);
  for (const band of BAND_ORDER) {
    if (bands.includes(band)) return band;
  }
  return "Inconclusive";
}

function flaggedRatio(observable: Observable) {
  const total = observable.sources.length;
  const flagged = observable.sources.filter(
    (s) => s.verdict === "malicious" || s.verdict === "suspicious",
  ).length;
  return { flagged, total };
}

export function ObservableGroupPanel({ group }: { group: ObservableGroup }) {
  const band = worstBand(group.observables);
  const worst = group.observables.find((o) => o.verdict?.band === band);

  const bandCounts = new Map<string, number>();
  for (const o of group.observables) {
    if (o.verdict?.band) {
      bandCounts.set(o.verdict.band, (bandCounts.get(o.verdict.band) ?? 0) + 1);
    }
  }

  return (
    <Box sx={{ px: 2.25, pt: 2, pb: 1 }}>
      <Stack direction="row" spacing={1} sx={{ mb: 1.25, alignItems: "center" }}>
        <Chip
          color={bandColor(band)}
          label={
            worst?.verdict ? `${band} · ${worst.verdict.confidence}%` : band
          }
        />
      </Stack>

      <Stack direction="row" spacing={0.75} sx={{ mb: 1.5, flexWrap: "wrap" }}>
        {BAND_ORDER.filter((b) => bandCounts.has(b)).map((b) => (
          <Chip
            key={b}
            size="small"
            color={bandColor(b)}
            label={`${b} ${bandCounts.get(b)}`}
          />
        ))}
      </Stack>

      <Stack spacing={1}>
        {group.observables.map((observable, i) => {
          const { flagged, total } = flaggedRatio(observable);
          return (
            <Accordion
              key={`${observable.value}-${i}`}
              disableGutters
              sx={{ "&:before": { display: "none" } }}
            >
              <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                <Stack
                  direction="row"
                  spacing={1}
                  sx={{ alignItems: "center", flexWrap: "wrap", width: "100%" }}
                >
                  <Typography sx={{ fontFamily: "monospace", fontWeight: 700 }}>
                    {observable.value}
                  </Typography>
                  {observable.verdict ? (
                    <Chip
                      size="small"
                      color={bandColor(observable.verdict.band)}
                      label={observable.verdict.band}
                    />
                  ) : null}
                  <Typography variant="caption" color="text.secondary">
                    {flagged} / {total} sources flagged this
                  </Typography>
                  {observable.derived_from && (
                    <Chip
                      size="small"
                      variant="outlined"
                      label={`⛓ extracted from ${observable.derived_from.value} via ${observable.derived_from.via_analyzer}`}
                    />
                  )}
                  {observable.escalation_note && (
                    <Typography variant="caption" color="warning.main">
                      {observable.escalation_note}
                    </Typography>
                  )}
                </Stack>
              </AccordionSummary>
              <AccordionDetails>
                <SourceTable sources={observable.sources} />
              </AccordionDetails>
            </Accordion>
          );
        })}
      </Stack>
    </Box>
  );
}
