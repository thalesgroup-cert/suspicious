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
import { monoStack } from "@/styles/themes";
import { ScreenshotPanel } from "@/shared/components/ScreenshotPanel";
import { RiskChip } from "@/features/submissions/components/AnalyzerReportCard";
import { Heading } from "@/features/submissions/components/AnalyzerGroups";

const BAND_TONE: Record<string, "error" | "warning" | "success"> = {
  Dangerous: "error",
  Suspicious: "warning",
  Safe: "success",
};

const BAND_ORDER = ["Dangerous", "Suspicious", "Safe", "Inconclusive"];

/** Themes restyle Chip's color prop (several paint every colour as the accent), so bands use the risk chip's explicit palette and Inconclusive stays neutral. */
function BandChip({ band, label = band }: { band: string; label?: string }) {
  const tone = BAND_TONE[band];
  return tone ? <RiskChip label={label} tone={tone} /> : <Chip size="small" variant="outlined" label={label} sx={{ flexShrink: 0, color: "text.secondary", borderColor: "divider", bgcolor: "transparent" }} />;
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
    <Box component="section" sx={{ px: 2.25, pt: 2, pb: 1 }}>
      {/* Same heading pattern as the Analysis section below, so the tab reads as two labelled sections. */}
      <Box sx={{ mb: 1 }}>
        <Heading title="Observables" count={`${group.observables.length} observable${group.observables.length === 1 ? "" : "s"}`} />
      </Box>
      {/* One row: the worst band first, then the count per band. */}
      <Stack direction="row" useFlexGap sx={{ mb: 1.5, flexWrap: "wrap", gap: 0.75, alignItems: "center" }}>
        <BandChip band={band} label={worst?.verdict ? `Worst: ${band} · ${worst.verdict.confidence}%` : `Worst: ${band}`} />
        {BAND_ORDER.filter((b) => bandCounts.has(b)).map((b) => (
          <BandChip key={b} band={b} label={`${b} ${bandCounts.get(b)}`} />
        ))}
      </Stack>

      <Stack spacing={1}>
        {group.observables.map((observable, i) => {
          const { flagged, total } = flaggedRatio(observable);
          return (
            <Accordion
              key={`${observable.value}-${i}`}
              disableGutters
              // Each observable sits under the "Observables" h3.
              slotProps={{ heading: { component: "h4" } }}
              sx={{ "&:before": { display: "none" } }}
            >
              <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                <Stack
                  direction="row"
                  spacing={1}
                  sx={{ alignItems: "center", flexWrap: "wrap", width: "100%" }}
                >
                  <Typography variant="body2" sx={{ fontFamily: monoStack, fontWeight: 600, overflowWrap: "anywhere" }}>
                    {observable.value}
                  </Typography>
                  {observable.verdict ? <BandChip band={observable.verdict.band} /> : null}
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
                <Stack spacing={1.5}>
                  {observable.screenshot_url && (
                    <ScreenshotPanel
                      src={observable.screenshot_url}
                      label={`Screenshot: ${observable.value}`}
                    />
                  )}
                  <SourceTable sources={observable.sources} />
                </Stack>
              </AccordionDetails>
            </Accordion>
          );
        })}
      </Stack>
    </Box>
  );
}
