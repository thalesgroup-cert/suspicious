// src/shared/components/ArtifactAnalyzersAccordion.tsx
import * as React from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Chip,
  Stack,
  Typography,
} from "@mui/material";
import ExpandMoreOutlined from "@mui/icons-material/ExpandMoreOutlined";
import type { AnalyzerGroup } from "@/shared/hooks/detailsNormalize";
import { AnalyzerRows } from "@/shared/components/AnalyzerRows";

function worstColor(groups: AnalyzerGroup[]) {
  // choose a quick visual hint (like old background coloring by level)
  let max = 0;
  for (const g of groups) {
    for (const a of g.analyzers) max = Math.max(max, a.score);
  }
  if (max >= 6) return "rgba(255, 0, 0, .10)";
  if (max >= 3) return "rgba(255, 165, 0, .10)";
  return "rgba(0, 128, 0, .10)";
}

export function ArtifactAnalyzersAccordion({
  groups,
  defaultExpanded = true,
}: {
  groups: AnalyzerGroup[];
  defaultExpanded?: boolean;
}) {
  if (!groups.length) return <Alert severity="info">No analyzers triggered for this submission.</Alert>;

  // group into “sections” (file/hash/url/ip/mail/etc), each section can contain multiple artifacts
  const byKind = new Map<string, AnalyzerGroup[]>();
  for (const g of groups) {
    const k = g.kind;
    const arr = byKind.get(k) ?? [];
    arr.push(g);
    byKind.set(k, arr);
  }

  const kindsInOrder: Array<AnalyzerGroup["kind"]> = [
    "file",
    "attachment",
    "hash",
    "url",
    "ip",
    "mail_header",
    "mail_body",
    "artifact",
    "unknown",
  ];

  return (
    <Box>
      <Stack spacing={1}>
        {kindsInOrder
          .filter((k) => (byKind.get(k) ?? []).length > 0)
          .map((k) => {
            const sectionGroups = byKind.get(k)!;
            const bg = worstColor(sectionGroups);

            return (
              <Accordion
                key={k}
                defaultExpanded={defaultExpanded}
                disableGutters
                sx={{
                  borderRadius: 3,
                  border: "1px solid rgba(255,255,255,.10)",
                  background: bg,
                  "&:before": { display: "none" },
                }}
              >
                <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ width: "100%" }}>
                    <Typography fontWeight={950} sx={{ textTransform: "capitalize" }}>
                      {titleForKind(k)}
                    </Typography>
                    <Chip
                      size="small"
                      label={`${sectionGroups.length} ${sectionGroups.length === 1 ? "item" : "items"}`}
                      variant="outlined"
                      sx={{ fontWeight: 850 }}
                    />
                    <Box sx={{ flex: 1 }} />
                    <Chip
                      size="small"
                      label={`Top score: ${topScore(sectionGroups).toFixed(1)}`}
                      variant="outlined"
                      sx={{ fontWeight: 850 }}
                    />
                  </Stack>
                </AccordionSummary>

                <AccordionDetails>
                  <Stack spacing={1.25}>
                    {sectionGroups.map((g) => (
                      <Box key={g.key}>
                        <Stack spacing={0.5} sx={{ mb: 0.75 }}>
                          <Typography fontWeight={900}>
                            {g.title}
                            {g.subtitle ? " — " : ""}
                            {g.subtitle ? (
                              <Typography component="span" color="text.secondary" fontWeight={700}>
                                {g.subtitle}
                              </Typography>
                            ) : null}
                          </Typography>

                          {g.artifact ? (
                            <Typography variant="body2" color="text.secondary" sx={{ wordBreak: "break-word" }}>
                              {g.artifact}
                            </Typography>
                          ) : null}
                        </Stack>

                        <AnalyzerRows analyzers={g.analyzers} />
                      </Box>
                    ))}
                  </Stack>
                </AccordionDetails>
              </Accordion>
            );
          })}
      </Stack>
    </Box>
  );
}

function titleForKind(kind: AnalyzerGroup["kind"]) {
  switch (kind) {
    case "file":
      return "File analysis";
    case "hash":
      return "Hash analysis";
    case "url":
      return "URL analysis";
    case "ip":
      return "IP analysis";
    case "mail_header":
      return "Mail header analysis";
    case "mail_body":
      return "Mail body analysis";
    case "attachment":
      return "Attachment analysis";
    case "artifact":
      return "Artifact analysis";
    default:
      return "Other analyzers";
  }
}

function topScore(groups: AnalyzerGroup[]) {
  let max = 0;
  for (const g of groups) {
    for (const a of g.analyzers) max = Math.max(max, a.score);
  }
  return max;
}
