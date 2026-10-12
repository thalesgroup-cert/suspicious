import { Accordion, AccordionDetails, AccordionSummary, Typography } from "@mui/material";
import { ExpandMoreOutlined } from "@mui/icons-material";

import type { InvestigationDetails } from "@/features/investigation/api";
import type { ObservableGroup } from "@/features/investigation/observableGroup";
import { ObservableGroupPanel } from "@/features/investigation/ObservableGroupPanel";
import { AnalyzerEnrichment } from "@/features/investigation/AnalyzerEnrichment";
import { parseEnrichment } from "@/features/investigation/enrichment";
import { AnalyzerGroups } from "@/features/submissions/components/AnalyzerGroups";

type Report = InvestigationDetails["analyzer_reports"][number];

/** The Investigation-only extra: the analyzer's enrichment facts, inside the expanded row's technical details. */
function enrichmentDetails(report: Report) {
  const parsed = report.enrichment ? parseEnrichment(report.enrichment) : null;
  if (!parsed) return null;
  return (
    <Accordion disableGutters
      sx={{ borderRadius: 2, border: 1, borderColor: "divider", bgcolor: "action.hover", "&:before": { display: "none" } }}>
      <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>Enrichment</Typography>
      </AccordionSummary>
      <AccordionDetails onClick={(e) => e.stopPropagation()}>
        <AnalyzerEnrichment enrichment={parsed} />
      </AccordionDetails>
    </Accordion>
  );
}

/** Rendered with key = case id by the drawer, so its expansion state starts fresh for every case and on reopen. */
export function InvestigationAnalysisTab({ reports, observableGroup, isLoading, isError }: {
  reports: Report[];
  observableGroup?: ObservableGroup;
  isLoading: boolean;
  isError: boolean;
}) {
  return (
    <>
      {/* IOC-group cases: the per-observable view first (what each indicator is), then the analyzer runs behind it. */}
      {observableGroup ? <ObservableGroupPanel group={observableGroup} /> : null}
      <AnalyzerGroups reports={reports} isLoading={isLoading} isError={isError} extraDetails={enrichmentDetails} />
    </>
  );
}
