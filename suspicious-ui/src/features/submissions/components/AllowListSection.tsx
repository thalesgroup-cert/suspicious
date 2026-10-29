import { Stack, Typography } from "@mui/material";
import { Section } from "@/shared/components/SheetSection";
import { getRiskTone } from "@/shared/lib/scoreUtils";
import type { AnalyzerReportRow } from "@/features/submissions/components/AnalyzerReportCard";

/** Says when analyzer results count as Safe because their target is allow-listed, and what was overridden. */
export function AllowListSection({ reports }: { reports: Pick<AnalyzerReportRow, "id" | "analyzer_name" | "allow_listed" | "pre_allowlist">[] }) {
  const listed = reports.filter((r) => r.allow_listed);
  if (listed.length === 0) return null;
  const overridden = listed.filter((r) => r.pre_allowlist);
  return (
    <Section title="Allow-list">
      <Typography variant="body2">
        {listed.length} of {reports.length} analyzer reports are for allow-listed targets and count as Safe.
      </Typography>
      {overridden.length > 0 ? (
        <Stack component="ul" spacing={0.5} sx={{ m: 0, mt: 1, pl: 2 }}>
          {overridden.map((r) => (
            <Typography component="li" variant="caption" color="text.secondary" key={r.id}>
              {r.analyzer_name}: was {getRiskTone(r.pre_allowlist?.score ?? undefined).label} before the allow-list
            </Typography>
          ))}
        </Stack>
      ) : null}
    </Section>
  );
}
