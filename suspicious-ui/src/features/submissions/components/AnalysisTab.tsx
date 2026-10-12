import { Box } from "@mui/material";
import type { SubmissionAnalyzerReport, UrlArtifact } from "@/features/submissions/api";
import { AnalyzerGroups, Heading } from "@/features/submissions/components/AnalyzerGroups";
import { UrlGroupList } from "@/features/submissions/components/UrlGroupList";

export type AnalysisTabProps = {
  submissionId: number;
  reports: SubmissionAnalyzerReport[];
  urlArtifacts: UrlArtifact[];
  isLoading: boolean;
  isError: boolean;
  /** Nothing ran and nothing reported: the report block is omitted (Task-6 rule). */
  hideReports: boolean;
};

export function AnalysisTab({ submissionId, reports, urlArtifacts, isLoading, isError, hideReports }: AnalysisTabProps) {
  return (
    <>
      {hideReports ? null : <AnalyzerGroups reports={reports} isLoading={isLoading} isError={isError} />}

      {urlArtifacts.length > 0 ? (
        <Box component="section" sx={{ px: 2.25, pt: 2, pb: 1 }}>
          <Box sx={{ mb: 1 }}><Heading title="URLs" count={`${urlArtifacts.length} artifact${urlArtifacts.length === 1 ? "" : "s"}`} /></Box>
          <UrlGroupList submissionId={submissionId} urls={urlArtifacts} />
        </Box>
      ) : null}
    </>
  );
}
