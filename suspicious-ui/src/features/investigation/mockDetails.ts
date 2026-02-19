// src/features/investigation/mockDetails.ts

export async function mockInvestigationDetails(caseId: number): Promise<any> {
  // Keep shape flexible: your page reads d.case_infos or d.*
  return {
    case_id: caseId,
    user: `user${(caseId % 24) + 1}@example.com`,
    status: "DONE",
    pub_date: new Date(Date.now() - 3600_000).toISOString(),
    analysis_done: 7,
    case_infos: {
      score: 6.5,
      confidence: 82,
      results: "SUSPICIOUS",
    },
    analyzers: [
      { analyzer_name: "AnalyzerA", status: "DONE", score: 7, confidence: 80, level: "SUSPICIOUS", artifact: "x" },
      { analyzer_name: "AnalyzerB", status: "DONE", score: 2, confidence: 60, level: "SAFE", artifact: "y" },
    ],
    note: "Mock details. Wire this to your real API payload.",
  };
}
