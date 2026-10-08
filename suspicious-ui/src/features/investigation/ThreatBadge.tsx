import { Chip, Tooltip } from "@mui/material";
import { BugReportOutlined } from "@mui/icons-material";

import type { ThreatClassification } from "./api";

const SOURCE_LABEL: Record<string, string> = {
  ai: "AI mail classifier",
  virustotal: "VirusTotal threat classification",
};

/** What kind of threat the case is (phishing kind, malware family), when known. */
export function ThreatBadge({ value }: { value?: ThreatClassification | null }) {
  if (!value) return null;
  const title = `${value.category} · ${SOURCE_LABEL[value.source] ?? value.source}`;
  return (
    <Tooltip title={title}>
      <Chip
        size="small"
        color="secondary"
        variant="outlined"
        icon={<BugReportOutlined />}
        label={value.label}
        sx={{ fontWeight: 800 }}
      />
    </Tooltip>
  );
}
