import { Chip } from "@mui/material";
import { StatusChip } from "@/shared/components/StatusChip";

/** DONE is the normal state: muted. Every other status keeps its colour. */
export function CalmStatusChip({ status, minWidth }: { status: string; minWidth?: number }) {
  if ((status ?? "").toUpperCase() !== "DONE") return <StatusChip status={status} minWidth={minWidth} />;
  return (
    <Chip
      size="small"
      label="DONE"
      variant="outlined"
      sx={{ minWidth, justifyContent: "center", color: "text.secondary", bgcolor: "transparent", borderColor: "divider", fontWeight: 700 }}
    />
  );
}
