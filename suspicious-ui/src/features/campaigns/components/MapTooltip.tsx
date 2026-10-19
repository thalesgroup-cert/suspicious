import { Paper, Typography } from "@mui/material";

import type { PcaPoint } from "@/features/campaigns/api";
import { classLabel, formatFullDay } from "@/features/campaigns/utils";

/** What a hovered point is: class, subject, case and day. Shared by the 2D and 3D maps. */
export default function MapTooltip({ point: p }: { point: PcaPoint }) {
  return (
    <Paper variant="outlined" sx={{ px: 1.25, py: 1, maxWidth: 280 }}>
      <Typography variant="subtitle2" component="p">
        {classLabel(p.label)}
      </Typography>
      <Typography variant="body2" sx={{ overflowWrap: "anywhere" }}>
        {p.mail_subject ?? "No subject"}
      </Typography>
      {p.suspicious_case_id ? (
        <Typography variant="caption" color="text.secondary" component="p">
          Case {p.suspicious_case_id}
        </Typography>
      ) : null}
      {p.date ? (
        <Typography variant="caption" color="text.secondary" component="p">
          {formatFullDay(p.date)}
        </Typography>
      ) : null}
    </Paper>
  );
}
