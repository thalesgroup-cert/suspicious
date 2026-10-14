import * as React from "react";
import { Stack, Typography } from "@mui/material";

type Props = { icon?: React.ReactNode; title: string; hint?: string; action?: React.ReactNode };

export function EmptyState({ icon, title, hint, action }: Props) {
  return (
    <Stack spacing={0.75} sx={{ height: "100%", alignItems: "center", justifyContent: "center", textAlign: "center", color: "text.secondary", px: 2 }}>
      {icon}
      <Typography variant="body1" sx={{ fontWeight: 650, color: "text.primary" }}>{title}</Typography>
      {hint && <Typography variant="body2">{hint}</Typography>}
      {action}
    </Stack>
  );
}
