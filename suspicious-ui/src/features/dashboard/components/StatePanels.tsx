// file: src/features/dashboard/components/StatePanels.tsx
import * as React from "react";
import { Box, Button, Container, Skeleton, Stack, Typography } from "@mui/material";
import { RefreshOutlined } from "@mui/icons-material";

export function DashboardLoading() {
  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
      <Box sx={{ mb: 2 }}>
        <Skeleton width={180} height={36} />
        <Skeleton width={260} height={20} />
      </Box>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", md: "repeat(3, 1fr)" },
          gap: 2,
        }}
      >
        {Array.from({ length: 3 }).map((_, i) => (
          <Box key={i} sx={{ borderRadius: 3, border: "1px solid", borderColor: "divider", p: 2 }}>
            <Skeleton width={120} height={16} />
            <Skeleton width={90} height={36} />
            <Skeleton width={160} height={14} />
            <Skeleton sx={{ mt: 1.5 }} height={44} />
          </Box>
        ))}
      </Box>

      <Box sx={{ mt: 2, display: "grid", gridTemplateColumns: { xs: "1fr", md: "2fr 1fr" }, gap: 2 }}>
        <Skeleton sx={{ borderRadius: 3 }} height={420} />
        <Skeleton sx={{ borderRadius: 3 }} height={420} />
      </Box>
    </Container>
  );
}

export function DashboardEmpty(props: {
  title: string;
  description: string;
  onRefresh: () => void;
  canAdjust: boolean;
}) {
  return (
    <Box
      sx={{
        borderRadius: 3,
        border: "1px solid",
        borderColor: "divider",
        bgcolor: "background.paper",
        p: 2,
        mb: 2,
      }}
    >
      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ alignItems: { xs: "flex-start", sm: "center" }, justifyContent: "space-between" }} >
        <Box>
          <Typography sx={{ fontWeight: 950 }}>{props.title}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.25 }}>
            {props.description} {props.canAdjust ? "" : "Time/scope controls may be restricted for your role."}
          </Typography>
        </Box>
        <Button variant="outlined" startIcon={<RefreshOutlined />} onClick={props.onRefresh}>
          Refresh
        </Button>
      </Stack>
    </Box>
  );
}
