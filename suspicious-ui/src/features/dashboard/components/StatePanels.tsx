import * as React from "react";
import { Box, Container, Skeleton } from "@mui/material";

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
