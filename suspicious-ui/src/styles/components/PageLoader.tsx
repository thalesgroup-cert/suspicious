
import * as React from "react";
import { Box, Container, Skeleton, Stack, useTheme } from "@mui/material";
import { alpha } from "@mui/material/styles";

export default function PageLoader(_props: { label?: string }) {
  const theme = useTheme();
  const border = `1px solid ${alpha(theme.palette.divider, 0.4)}`;

  return (
    <Container maxWidth="xl" sx={{ py: { xs: 2, md: 3 } }}>
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={2}
        sx={{ mb: 3, alignItems: { md: "center" }, justifyContent: "space-between" }}
      >
        <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
          <Skeleton variant="circular" width={46} height={46} />
          <Stack spacing={0.5}>
            <Skeleton variant="rectangular" width={220} height={28} sx={{ borderRadius: 1 }} />
            <Skeleton variant="rectangular" width={160} height={14} sx={{ borderRadius: 1 }} />
          </Stack>
        </Stack>
        <Stack direction="row" spacing={1}>
          <Skeleton variant="rectangular" width={120} height={36} sx={{ borderRadius: 2 }} />
          <Skeleton variant="rectangular" width={120} height={36} sx={{ borderRadius: 2 }} />
        </Stack>
      </Stack>

      <Stack spacing={2}>
        {[0, 1, 2].map((i) => (
          <Box
            key={i}
            sx={{
              border,
              borderRadius: 3,
              p: 2,
              background: alpha(theme.palette.background.paper, 0.6),
            }}
          >
            <Stack spacing={1.25}>
              <Skeleton variant="rectangular" width="35%" height={20} sx={{ borderRadius: 1 }} />
              <Skeleton variant="rectangular" width="100%" height={14} sx={{ borderRadius: 1 }} />
              <Skeleton variant="rectangular" width="92%" height={14} sx={{ borderRadius: 1 }} />
              <Skeleton variant="rectangular" width="78%" height={14} sx={{ borderRadius: 1 }} />
            </Stack>
          </Box>
        ))}
      </Stack>
    </Container>
  );
}
