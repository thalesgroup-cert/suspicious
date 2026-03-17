import { Box, Button, Stack, Typography, CircularProgress } from "@mui/material";
import { Navigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getMe } from "@/api/auth";

export default function NotFound() {
  const { data: me, isLoading } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false
  });

  // While checking auth, show nothing or a loader
  if (isLoading) {
    return (
      <Box sx={{ minHeight: "100vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  // Auto-redirect based on auth state
  if (me) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <Box sx={{ minHeight: "100vh", display: "grid", placeItems: "center", p: 3 }}>
      <Stack spacing={2} alignItems="center">
        <Typography variant="h3" fontWeight={800}>
          404
        </Typography>
        <Typography color="text.secondary">
          Page not found.
        </Typography>
        <Button
          variant="contained"
          onClick={() => window.location.assign("/login")}
        >
          Go to login
        </Button>
      </Stack>
    </Box>
  );
}
