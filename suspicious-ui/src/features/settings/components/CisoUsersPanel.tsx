import * as React from "react";
import {
  Alert,
  Box,
  Chip,
  CircularProgress,
  Divider,
  InputAdornment,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { SearchOutlined, ShieldOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
import { useQuery } from "@tanstack/react-query";

import { listItems, type CisoUser } from "@/features/settings/api";
import { EmptyList, InnerCard } from "@/features/settings/components/cards";

export function CisoUsersPanel() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const [filter, setFilter] = React.useState("");

  const query = useQuery<CisoUser[]>({
    queryKey: ["settings", "list", "ciso_users"],
    queryFn: () => listItems("ciso_users"),
    retry: false,
  });

  const items = React.useMemo(() => query.data ?? [], [query.data]);
  const filtered = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) =>
      [it.username, it.email, it.function, it.region, it.country, it.gbu, it.scope]
        .filter(Boolean).join(" ").toLowerCase().includes(q)
    );
  }, [items, filter]);

  return (
    <Stack spacing={2}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
        <TextField
          size="small"
          placeholder="Search by username, email, scope, region…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          fullWidth
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start"><SearchOutlined fontSize="small" /></InputAdornment>
              ),
            },
          }}
        />
        <Chip size="small" label={`${filtered.length} / ${items.length}`} variant="outlined" />
      </Stack>

      {query.isLoading ? (
        <Box sx={{ py: 4, display: "grid", placeItems: "center" }}><CircularProgress /></Box>
      ) : query.isError ? (
        <Alert severity="error">Failed to load CISO users.</Alert>
      ) : filtered.length === 0 ? (
        <EmptyList message={filter ? `No users matching "${filter}"` : "No CISO users."} />
      ) : (
        <Stack spacing={1}>
          {filtered.map((user) => (
            <InnerCard key={user.id} hover sx={{ p: 2 }}>
              <Stack spacing={1.25}>
                <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ justifyContent: "space-between", alignItems: { sm: "center" } }} >
                  <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }} >
                    <Box
                      sx={{
                        width: 40,
                        height: 40,
                        borderRadius: 2.5,
                        display: "grid",
                        placeItems: "center",
                        background: alpha(theme.palette.primary.main, 0.1),
                        border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                      }}
                    >
                      <Typography color="primary" sx={{ fontWeight: 950, fontSize: 15 }} >
                        {(user.username?.[0] ?? "?").toUpperCase()}
                      </Typography>
                    </Box>
                    <Box>
                      <Typography sx={{ fontWeight: 950, fontSize: 14 }} >{user.username}</Typography>
                      <Typography variant="caption" color="text.secondary">{user.email || "No email"}</Typography>
                    </Box>
                  </Stack>

                  {user.scope ? (
                    <Chip
                      size="small"
                      icon={<ShieldOutlined />}
                      label={user.scope}
                      variant="outlined"
                      color="primary"
                    />
                  ) : (
                    <Chip size="small" label="No scope" variant="outlined" />
                  )}
                </Stack>

                <Divider sx={{ opacity: isDark ? 0.12 : 0.35 }} />

                <Box
                  sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)", md: "repeat(4, 1fr)" },
                    gap: 1,
                  }}
                >
                  {[
                    ["Function", user.function],
                    ["GBU", user.gbu],
                    ["Country", user.country],
                    ["Region", user.region],
                  ].map(([label, value]) => (
                    <Box key={label}>
                      <Typography variant="caption" color="text.disabled" sx={{ fontWeight: 700, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5 }}>
                        {label}
                      </Typography>
                      <Typography variant="body2" sx={{ fontSize: 13, fontWeight: 700 }}>
                        {value || "—"}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              </Stack>
            </InnerCard>
          ))}
        </Stack>
      )}
    </Stack>
  );
}
