import * as React from "react";
import {
  Alert,
  Box,
  Chip,
  CircularProgress,
  InputAdornment,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { SearchOutlined, ShieldOutlined } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";

import { listItems, type CisoUser } from "@/features/settings/api";
import { EmptyList } from "@/features/settings/components/cards";

const hidden = {
  position: "absolute", width: "1px", height: "1px", overflow: "hidden", clip: "rect(0 0 0 0)", whiteSpace: "nowrap",
} as const;

function Scope({ scope }: { scope?: string }) {
  // Text in both branches: the shield chip is decoration, "No scope" is spelled out.
  return scope
    ? <Chip size="small" icon={<ShieldOutlined />} label={scope} variant="outlined" />
    : <Typography variant="body2" color="text.secondary">No scope</Typography>;
}

const NotSet = () => <Typography component="span" variant="body2" color="text.secondary">Not set</Typography>;

function Identity({ user }: { user: CisoUser }) {
  return (
    <>
      <Typography variant="body2" sx={{ fontWeight: 600 }}>{user.username}</Typography>
      <Typography variant="caption" color="text.secondary" sx={{ display: "block", overflowWrap: "anywhere" }}>
        {user.email || "No email"}
      </Typography>
    </>
  );
}

function UserTable({ users }: { users: CisoUser[] }) {
  const columns = ["Function", "Scope", "GBU", "Country", "Region"];
  return (
    <Box sx={{ border: 1, borderColor: "divider", borderRadius: 2, overflowX: "auto" }}>
      <Table size="small">
        <Box component="caption" sx={hidden}>CISO users</Box>
        <TableHead>
          <TableRow>
            <TableCell scope="col">User</TableCell>
            {columns.map((c) => <TableCell key={c} scope="col">{c}</TableCell>)}
          </TableRow>
        </TableHead>
        <TableBody>
          {users.map((u) => (
            <TableRow key={u.id} hover>
              <TableCell sx={{ minWidth: 200 }}><Identity user={u} /></TableCell>
              <TableCell>{u.function || <NotSet />}</TableCell>
              <TableCell><Scope scope={u.scope} /></TableCell>
              <TableCell>{u.gbu || <NotSet />}</TableCell>
              <TableCell>{u.country || <NotSet />}</TableCell>
              <TableCell>{u.region || <NotSet />}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Box>
  );
}

function UserCards({ users }: { users: CisoUser[] }) {
  return (
    <Box component="ul" aria-label="CISO users" sx={{ listStyle: "none", m: 0, p: 0, display: "grid", gap: 1 }}>
      {users.map((u) => (
        <Box
          component="li"
          key={u.id}
          sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: 1.5, display: "grid", gap: 1 }}
        >
          <Box><Identity user={u} /></Box>
          <Box component="dl" sx={{ m: 0, display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 1 }}>
            {/* Scope gets its own full-width row so a long email keeps the whole card width. */}
            <Box sx={{ gridColumn: "1 / -1" }}>
              <Typography component="dt" variant="caption" color="text.secondary">Scope</Typography>
              <Box component="dd" sx={{ m: 0 }}><Scope scope={u.scope} /></Box>
            </Box>
            {([["Function", u.function], ["GBU", u.gbu], ["Country", u.country], ["Region", u.region]] as const).map(([k, v]) => (
              <Box key={k}>
                <Typography component="dt" variant="caption" color="text.secondary">{k}</Typography>
                <Typography component="dd" variant="body2" sx={{ m: 0 }}>{v || <NotSet />}</Typography>
              </Box>
            ))}
          </Box>
        </Box>
      ))}
    </Box>
  );
}

export function CisoUsersPanel() {
  const theme = useTheme();
  const isDesktop = useMediaQuery(theme.breakpoints.up("md"));
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
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
        <TextField
          size="small"
          placeholder="Search by username, email, scope, region…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          fullWidth
          slotProps={{
            htmlInput: { "aria-label": "Search CISO users" },
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
      ) : isDesktop ? (
        <UserTable users={filtered} />
      ) : (
        <UserCards users={filtered} />
      )}
    </Stack>
  );
}
