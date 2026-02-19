import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Grid,
  IconButton,
  InputAdornment,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import {
  AddOutlined,
  DeleteOutline,
  FileUploadOutlined,
  RefreshOutlined,
  SearchOutlined,
  SettingsOutlined,
  BlockOutlined,
  CheckCircleOutline,
  CampaignOutlined,
  InsertDriveFileOutlined,
  ExtensionOutlined,
  GroupsOutlined,
  MailOutline,
  TuneOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getMe, type Me } from "@/api/auth";
import {
  addFromFile,
  addItems,
  getFeederStatus,
  listAnalyzers,
  listItems,
  removeItem,
  setFeederStatus,
  updateAnalyzerWeight,
  type Analyzer,
  type ListItem,
  type SettingsSection,
} from "@/features/settings/api";
import { mockAnalyzers, mockFeeder, mockList } from "@/features/settings/mock";

type SectionMeta = {
  key: SettingsSection;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  kind: "list" | "toggle" | "scoring";
};

const SECTIONS: SectionMeta[] = [
  {
    key: "domains_allow",
    title: "Domains AllowList",
    subtitle: "Allow known benign domains (reduce noise).",
    icon: <CheckCircleOutline />,
    kind: "list",
  },
  {
    key: "domains_deny",
    title: "Domains DenyList",
    subtitle: "Block known malicious domains (fast detection).",
    icon: <BlockOutlined />,
    kind: "list",
  },
  {
    key: "campaign_domains_allow",
    title: "Campaign Domains AllowList",
    subtitle: "Allow internal campaign / newsletter domains.",
    icon: <CampaignOutlined />,
    kind: "list",
  },
  {
    key: "emails_files_allow",
    title: "Emails / Files AllowList",
    subtitle: "Allow specific file hashes or email artifacts.",
    icon: <InsertDriveFileOutlined />,
    kind: "list",
  },
  {
    key: "filetypes_allow",
    title: "Filetypes AllowList",
    subtitle: "Allow known safe file extensions.",
    icon: <ExtensionOutlined />,
    kind: "list",
  },
  {
    key: "ciso_users",
    title: "CISO Users",
    subtitle: "Manage CISO identities (scoped dashboards).",
    icon: <GroupsOutlined />,
    kind: "list",
  },
  {
    key: "email_feeder",
    title: "Email Settings",
    subtitle: "Enable/disable email feeder service.",
    icon: <MailOutline />,
    kind: "toggle",
  },
  {
    key: "scoring",
    title: "Analysis Scoring",
    subtitle: "Tune analyzer weights for risk scoring.",
    icon: <TuneOutlined />,
    kind: "scoring",
  },
];

function parseMulti(input: string) {
  return input
    .split(/[\n,; ]+/g)
    .map((s) => s.trim())
    .filter(Boolean);
}

function SectionCard(props: React.PropsWithChildren<{ title: string; subtitle: string; right?: React.ReactNode }>) {
  return (
    <Card
      sx={{
        borderRadius: 4,
        border: "1px solid rgba(255,255,255,.10)",
        background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
      }}
    >
      <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
        <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} justifyContent="space-between">
          <Box>
            <Typography variant="h6" fontWeight={950} letterSpacing={-0.2}>
              {props.title}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {props.subtitle}
            </Typography>
          </Box>
          {props.right}
        </Stack>
        <Divider sx={{ my: 2, opacity: 0.25 }} />
        {props.children}
      </CardContent>
    </Card>
  );
}

function ListManager(props: {
  section: SettingsSection;
  placeholder: string;
  fileAccept: string;
}) {
  const qc = useQueryClient();
  const useMock = import.meta.env.VITE_USE_MOCK_SETTINGS === "true";

  const [input, setInput] = React.useState("");
  const [filter, setFilter] = React.useState("");

  const listQuery = useQuery<ListItem[]>({
    queryKey: ["settings", "list", props.section, useMock],
    queryFn: async () => (useMock ? mockList(props.section) : listItems(props.section)),
    retry: false,
  });

  const addMutation = useMutation({
    mutationFn: async (values: string[]) => {
      if (useMock) return;
      return addItems(props.section, values);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings", "list", props.section] }),
  });

  const removeMutation = useMutation({
    mutationFn: async (id: string) => {
      if (useMock) return;
      return removeItem(props.section, id);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings", "list", props.section] }),
  });

  const importMutation = useMutation({
    mutationFn: async (file: File) => {
      if (useMock) return;
      return addFromFile(props.section, file);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings", "list", props.section] }),
  });

  const items = (listQuery.data ?? []).filter((it) =>
    filter ? it.value.toLowerCase().includes(filter.toLowerCase()) : true
  );

  return (
    <Stack spacing={2}>
      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <TextField
            label="Add values"
            placeholder={props.placeholder}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            helperText="Tip: paste multiple values separated by spaces, commas, or new lines."
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    aria-label="Add"
                    onClick={() => {
                      const values = parseMulti(input);
                      if (!values.length) return;
                      addMutation.mutate(values);
                      setInput("");
                    }}
                  >
                    <AddOutlined />
                  </IconButton>
                </InputAdornment>
              ),
            }}
            fullWidth
          />
        </Grid>

        <Grid item xs={12} md={6}>
          <TextField
            label="Search"
            placeholder="Filter list…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchOutlined fontSize="small" />
                </InputAdornment>
              ),
            }}
            fullWidth
          />
        </Grid>

        <Grid item xs={12}>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25} alignItems="center">
            <Button
              variant="outlined"
              component="label"
              startIcon={<FileUploadOutlined />}
              sx={{ borderRadius: 3, textTransform: "none", fontWeight: 900 }}
            >
              Import from file
              <input
                hidden
                type="file"
                accept={props.fileAccept}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) importMutation.mutate(f);
                  e.currentTarget.value = "";
                }}
              />
            </Button>

            <Chip
              size="small"
              label={`${items.length} item(s)`}
              variant="outlined"
              sx={{ ml: { sm: "auto" } }}
            />
          </Stack>
        </Grid>
      </Grid>

      {listQuery.isLoading ? (
        <Box sx={{ display: "grid", placeItems: "center", py: 4 }}>
          <CircularProgress />
        </Box>
      ) : listQuery.isError ? (
        <Alert severity="error">Failed to load list (API route / permissions).</Alert>
      ) : (
        <Card
          sx={{
            borderRadius: 3,
            border: "1px solid rgba(255,255,255,.10)",
            background: "rgba(255,255,255,.03)",
          }}
        >
          <CardContent sx={{ p: 1.25 }}>
            {items.length ? (
              <Stack spacing={1}>
                {items.map((it) => (
                  <Stack
                    key={it.id}
                    direction="row"
                    alignItems="center"
                    justifyContent="space-between"
                    sx={{
                      borderRadius: 2.5,
                      border: "1px solid rgba(255,255,255,.08)",
                      px: 1.25,
                      py: 0.9,
                    }}
                  >
                    <Typography sx={{ fontWeight: 800, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {it.value}
                    </Typography>

                    <IconButton
                      aria-label="Remove"
                      onClick={() => removeMutation.mutate(it.id)}
                      size="small"
                      sx={{ border: "1px solid rgba(255,255,255,.10)", borderRadius: 2 }}
                    >
                      <DeleteOutline fontSize="small" />
                    </IconButton>
                  </Stack>
                ))}
              </Stack>
            ) : (
              <Typography color="text.secondary" sx={{ p: 2 }}>
                No items.
              </Typography>
            )}
          </CardContent>
        </Card>
      )}
    </Stack>
  );
}

function FeederPanel() {
  const qc = useQueryClient();
  const useMock = import.meta.env.VITE_USE_MOCK_SETTINGS === "true";

  const statusQuery = useQuery({
    queryKey: ["settings", "email_feeder", useMock],
    queryFn: async () => (useMock ? mockFeeder() : getFeederStatus()),
    retry: false,
  });

  const toggleMutation = useMutation({
    mutationFn: async (enabled: boolean) => {
      if (useMock) return;
      return setFeederStatus(enabled);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings", "email_feeder"] }),
  });

  const enabled = statusQuery.data?.enabled ?? false;

  return (
    <Stack spacing={2}>
      {statusQuery.isError ? <Alert severity="error">Failed to load feeder status.</Alert> : null}

      <Stack direction="row" alignItems="center" justifyContent="space-between">
        <Stack spacing={0.25}>
          <Typography fontWeight={950}>Email feeder</Typography>
          <Typography variant="body2" color="text.secondary">
            When enabled, the system ingests suspicious emails and creates cases automatically.
          </Typography>
        </Stack>

        <Stack direction="row" spacing={1} alignItems="center">
          <Chip size="small" label={enabled ? "Enabled" : "Disabled"} variant="outlined" />
          <Switch
            checked={enabled}
            onChange={(e) => toggleMutation.mutate(e.target.checked)}
            disabled={statusQuery.isLoading}
          />
        </Stack>
      </Stack>
    </Stack>
  );
}

function ScoringPanel() {
  const qc = useQueryClient();
  const useMock = import.meta.env.VITE_USE_MOCK_SETTINGS === "true";

  const analyzersQuery = useQuery<Analyzer[]>({
    queryKey: ["settings", "scoring", useMock],
    queryFn: async () => (useMock ? mockAnalyzers() : listAnalyzers()),
    retry: false,
  });

  const mut = useMutation({
    mutationFn: async (p: { id: string; weight: number }) => {
      if (useMock) return;
      return updateAnalyzerWeight(p.id, p.weight);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings", "scoring"] }),
  });

  if (analyzersQuery.isLoading) {
    return (
      <Box sx={{ display: "grid", placeItems: "center", py: 4 }}>
        <CircularProgress />
      </Box>
    );
  }
  if (analyzersQuery.isError) {
    return <Alert severity="error">Failed to load analyzers.</Alert>;
  }

  const list = analyzersQuery.data ?? [];

  return (
    <Stack spacing={1.25}>
      {list.map((a) => (
        <Card
          key={a.id}
          sx={{
            borderRadius: 3,
            border: "1px solid rgba(255,255,255,.10)",
            background: "rgba(255,255,255,.03)",
          }}
        >
          <CardContent sx={{ p: 2 }}>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
              <Box sx={{ flex: 1 }}>
                <Typography fontWeight={950}>{a.name}</Typography>
                <Typography variant="caption" color="text.secondary">
                  id: {a.id}
                </Typography>
              </Box>

              <Stack direction="row" spacing={1} alignItems="center">
                <Button
                  variant="outlined"
                  onClick={() => mut.mutate({ id: a.id, weight: Math.max(0, +(a.weight - 0.1).toFixed(1)) })}
                  sx={{ borderRadius: 3, textTransform: "none", fontWeight: 900, minWidth: 44 }}
                >
                  −
                </Button>

                <TextField
                  value={a.weight}
                  size="small"
                  onChange={(e) => {
                    const v = Number(e.target.value);
                    if (!Number.isFinite(v)) return;
                    qc.setQueryData<Analyzer[]>(["settings", "scoring", useMock], (prev) =>
                      (prev ?? []).map((x) => (x.id === a.id ? { ...x, weight: v } : x))
                    );
                  }}
                  inputProps={{ inputMode: "decimal", style: { textAlign: "center", width: 90 } }}
                />

                <Button
                  variant="outlined"
                  onClick={() => mut.mutate({ id: a.id, weight: +(a.weight + 0.1).toFixed(1) })}
                  sx={{ borderRadius: 3, textTransform: "none", fontWeight: 900, minWidth: 44 }}
                >
                  +
                </Button>

                <Button
                  variant="contained"
                  onClick={() => mut.mutate({ id: a.id, weight: a.weight })}
                  sx={{ borderRadius: 3, textTransform: "none", fontWeight: 900 }}
                >
                  Save
                </Button>
              </Stack>
            </Stack>
          </CardContent>
        </Card>
      ))}
    </Stack>
  );
}

export default function SettingsPage() {
  const qc = useQueryClient();
  const useMockMe = import.meta.env.VITE_USE_MOCK_ME === "true";

  const meQuery = useQuery<Me>({
    queryKey: ["me", useMockMe],
    queryFn: getMe,
    retry: false,
    enabled: !useMockMe,
  });

  const me: any = useMockMe
    ? { username: "mockadmin", groups: ["CERT", "Admin"] }
    : meQuery.data;

  const isAllowed =
    (me?.groups ?? []).includes("Admin") || (me?.groups ?? []).includes("CERT");

  const [active, setActive] = React.useState<SettingsSection>("domains_allow");

  const meta = SECTIONS.find((s) => s.key === active)!;

  if (!useMockMe && meQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me || !isAllowed) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Not authorized (Admin/CERT only).</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: { xs: 2, md: 3 } }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
        <Stack spacing={0.25}>
          <Typography variant="h4" fontWeight={950} letterSpacing={-0.5}>
            Settings
          </Typography>
          <Typography color="text.secondary">
            Manage allow/deny lists, services, and analyzer scoring.
          </Typography>
        </Stack>

        <IconButton
          aria-label="Refresh all"
          onClick={() => {
            qc.invalidateQueries({ queryKey: ["settings"] });
          }}
          sx={{ border: "1px solid rgba(255,255,255,.10)", borderRadius: 2 }}
        >
          <RefreshOutlined />
        </IconButton>
      </Stack>

      <Grid container spacing={2}>
        {/* Left nav */}
        <Grid item xs={12} md={3.5}>
          <Card
            sx={{
              borderRadius: 4,
              border: "1px solid rgba(255,255,255,.10)",
              background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
              overflow: "hidden",
            }}
          >
            <CardContent sx={{ p: 1.25 }}>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ px: 1, py: 1 }}>
                <Box
                  sx={{
                    width: 38,
                    height: 38,
                    borderRadius: 2.5,
                    display: "grid",
                    placeItems: "center",
                    border: "1px solid rgba(255,255,255,.12)",
                    background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                  }}
                >
                  <SettingsOutlined />
                </Box>
                <Box>
                  <Typography fontWeight={950}>Admin Console</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {me.username}
                  </Typography>
                </Box>
              </Stack>

              <Divider sx={{ opacity: 0.25, my: 1 }} />

              <List dense disablePadding>
                {SECTIONS.map((s) => (
                  <ListItemButton
                    key={s.key}
                    selected={active === s.key}
                    onClick={() => setActive(s.key)}
                    sx={{
                      borderRadius: 2.5,
                      mx: 0.5,
                      my: 0.4,
                      "&.Mui-selected": {
                        backgroundColor: "rgba(255,255,255,.08)",
                      },
                    }}
                  >
                    <Box sx={{ width: 34, display: "grid", placeItems: "center", opacity: 0.9 }}>
                      {s.icon}
                    </Box>
                    <ListItemText
                      primary={s.title}
                      secondary={s.subtitle}
                      primaryTypographyProps={{ fontWeight: 900 }}
                      secondaryTypographyProps={{
                        sx: { display: { xs: "none", md: "block" } },
                      }}
                    />
                  </ListItemButton>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Right content */}
        <Grid item xs={12} md={8.5}>
          <SectionCard title={meta.title} subtitle={meta.subtitle}>
            {meta.kind === "list" ? (
              <ListManager
                section={meta.key}
                placeholder="Paste values…"
                fileAccept=".txt,.csv,application/json,.eml"
              />
            ) : meta.kind === "toggle" ? (
              <FeederPanel />
            ) : (
              <ScoringPanel />
            )}
          </SectionCard>
        </Grid>
      </Grid>
    </Box>
  );
}
