// src/pages/SettingsPage.tsx
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
  Slider,
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
  ShieldOutlined,
} from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";
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
  type CisoUser,
  type ListItem,
  type SettingsSection,
} from "@/features/settings/api";

type SectionKind = "list" | "toggle" | "scoring" | "ciso_users" | "domain_pair";

type SectionMeta = {
  key: SettingsSection;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  kind: SectionKind;
};

const SECTIONS: SectionMeta[] = [
  {
    key: "domains_allow",
    title: "Domains allowlist",
    subtitle: "Manage local allowlist and synced Watcher legit domains.",
    icon: <CheckCircleOutline />,
    kind: "domain_pair",
  },
  {
    key: "domains_deny",
    title: "Domains denylist",
    subtitle: "Manage local denylist and synced Watcher monitored domains.",
    icon: <BlockOutlined />,
    kind: "domain_pair",
  },
  {
    key: "campaign_domains_allow",
    title: "Campaign domains allowlist",
    subtitle: "Allow campaign or newsletter domains.",
    icon: <CampaignOutlined />,
    kind: "list",
  },
  {
    key: "emails_files_allow",
    title: "Files allowlist",
    subtitle: "Allow known safe file hashes.",
    icon: <InsertDriveFileOutlined />,
    kind: "list",
  },
  {
    key: "filetypes_allow",
    title: "Filetypes allowlist",
    subtitle: "Allow known safe file extensions.",
    icon: <ExtensionOutlined />,
    kind: "list",
  },
  {
    key: "ciso_users",
    title: "CISO users",
    subtitle: "Review scoped CISO identities.",
    icon: <GroupsOutlined />,
    kind: "ciso_users",
  },
  {
    key: "email_feeder",
    title: "Email feeder",
    subtitle: "Enable or disable the feeder service.",
    icon: <MailOutline />,
    kind: "toggle",
  },
  {
    key: "scoring",
    title: "Analyzer scoring",
    subtitle: "Tune analyzer weights.",
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

function GlassCard(props: React.PropsWithChildren<{ sx?: any }>) {
  return (
    <Card
      sx={{
        borderRadius: 3,
        border: "1px solid rgba(255,255,255,.10)",
        background:
          "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
        ...props.sx,
      }}
    >
      {props.children}
    </Card>
  );
}

function SectionCard(
  props: React.PropsWithChildren<{
    title: string;
    subtitle: string;
    right?: React.ReactNode;
  }>
) {
  return (
    <GlassCard>
      <CardContent sx={{ p: { xs: 2, md: 2.5 } }}>
        <Stack
          direction={{ xs: "column", md: "row" }}
          spacing={1.25}
          justifyContent="space-between"
          alignItems={{ md: "center" }}
        >
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

        <Divider sx={{ my: 1.75, opacity: 0.25 }} />
        {props.children}
      </CardContent>
    </GlassCard>
  );
}

function ListManager(props: {
  section: Exclude<
    SettingsSection,
    | "email_feeder"
    | "scoring"
    | "ciso_users"
    | "watcher_legit_domains"
    | "watcher_monitored_domains"
  >;
  placeholder: string;
  fileAccept: string;
}) {
  const qc = useQueryClient();
  const [input, setInput] = React.useState("");
  const [filter, setFilter] = React.useState("");

  const listQuery = useQuery<ListItem[]>({
    queryKey: ["settings", "list", props.section],
    queryFn: () => listItems(props.section),
    retry: false,
  });

  const addMutation = useMutation({
    mutationFn: (values: string[]) => addItems(props.section, values),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "list", props.section] });
      setInput("");
    },
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => removeItem(props.section, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "list", props.section] });
    },
  });

  const importMutation = useMutation({
    mutationFn: (file: File) => addFromFile(props.section, file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "list", props.section] });
    },
  });

  const items = React.useMemo(() => {
    const base = listQuery.data ?? [];
    const q = filter.trim().toLowerCase();
    if (!q) return base;
    return base.filter((it) => it.value.toLowerCase().includes(q));
  }, [listQuery.data, filter]);

  return (
    <Stack spacing={2}>
      <Grid container spacing={1.5}>
        <Grid item xs={12} md={6}>
          <TextField
            label="Add values"
            placeholder={props.placeholder}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            helperText="Multiple values supported: spaces, commas or new lines."
            fullWidth
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    aria-label="Add values"
                    onClick={() => {
                      const values = parseMulti(input);
                      if (!values.length) return;
                      addMutation.mutate(values);
                    }}
                  >
                    <AddOutlined />
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />
        </Grid>

        <Grid item xs={12} md={6}>
          <TextField
            label="Search"
            placeholder="Filter items…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            fullWidth
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchOutlined fontSize="small" />
                </InputAdornment>
              ),
            }}
          />
        </Grid>

        <Grid item xs={12}>
          <Stack
            direction={{ xs: "column", sm: "row" }}
            spacing={1}
            alignItems={{ sm: "center" }}
          >
            <Button
              variant="outlined"
              component="label"
              startIcon={<FileUploadOutlined />}
              sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900 }}
            >
              Import file
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

      {addMutation.isError ? (
        <Alert severity="error">Failed to add values.</Alert>
      ) : null}
      {removeMutation.isError ? (
        <Alert severity="error">Failed to remove item.</Alert>
      ) : null}
      {importMutation.isError ? (
        <Alert severity="error">Failed to import file.</Alert>
      ) : null}

      {listQuery.isLoading ? (
        <Box sx={{ display: "grid", placeItems: "center", py: 4 }}>
          <CircularProgress />
        </Box>
      ) : listQuery.isError ? (
        <Alert severity="error">Failed to load list.</Alert>
      ) : (
        <GlassCard
          sx={{
            borderRadius: 2.5,
            background: "rgba(255,255,255,.03)",
          }}
        >
          <CardContent sx={{ p: 1.25 }}>
            {items.length ? (
              <Stack spacing={0.9}>
                {items.map((it) => (
                  <Stack
                    key={it.id}
                    direction="row"
                    alignItems="center"
                    justifyContent="space-between"
                    sx={{
                      borderRadius: 2,
                      border: "1px solid rgba(255,255,255,.08)",
                      px: 1.25,
                      py: 0.9,
                    }}
                  >
                    <Box sx={{ minWidth: 0, pr: 1 }}>
                      <Typography
                        sx={{
                          fontWeight: 800,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {it.value}
                      </Typography>
                      {it.created_at ? (
                        <Typography variant="caption" color="text.secondary">
                          {new Date(it.created_at).toLocaleString()}
                        </Typography>
                      ) : null}
                    </Box>

                    <IconButton
                      aria-label="Remove"
                      onClick={() => removeMutation.mutate(it.id)}
                      size="small"
                      sx={{
                        border: "1px solid rgba(255,255,255,.10)",
                        borderRadius: 2,
                      }}
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
        </GlassCard>
      )}
    </Stack>
  );
}

function EditableListCard(props: {
  section: Exclude<
    SettingsSection,
    | "email_feeder"
    | "scoring"
    | "ciso_users"
    | "watcher_legit_domains"
    | "watcher_monitored_domains"
  >;
  title: string;
  subtitle: string;
  placeholder: string;
  fileAccept: string;
}) {
  const qc = useQueryClient();
  const [input, setInput] = React.useState("");
  const [filter, setFilter] = React.useState("");

  const listQuery = useQuery<ListItem[]>({
    queryKey: ["settings", "list", props.section],
    queryFn: () => listItems(props.section),
    retry: false,
  });

  const addMutation = useMutation({
    mutationFn: (values: string[]) => addItems(props.section, values),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "list", props.section] });
      setInput("");
    },
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => removeItem(props.section, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "list", props.section] });
    },
  });

  const importMutation = useMutation({
    mutationFn: (file: File) => addFromFile(props.section, file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "list", props.section] });
    },
  });

  const items = React.useMemo(() => {
    const base = listQuery.data ?? [];
    const q = filter.trim().toLowerCase();
    if (!q) return base;
    return base.filter((it) => it.value.toLowerCase().includes(q));
  }, [listQuery.data, filter]);

  return (
    <GlassCard
      sx={{
        height: "100%",
        borderRadius: 2.5,
        background: "rgba(255,255,255,.03)",
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Stack spacing={1.5}>
          <Box>
            <Typography fontWeight={950}>{props.title}</Typography>
            <Typography variant="body2" color="text.secondary">
              {props.subtitle}
            </Typography>
          </Box>

          <TextField
            size="small"
            label="Add values"
            placeholder={props.placeholder}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            fullWidth
            helperText="Spaces, commas or new lines."
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    aria-label="Add values"
                    onClick={() => {
                      const values = parseMulti(input);
                      if (!values.length) return;
                      addMutation.mutate(values);
                    }}
                    size="small"
                  >
                    <AddOutlined fontSize="small" />
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />

          <TextField
            size="small"
            label="Search"
            placeholder="Filter items…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            fullWidth
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchOutlined fontSize="small" />
                </InputAdornment>
              ),
            }}
          />

          <Stack
            direction={{ xs: "column", sm: "row" }}
            spacing={1}
            alignItems={{ sm: "center" }}
          >
            <Button
              size="small"
              variant="outlined"
              component="label"
              startIcon={<FileUploadOutlined />}
              sx={{ borderRadius: 2, textTransform: "none", fontWeight: 900 }}
            >
              Import
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

          {addMutation.isError ? (
            <Alert severity="error">Failed to add values.</Alert>
          ) : null}
          {removeMutation.isError ? (
            <Alert severity="error">Failed to remove item.</Alert>
          ) : null}
          {importMutation.isError ? (
            <Alert severity="error">Failed to import file.</Alert>
          ) : null}

          {listQuery.isLoading ? (
            <Box sx={{ display: "grid", placeItems: "center", py: 4 }}>
              <CircularProgress size={24} />
            </Box>
          ) : listQuery.isError ? (
            <Alert severity="error">Failed to load list.</Alert>
          ) : (
            <Box
              sx={{
                maxHeight: 420,
                overflowY: "auto",
                borderRadius: 2,
                border: "1px solid rgba(255,255,255,.08)",
              }}
            >
              {items.length ? (
                <Stack spacing={0} sx={{ p: 1 }}>
                  {items.map((it) => (
                    <Stack
                      key={it.id}
                      direction="row"
                      alignItems="center"
                      justifyContent="space-between"
                      sx={{
                        px: 1.25,
                        py: 1,
                        borderRadius: 1.5,
                        "&:not(:last-child)": {
                          mb: 0.75,
                        },
                        border: "1px solid rgba(255,255,255,.06)",
                      }}
                    >
                      <Box sx={{ minWidth: 0, pr: 1 }}>
                        <Typography
                          sx={{
                            fontWeight: 800,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {it.value}
                        </Typography>
                        {it.created_at ? (
                          <Typography variant="caption" color="text.secondary">
                            {new Date(it.created_at).toLocaleString()}
                          </Typography>
                        ) : null}
                      </Box>

                      <IconButton
                        aria-label="Remove"
                        onClick={() => removeMutation.mutate(it.id)}
                        size="small"
                        sx={{
                          border: "1px solid rgba(255,255,255,.10)",
                          borderRadius: 2,
                        }}
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
            </Box>
          )}
        </Stack>
      </CardContent>
    </GlassCard>
  );
}

function ReadOnlyListCard(props: {
  section: "watcher_legit_domains" | "watcher_monitored_domains";
  title: string;
  subtitle: string;
}) {
  const [filter, setFilter] = React.useState("");

  const listQuery = useQuery<ListItem[]>({
    queryKey: ["settings", "list", props.section],
    queryFn: () => listItems(props.section),
    retry: false,
  });

  const items = React.useMemo(() => {
    const base = listQuery.data ?? [];
    const q = filter.trim().toLowerCase();
    if (!q) return base;
    return base.filter((it) => it.value.toLowerCase().includes(q));
  }, [listQuery.data, filter]);

  return (
    <GlassCard
      sx={{
        height: "100%",
        borderRadius: 2.5,
        background: "rgba(255,255,255,.03)",
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Stack spacing={1.5}>
          <Stack
            direction="row"
            justifyContent="space-between"
            alignItems="flex-start"
            spacing={1}
          >
            <Box>
              <Typography fontWeight={950}>{props.title}</Typography>
              <Typography variant="body2" color="text.secondary">
                {props.subtitle}
              </Typography>
            </Box>

            <Chip
              size="small"
              label="Synced from Watcher"
              color="info"
              variant="outlined"
            />
          </Stack>

          <Typography variant="caption" color="text.secondary">
            Managed externally. These domains are read-only in this page.
          </Typography>

          <TextField
            size="small"
            label="Search"
            placeholder="Filter domains…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            fullWidth
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchOutlined fontSize="small" />
                </InputAdornment>
              ),
            }}
          />

          {listQuery.isLoading ? (
            <Box sx={{ display: "grid", placeItems: "center", py: 4 }}>
              <CircularProgress size={24} />
            </Box>
          ) : listQuery.isError ? (
            <Alert severity="error">Failed to load synced domains.</Alert>
          ) : (
            <>
              <Stack
                direction="row"
                justifyContent="space-between"
                alignItems="center"
              >
                <Typography variant="caption" color="text.secondary">
                  Read-only list
                </Typography>
                <Chip
                  size="small"
                  label={`${items.length} item(s)`}
                  variant="outlined"
                />
              </Stack>

              <Box
                sx={{
                  maxHeight: 420,
                  overflowY: "auto",
                  borderRadius: 2,
                  border: "1px solid rgba(255,255,255,.08)",
                }}
              >
                {items.length ? (
                  <Stack spacing={0} sx={{ p: 1 }}>
                    {items.map((it) => (
                      <Box
                        key={it.id}
                        sx={{
                          px: 1.25,
                          py: 1,
                          borderRadius: 1.5,
                          "&:not(:last-child)": {
                            mb: 0.75,
                          },
                          border: "1px solid rgba(255,255,255,.06)",
                        }}
                      >
                        <Typography
                          sx={{
                            fontWeight: 800,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {it.value}
                        </Typography>
                        {it.created_at ? (
                          <Typography variant="caption" color="text.secondary">
                            {new Date(it.created_at).toLocaleString()}
                          </Typography>
                        ) : null}
                      </Box>
                    ))}
                  </Stack>
                ) : (
                  <Typography color="text.secondary" sx={{ p: 2 }}>
                    No synced items.
                  </Typography>
                )}
              </Box>
            </>
          )}
        </Stack>
      </CardContent>
    </GlassCard>
  );
}

function DomainPairPanel(props: {
  editableSection: "domains_allow" | "domains_deny";
}) {
  const isAllow = props.editableSection === "domains_allow";

  return (
    <Grid container spacing={2}>
      <Grid item xs={12} lg={6}>
        <EditableListCard
          section={props.editableSection}
          title={isAllow ? "Domains allowlist" : "Domains denylist"}
          subtitle={
            isAllow
              ? "Manage locally allowed domains."
              : "Manage locally denied domains."
          }
          placeholder="Paste domains…"
          fileAccept=".txt,.csv,.json"
        />
      </Grid>

      <Grid item xs={12} lg={6}>
        <ReadOnlyListCard
          section={
            isAllow ? "watcher_legit_domains" : "watcher_monitored_domains"
          }
          title={
            isAllow ? "Watcher legit domains" : "Watcher monitored domains"
          }
          subtitle={
            isAllow
              ? "Read-only domains synchronized from Watcher."
              : "Read-only monitored domains synchronized from Watcher."
          }
        />
      </Grid>
    </Grid>
  );
}

function FeederPanel() {
  const qc = useQueryClient();

  const statusQuery = useQuery({
    queryKey: ["settings", "email_feeder"],
    queryFn: getFeederStatus,
    retry: false,
  });

  const toggleMutation = useMutation({
    mutationFn: (enabled: boolean) => setFeederStatus(enabled),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "email_feeder"] });
    },
  });

  const enabled = statusQuery.data?.enabled ?? false;

  return (
    <Stack spacing={2}>
      {statusQuery.isError ? (
        <Alert severity="error">Failed to load feeder status.</Alert>
      ) : null}

      <GlassCard
        sx={{
          borderRadius: 2.5,
          background: "rgba(255,255,255,.03)",
        }}
      >
        <CardContent sx={{ p: 2 }}>
          <Stack
            direction="row"
            alignItems="center"
            justifyContent="space-between"
            spacing={2}
          >
            <Stack spacing={0.25}>
              <Typography fontWeight={950}>Email feeder</Typography>
              <Typography variant="body2" color="text.secondary">
                Automatically ingest suspicious emails and create cases.
              </Typography>
            </Stack>

            <Stack direction="row" spacing={1} alignItems="center">
              <Chip
                size="small"
                label={enabled ? "Enabled" : "Disabled"}
                variant="outlined"
                color={enabled ? "success" : "default"}
              />
              <Switch
                checked={enabled}
                onChange={(e) => toggleMutation.mutate(e.target.checked)}
                disabled={statusQuery.isLoading || toggleMutation.isPending}
              />
            </Stack>
          </Stack>
        </CardContent>
      </GlassCard>
    </Stack>
  );
}

function ScoringPanel() {
  const qc = useQueryClient();

  const analyzersQuery = useQuery<Analyzer[]>({
    queryKey: ["settings", "scoring"],
    queryFn: listAnalyzers,
    retry: false,
  });

  const updateMutation = useMutation({
    mutationFn: async (payload: { id: number; weight: number }) =>
      updateAnalyzerWeight(payload.id, payload.weight),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings", "scoring"] });
    },
  });

  const [drafts, setDrafts] = React.useState<Record<number, number>>({});

  React.useEffect(() => {
    if (!analyzersQuery.data) return;
    const next: Record<number, number> = {};
    for (const analyzer of analyzersQuery.data) {
      next[analyzer.id] = analyzer.weight;
    }
    setDrafts(next);
  }, [analyzersQuery.data]);

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

  const analyzers = analyzersQuery.data ?? [];

  return (
    <Stack spacing={1.25}>
      {analyzers.map((a) => {
        const draftWeight = drafts[a.id] ?? a.weight;
        const dirty = Number(draftWeight) !== Number(a.weight);
        const savingThisOne =
          updateMutation.isPending && updateMutation.variables?.id === a.id;

        return (
          <Card
            key={a.id}
            sx={{
              borderRadius: 3,
              border: "1px solid rgba(255,255,255,.10)",
              background: "rgba(255,255,255,.03)",
            }}
          >
            <CardContent sx={{ p: 2 }}>
              <Stack
                direction={{ xs: "column", md: "row" }}
                spacing={2}
                alignItems={{ md: "center" }}
              >
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography fontWeight={950}>{a.name}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    cortex id: {a.analyzer_cortex_id}
                  </Typography>
                </Box>

                <Stack
                  direction={{ xs: "column", sm: "row" }}
                  spacing={1.5}
                  alignItems={{ xs: "stretch", sm: "center" }}
                  sx={{ minWidth: { md: 420 } }}
                >
                  <Box sx={{ flex: 1, px: 1 }}>
                    <Slider
                      value={draftWeight}
                      min={0}
                      max={1}
                      step={0.1}
                      marks
                      onChange={(_, value) => {
                        setDrafts((prev) => ({
                          ...prev,
                          [a.id]: Number(value),
                        }));
                      }}
                      sx={{
                        "& .MuiSlider-mark": {
                          width: 4,
                          height: 4,
                          borderRadius: 99,
                          opacity: 0.7,
                        },
                        "& .MuiSlider-markLabel": {
                          display: "none",
                        },
                      }}
                    />
                  </Box>

                  <TextField
                    size="small"
                    value={draftWeight}
                    onChange={(e) => {
                      const v = Number(e.target.value);
                      if (!Number.isFinite(v)) return;
                      const clamped = Math.max(0, Math.min(1, v));
                      setDrafts((prev) => ({
                        ...prev,
                        [a.id]: clamped,
                      }));
                    }}
                    inputProps={{
                      inputMode: "decimal",
                      step: 0.1,
                      min: 0,
                      max: 1,
                      style: { textAlign: "center", width: 72 },
                    }}
                  />

                  <Button
                    variant="contained"
                    disabled={!dirty || savingThisOne}
                    onClick={() =>
                      updateMutation.mutate({
                        id: a.id,
                        weight: Number(draftWeight.toFixed(1)),
                      })
                    }
                    sx={{
                      borderRadius: 3,
                      textTransform: "none",
                      fontWeight: 900,
                      minWidth: 88,
                    }}
                  >
                    {savingThisOne ? "Saving…" : "Save"}
                  </Button>
                </Stack>
              </Stack>
            </CardContent>
          </Card>
        );
      })}
    </Stack>
  );
}

function CisoUsersPanel() {
  const [filter, setFilter] = React.useState("");

  const query = useQuery<CisoUser[]>({
    queryKey: ["settings", "list", "ciso_users"],
    queryFn: () => listItems("ciso_users"),
    retry: false,
  });

  const items = React.useMemo(() => {
    const base = query.data ?? [];
    const q = filter.trim().toLowerCase();
    if (!q) return base;

    return base.filter((it) => {
      const haystack = [
        it.username,
        it.email,
        it.function,
        it.region,
        it.country,
        it.gbu,
        it.scope,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return haystack.includes(q);
    });
  }, [query.data, filter]);

  return (
    <Stack spacing={2}>
      <TextField
        label="Search CISO users"
        placeholder="username, email, scope…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        fullWidth
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              <SearchOutlined fontSize="small" />
            </InputAdornment>
          ),
        }}
      />

      {query.isLoading ? (
        <Box sx={{ display: "grid", placeItems: "center", py: 4 }}>
          <CircularProgress />
        </Box>
      ) : query.isError ? (
        <Alert severity="error">Failed to load CISO users.</Alert>
      ) : items.length === 0 ? (
        <Alert severity="info">No CISO users found.</Alert>
      ) : (
        <Stack spacing={1}>
          {items.map((user) => (
            <GlassCard
              key={user.id}
              sx={{
                borderRadius: 2.5,
                background: "rgba(255,255,255,.03)",
              }}
            >
              <CardContent sx={{ p: 2 }}>
                <Stack spacing={1}>
                  <Stack
                    direction={{ xs: "column", sm: "row" }}
                    justifyContent="space-between"
                    spacing={1}
                  >
                    <Box>
                      <Typography fontWeight={950}>{user.username}</Typography>
                      <Typography variant="body2" color="text.secondary">
                        {user.email || "No email"}
                      </Typography>
                    </Box>

                    <Chip
                      size="small"
                      icon={<ShieldOutlined />}
                      label={user.scope || "No scope"}
                      variant="outlined"
                    />
                  </Stack>

                  <Divider sx={{ opacity: 0.2 }} />

                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)" },
                      gap: 1,
                    }}
                  >
                    <Typography variant="body2">
                      <b>Function:</b> {user.function || "—"}
                    </Typography>
                    <Typography variant="body2">
                      <b>GBU:</b> {user.gbu || "—"}
                    </Typography>
                    <Typography variant="body2">
                      <b>Country:</b> {user.country || "—"}
                    </Typography>
                    <Typography variant="body2">
                      <b>Region:</b> {user.region || "—"}
                    </Typography>
                  </Box>
                </Stack>
              </CardContent>
            </GlassCard>
          ))}
        </Stack>
      )}
    </Stack>
  );
}

export default function SettingsPage() {
  const qc = useQueryClient();
  const theme = useTheme();

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  const me = meQuery.data;
  const groups = me?.groups ?? [];
  const isAllowed = groups.includes("Admin") || groups.includes("CERT");

  const [active, setActive] =
    React.useState<SettingsSection>("domains_allow");

  const meta = SECTIONS.find((s) => s.key === active)!;

  if (meQuery.isLoading) {
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
    <Box sx={{ p: { xs: 1.5, md: 2.5 } }}>
      <Stack
        direction={{ xs: "column", md: "row" }}
        justifyContent="space-between"
        spacing={1.5}
        sx={{ mb: 2 }}
      >
        <Stack spacing={0.3}>
          <Typography variant="h4" fontWeight={950} letterSpacing={-0.5}>
            Settings
          </Typography>
          <Typography color="text.secondary">
            Manage lists, feeder state and analyzer scoring.
          </Typography>
        </Stack>

        <IconButton
          aria-label="Refresh all"
          onClick={() => qc.invalidateQueries({ queryKey: ["settings"] })}
          sx={{
            alignSelf: { xs: "flex-start", md: "center" },
            border: `1px solid ${alpha(theme.palette.common.white, 0.1)}`,
            borderRadius: 2,
          }}
        >
          <RefreshOutlined />
        </IconButton>
      </Stack>

      <Grid container spacing={2}>
        <Grid item xs={12} md={3.5}>
          <GlassCard sx={{ overflow: "hidden" }}>
            <CardContent sx={{ p: 1.25 }}>
              <Stack
                direction="row"
                spacing={1}
                alignItems="center"
                sx={{ px: 1, py: 1 }}
              >
                <Box
                  sx={{
                    width: 38,
                    height: 38,
                    borderRadius: 2.5,
                    display: "grid",
                    placeItems: "center",
                    border: "1px solid rgba(255,255,255,.12)",
                    background:
                      "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                  }}
                >
                  <SettingsOutlined />
                </Box>
                <Box>
                  <Typography fontWeight={950}>Admin console</Typography>
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
                      borderRadius: 2.25,
                      mx: 0.5,
                      my: 0.4,
                      "&.Mui-selected": {
                        backgroundColor: "rgba(255,255,255,.08)",
                      },
                    }}
                  >
                    <Box
                      sx={{
                        width: 34,
                        display: "grid",
                        placeItems: "center",
                        opacity: 0.9,
                      }}
                    >
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
          </GlassCard>
        </Grid>

        <Grid item xs={12} md={8.5}>
          <SectionCard title={meta.title} subtitle={meta.subtitle}>
            {meta.kind === "domain_pair" && active === "domains_allow" ? (
              <DomainPairPanel editableSection="domains_allow" />
            ) : meta.kind === "domain_pair" && active === "domains_deny" ? (
              <DomainPairPanel editableSection="domains_deny" />
            ) : meta.kind === "list" ? (
              <ListManager
                section={
                  meta.key as Exclude<
                    SettingsSection,
                    | "email_feeder"
                    | "scoring"
                    | "ciso_users"
                    | "watcher_legit_domains"
                    | "watcher_monitored_domains"
                  >
                }
                placeholder="Paste values…"
                fileAccept=".txt,.csv,.json"
              />
            ) : meta.kind === "toggle" ? (
              <FeederPanel />
            ) : meta.kind === "scoring" ? (
              <ScoringPanel />
            ) : (
              <CisoUsersPanel />
            )}
          </SectionCard>
        </Grid>
      </Grid>
    </Box>
  );
}