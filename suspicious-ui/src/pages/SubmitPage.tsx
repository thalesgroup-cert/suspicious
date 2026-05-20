// src/pages/SubmitPage.tsx
import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Container,
  Dialog,
  DialogContent,
  Divider,
  LinearProgress,
  Stack,
  TextField,
  Typography,
  useTheme,
} from "@mui/material";
import { alpha } from "@mui/material/styles";
import {
  ContentCopyOutlined,
  UploadFileOutlined,
  LinkOutlined,
  FingerprintOutlined,
  CheckCircleOutlined,
  InfoOutlined,
  InsertDriveFileOutlined,
  PublicOutlined,
  CloudUploadOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useDropzone } from "react-dropzone";
import { useSnackbar } from "notistack";
import { useNavigate } from "react-router-dom";

import { api } from "@/api/client";
import { env } from "@/lib/runtimeEnv";
import { getMe, type Me } from "@/api/auth";

import axios from "axios";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SubmitConfigResponse = {
  status: "success";
  data: {
    suspicious_email: string;
  };
};

type SubmitSuccessResponse = {
  status: "success";
  accepted: boolean;
  submission_type: "url" | "other" | "file";
  result_type: "case" | "mail";
  case_id: number | string | null;
  id?: number | string | null;
  message: string;
};

type ApiErrorResponse = {
  status?: "error";
  code?: string;
  detail?: string;
  non_field_errors?: string[];
} & Record<string, unknown>;

type SubmitMode = "file" | "artifact";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractApiErrorMessage(error: unknown): string {
  if (!axios.isAxiosError(error)) {
    return "Request failed.";
  }

  const data = error.response?.data as ApiErrorResponse | undefined;
  if (!data) {
    return error.message || "Request failed.";
  }

  if (typeof data.detail === "string" && data.detail.trim()) {
    return data.detail;
  }

  const fieldMessages = Object.entries(data)
    .filter(([key]) => key !== "status" && key !== "code" && key !== "detail")
    .flatMap(([key, value]) => {
      if (Array.isArray(value)) {
        return value.map((msg) => `${key}: ${String(msg)}`);
      }
      if (typeof value === "string") {
        return [`${key}: ${value}`];
      }
      return [];
    });

  if (fieldMessages.length > 0) {
    return fieldMessages.join(" ");
  }

  return error.message || "Request failed.";
}

function resolveId(res: SubmitSuccessResponse): string | number | null {
  return res.case_id ?? res.id ?? null;
}

function formatBytes(bytes: number) {
  const units = ["B", "KB", "MB", "GB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

// ---------------------------------------------------------------------------
// Artifact classification
//
// Determines whether a raw input string should be routed to /submit/url/
// or /submit/other/.
//
// Rules (in priority order):
//   1. Starts with http:// or https://                                   → url
//   2. Looks like a bare domain (evil.com, sub.evil.co.uk, evil.com/path) → url
//   3. Everything else (hash, IP, free-text IOC)                          → ioc
//
// The bare-domain branch also normalises the value to "http://<input>"
// before sending, because Django's URLField requires a scheme.
// ---------------------------------------------------------------------------

const FULL_URL_RE = /^https?:\/\/.+/i;

/**
 * Matches bare hostnames / domains with an optional path.
 * Does NOT match plain IPs (handled as IOC) or hashes (no dots).
 *
 * Matches:   evil.com  sub.evil.co.uk  evil.com/path?q=1
 * No match:  192.168.1.1  abc123deadbeef  malware
 */
const BARE_DOMAIN_RE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(\/.*)?$/i;

type ArtifactKind = "url" | "ioc";

function classifyArtifact(raw: string): ArtifactKind {
  const v = raw.trim();
  if (FULL_URL_RE.test(v)) return "url";
  if (BARE_DOMAIN_RE.test(v)) return "url";
  return "ioc";
}

/**
 * Ensures the value sent to /submit/url/ always carries a scheme.
 * Django URLField rejects scheme-less strings, so bare domains get http://.
 */
function normaliseUrl(raw: string): string {
  const v = raw.trim();
  return FULL_URL_RE.test(v) ? v : `http://${v}`;
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

async function submitUrl(input: {
  url: string;
  context?: string;
}): Promise<SubmitSuccessResponse> {
  const res = await api.post("/submit/url/", input);
  return res.data;
}

async function submitIoc(input: {
  value: string;
  context?: string;
}): Promise<SubmitSuccessResponse> {
  const res = await api.post("/submit/other/", input);
  return res.data;
}

async function submitFile(input: {
  file: File;
  context?: string;
}): Promise<SubmitSuccessResponse> {
  const form = new FormData();
  form.append("file", input.file);
  if (input.context) form.append("context", input.context);
  const res = await api.post("/submit/file/", form);
  return res.data;
}

async function getSubmitConfig(): Promise<string> {
  const res = await api.get<SubmitConfigResponse>("/submit/config/");
  return res.data.data.suspicious_email;
}

// ---------------------------------------------------------------------------
// Validation schemas
// ---------------------------------------------------------------------------

const artifactSchema = z.object({
  value: z
    .string()
    .trim()
    .min(1, "URL or indicator is required")
    .max(4096, "Input is too long"),
  context: z.string().optional(),
});

const fileSchema = z.object({
  context: z.string().optional(),
});

type ArtifactForm = z.infer<typeof artifactSchema>;
type FileForm = z.infer<typeof fileSchema>;

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SoftCard(props: React.PropsWithChildren<{ sx?: object }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Card
      sx={{
        borderRadius: 4,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`,
        background: isDark
          ? `linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
          : `linear-gradient(180deg, ${alpha("#fff", 0.88)}, ${alpha(
              theme.palette.grey[50],
              0.96
            )})`,
        boxShadow: isDark
          ? "0 12px 32px rgba(0,0,0,.28)"
          : "0 10px 28px rgba(15,23,42,.06)",
        ...props.sx,
      }}
    >
      {props.children}
    </Card>
  );
}

function ModeSelectorCard(props: {
  active: boolean;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  helper?: string;
  onClick: () => void;
}) {
  const theme = useTheme();

  return (
    <Box
      role="button"
      tabIndex={0}
      onClick={props.onClick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          props.onClick();
        }
      }}
      sx={{
        cursor: "pointer",
        borderRadius: 3,
        p: 2,
        border: `1px solid ${
          props.active
            ? alpha(theme.palette.primary.main, 0.42)
            : alpha(theme.palette.divider, 0.9)
        }`,
        background: props.active
          ? alpha(
              theme.palette.primary.main,
              theme.palette.mode === "dark" ? 0.1 : 0.06
            )
          : "rgba(255,255,255,.02)",
        transition: "all .16s ease",
        "&:hover": {
          borderColor: alpha(theme.palette.primary.main, 0.35),
          background: alpha(
            theme.palette.primary.main,
            theme.palette.mode === "dark" ? 0.08 : 0.045
          ),
        },
      }}
    >
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "flex-start" }} >
        <Box
          sx={{
            width: 42,
            height: 42,
            borderRadius: 2,
            display: "grid",
            placeItems: "center",
            border: "1px solid rgba(255,255,255,.10)",
            background:
              "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
            flexShrink: 0,
          }}
        >
          {props.icon}
        </Box>

        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack
            direction="row"
            spacing={1}
            useFlexGap
            sx={{ alignItems: "center", flexWrap: "wrap" }}
>
            <Typography sx={{ fontWeight: 850 }} >{props.title}</Typography>

            {props.helper ? (
              <Chip
                size="small"
                label={props.helper}
                variant="outlined"
                sx={{ height: 24, "& .MuiChip-label": { px: 1, fontWeight: 700 } }}
              />
            ) : null}

            {props.active ? (
              <Chip
                size="small"
                icon={<CheckCircleOutlined sx={{ fontSize: 16 }} />}
                label="Selected"
                variant="outlined"
                sx={{ height: 24, "& .MuiChip-label": { px: 1, fontWeight: 700 } }}
              />
            ) : null}
          </Stack>

          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {props.subtitle}
          </Typography>
        </Box>
      </Stack>
    </Box>
  );
}

function SectionHeader(props: { title: string; subtitle: string }) {
  return (
    <Stack spacing={0.5}>
      <Typography variant="h5" sx={{ fontWeight: 850, letterSpacing: -0.4 }} >
        {props.title}
      </Typography>
      <Typography color="text.secondary">{props.subtitle}</Typography>
    </Stack>
  );
}

function SidePanel(
  props: React.PropsWithChildren<{ title: string; icon: React.ReactNode }>
) {
  return (
    <SoftCard>
      <CardContent sx={{ p: 2.25 }}>
        <Stack spacing={1.25}>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
            {props.icon}
            <Typography sx={{ fontWeight: 850 }} >{props.title}</Typography>
          </Stack>
          {props.children}
        </Stack>
      </CardContent>
    </SoftCard>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function SubmitPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const { enqueueSnackbar } = useSnackbar();

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  const me = meQuery.data;

  const suspiciousEmailEnv = env("VITE_SUSPICIOUS_EMAIL");

  const configQuery = useQuery({
    queryKey: ["submitConfig"],
    queryFn: getSubmitConfig,
    retry: false,
    enabled: !!me && !suspiciousEmailEnv,
    initialData: suspiciousEmailEnv ?? undefined,
  });

  const suspiciousEmail =
    suspiciousEmailEnv ?? configQuery.data ?? "suspicious@example.com";

  const [mode, setMode] = React.useState<SubmitMode>("file");
  const [selectedFile, setSelectedFile] = React.useState<File | null>(null);
  const [fallbackCta, setFallbackCta] = React.useState(false);

  const artifactForm = useForm<ArtifactForm>({
    resolver: zodResolver(artifactSchema),
    defaultValues: { value: "", context: "" },
    mode: "onChange",
  });

  const fileForm = useForm<FileForm>({
    resolver: zodResolver(fileSchema),
    defaultValues: { context: "" },
    mode: "onChange",
  });

  const dropzone = useDropzone({
    multiple: false,
    onDrop: (files) => {
      const f = files?.[0];
      if (f) setSelectedFile(f);
    },
  });

  // -------------------------------------------------------------------------
  // Shared post-submission navigation
  // -------------------------------------------------------------------------

  function handleSuccess(res: SubmitSuccessResponse) {
    const id = resolveId(res);
    if (id !== null) {
      enqueueSnackbar(`${res.message} (case #${id})`, { variant: "success" });
      navigate(
        `/submissions?q=${encodeURIComponent(String(id))}&open=${encodeURIComponent(
          String(id)
        )}`
      );
    } else {
      enqueueSnackbar(res.message, { variant: "success" });
      setFallbackCta(true);
    }
  }

  // -------------------------------------------------------------------------
  // Mutations
  // -------------------------------------------------------------------------

  const artifactMutation = useMutation({
    mutationFn: (input: ArtifactForm) => {
      const kind = classifyArtifact(input.value);
      if (kind === "url") {
        return submitUrl({
          url: normaliseUrl(input.value),
          context: input.context,
        });
      }
      return submitIoc(input);
    },
    onSuccess: (res) => {
      handleSuccess(res);
      artifactForm.reset();
    },
    onError: (error) => {
      enqueueSnackbar(extractApiErrorMessage(error), { variant: "error" });
    },
  });

  const fileMutation = useMutation({
    mutationFn: submitFile,
    onSuccess: (res) => {
      handleSuccess(res);
      setSelectedFile(null);
      fileForm.reset();
    },
    onError: (error) => {
      enqueueSnackbar(extractApiErrorMessage(error), { variant: "error" });
    },
  });

  const loadingOpen = artifactMutation.isPending || fileMutation.isPending;

  // -------------------------------------------------------------------------
  // Auth guard
  // -------------------------------------------------------------------------

  if (meQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "60vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Not authenticated.</Alert>
      </Box>
    );
  }

  // -------------------------------------------------------------------------
  // Handlers
  // -------------------------------------------------------------------------

  async function copyEmail() {
    try {
      await navigator.clipboard.writeText(suspiciousEmail);
      enqueueSnackbar("Email address copied.", { variant: "info" });
    } catch {
      enqueueSnackbar("Copy blocked by browser.", { variant: "warning" });
    }
  }

  function switchMode(next: SubmitMode) {
    setMode(next);
    setFallbackCta(false);
  }

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  return (
    <Skeleton
      name="submit-page"
      loading={meQuery.isPending || configQuery.isPending}
      animate="shimmer"
    >
    <Container maxWidth="lg" sx={{ py: { xs: 2.5, md: 3.5 }, pb: 8 }}>
      <Stack spacing={2}>
        {/* ---------------------------------------------------------------- */}
        {/* Header + mode selector                                           */}
        {/* ---------------------------------------------------------------- */}
        <SoftCard>
          <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
            <Stack spacing={2}>
              <Stack spacing={0.6}>
                <Typography variant="h4" sx={{ fontWeight: 900, letterSpacing: -0.6 }} >
                  Submit
                </Typography>
                <Typography color="text.secondary" sx={{ maxWidth: 760 }}>
                  Send a file, URL, domain, hash, or IP for security triage.
                  Choose the artifact type, add short factual context, and
                  submit it for analysis.
                </Typography>
              </Stack>

              <Divider sx={{ opacity: 0.25 }} />

              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: { xs: "1fr", md: "repeat(2, 1fr)" },
                  gap: 1.5,
                }}
              >
                <ModeSelectorCard
                  active={mode === "file"}
                  title="File"
                  subtitle="Upload an attachment or sample for analysis."
                  icon={<UploadFileOutlined />}
                  helper="Recommended"
                  onClick={() => switchMode("file")}
                />
                <ModeSelectorCard
                  active={mode === "artifact"}
                  title="URL, Domain or Indicator"
                  subtitle="Submit a link, bare domain, hash, IP, or any other text-based indicator. Type is detected automatically."
                  icon={<FingerprintOutlined />}
                  onClick={() => switchMode("artifact")}
                />
              </Box>
            </Stack>
          </CardContent>
        </SoftCard>

        {/* ---------------------------------------------------------------- */}
        {/* Main content + sidebar                                           */}
        {/* ---------------------------------------------------------------- */}
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: { xs: "1fr", lg: "minmax(0, 1fr) 320px" },
            gap: 2,
            alignItems: "start",
          }}
        >
          {/* Main form */}
          <SoftCard>
            <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
              {/* ---------------------------------------------------------- */}
              {/* FILE mode                                                   */}
              {/* ---------------------------------------------------------- */}
              {mode === "file" ? (
                <Stack spacing={2.5}>
                  <SectionHeader
                    title="File upload"
                    subtitle="Drop a file or browse from your device. Add short context only if it helps triage."
                  />

                  <Box
                    {...dropzone.getRootProps()}
                    sx={{
                      borderRadius: 3,
                      border: `1px dashed ${
                        dropzone.isDragActive
                          ? alpha(theme.palette.primary.main, 0.52)
                          : alpha(theme.palette.divider, 0.9)
                      }`,
                      background: dropzone.isDragActive
                        ? alpha(
                            theme.palette.primary.main,
                            theme.palette.mode === "dark" ? 0.08 : 0.04
                          )
                        : alpha(
                            theme.palette.background.default,
                            theme.palette.mode === "dark" ? 0.24 : 0.45
                          ),
                      px: 3,
                      py: 4.5,
                      cursor: "pointer",
                      transition: "all .14s ease",
                      outline: "none",
                    }}
                  >
                    <input {...dropzone.getInputProps()} />

                    <Stack spacing={1.5} sx={{ alignItems: "center", textAlign: "center" }} >
                      <Box
                        sx={{
                          width: 58,
                          height: 58,
                          borderRadius: 3,
                          display: "grid",
                          placeItems: "center",
                          border: "1px solid rgba(255,255,255,.10)",
                          background:
                            "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                        }}
                      >
                        <CloudUploadOutlined />
                      </Box>

                      <Box>
                        <Typography sx={{ fontWeight: 850 }} >
                          {selectedFile
                            ? "File selected"
                            : dropzone.isDragActive
                            ? "Drop file here"
                            : "Drag and drop or click to browse"}
                        </Typography>
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          sx={{ mt: 0.5 }}
                        >
                          One file per submission. Limits and acceptance rules
                          are enforced server-side.
                        </Typography>
                      </Box>

                      {selectedFile ? (
                        <Stack
                          direction="row"
                          spacing={1}
                          useFlexGap
                          sx={{ flexWrap: "wrap", justifyContent: "center" }}
>
                          <Chip label={selectedFile.name} variant="outlined" />
                          <Chip
                            label={formatBytes(selectedFile.size)}
                            variant="outlined"
                          />
                          <Button
                            size="small"
                            variant="text"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedFile(null);
                            }}
                            sx={{ textTransform: "none", fontWeight: 700 }}
                          >
                            Remove
                          </Button>
                        </Stack>
                      ) : null}
                    </Stack>
                  </Box>

                  <TextField
                    label="Context (optional)"
                    placeholder="Source, user report, observed behavior, or why the file is suspicious."
                    multiline
                    minRows={4}
                    {...fileForm.register("context")}
                  />

                  {fallbackCta ? (
                    <Alert
                      severity="success"
                      action={
                        <Button
                          color="inherit"
                          size="small"
                          onClick={() => navigate("/submissions")}
                          sx={{ fontWeight: 850, textTransform: "none" }}
                        >
                          View submissions
                        </Button>
                      }
                    >
                      Submitted successfully. Navigate to see the result.
                    </Alert>
                  ) : null}

                  <Stack direction="row" sx={{ justifyContent: "flex-end" }} >
                    <Button
                      variant="contained"
                      disabled={!selectedFile || fileMutation.isPending}
                      onClick={() => {
                        const ctx = fileForm.getValues("context") ?? "";
                        if (selectedFile) {
                          fileMutation.mutate({ file: selectedFile, context: ctx });
                        }
                      }}
                      sx={{
                        borderRadius: 2,
                        textTransform: "none",
                        fontWeight: 850,
                        minWidth: 140,
                      }}
                    >
                      Upload file
                    </Button>
                  </Stack>
                </Stack>
              ) : null}

              {/* ---------------------------------------------------------- */}
              {/* ARTIFACT mode — URL / domain / IOC unified                  */}
              {/* ---------------------------------------------------------- */}
              {mode === "artifact" ? (
                <Stack spacing={2.5}>
                  <SectionHeader
                    title="URL, domain or indicator"
                    subtitle="Paste a full URL, bare domain, hash, IP, or other indicator. The type is detected automatically."
                  />

                  <TextField
                    label="URL, domain or indicator"
                    placeholder="https://evil.com  ·  evil.com  ·  SHA256 / MD5 / IP"
                    error={!!artifactForm.formState.errors.value}
                    helperText={
                      artifactForm.formState.errors.value?.message ??
                      "Full URLs and bare domains are submitted for reputation and detonation. Everything else is correlated as an indicator."
                    }
                    {...artifactForm.register("value")}
                  />

                  <TextField
                    label="Context (optional)"
                    placeholder="Source, related case, user report, or observed behavior."
                    multiline
                    minRows={4}
                    {...artifactForm.register("context")}
                  />

                  {fallbackCta ? (
                    <Alert
                      severity="success"
                      action={
                        <Button
                          color="inherit"
                          size="small"
                          onClick={() => navigate("/submissions")}
                          sx={{ fontWeight: 850, textTransform: "none" }}
                        >
                          View submissions
                        </Button>
                      }
                    >
                      Submitted successfully. Navigate to see the result.
                    </Alert>
                  ) : null}

                  <Stack direction="row" sx={{ justifyContent: "flex-end" }} >
                    <Button
                      variant="contained"
                      disabled={
                        !artifactForm.formState.isValid ||
                        artifactMutation.isPending
                      }
                      onClick={artifactForm.handleSubmit((v) =>
                        artifactMutation.mutate(v)
                      )}
                      sx={{
                        borderRadius: 2,
                        textTransform: "none",
                        fontWeight: 850,
                        minWidth: 160,
                      }}
                    >
                      Submit
                    </Button>
                  </Stack>
                </Stack>
              ) : null}
            </CardContent>
          </SoftCard>

          {/* Sidebar */}
          <Stack spacing={2}>
            <SidePanel title="Guidance" icon={<InfoOutlined fontSize="small" />}>
              <Typography variant="body2" color="text.secondary">
                Keep context brief and factual. Prefer original artifacts. Do
                not alter submitted content unless required by policy.
              </Typography>

              <Divider sx={{ opacity: 0.25 }} />

              <Stack spacing={1}>
                <Chip label="URL / domain: include full path if known" variant="outlined" />
                <Chip label="Hash: specify algorithm if known" variant="outlined" />
                <Chip label="File: keep original filename" variant="outlined" />
              </Stack>
            </SidePanel>

            <SidePanel
              title="Accepted inputs"
              icon={<InsertDriveFileOutlined fontSize="small" />}
            >
              <Stack spacing={1}>
                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                  <InsertDriveFileOutlined fontSize="small" color="action" />
                  <Typography variant="body2" color="text.secondary">
                    Files and attachments
                  </Typography>
                </Stack>
                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                  <LinkOutlined fontSize="small" color="action" />
                  <Typography variant="body2" color="text.secondary">
                    Full URLs and bare domains
                  </Typography>
                </Stack>
                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                  <FingerprintOutlined fontSize="small" color="action" />
                  <Typography variant="body2" color="text.secondary">
                    Hashes and file indicators
                  </Typography>
                </Stack>
                <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                  <PublicOutlined fontSize="small" color="action" />
                  <Typography variant="body2" color="text.secondary">
                    IP addresses
                  </Typography>
                </Stack>
              </Stack>
            </SidePanel>

            <SidePanel
              title="Forward suspicious email"
              icon={<ContentCopyOutlined fontSize="small" />}
            >
              <Typography variant="body2" color="text.secondary">
                Alternative intake channel. Click to copy the reporting address.
              </Typography>

              <Button
                variant="outlined"
                onClick={copyEmail}
                startIcon={<ContentCopyOutlined />}
                sx={{
                  mt: 0.5,
                  borderRadius: 2,
                  textTransform: "none",
                  fontWeight: 800,
                }}
                fullWidth
              >
                {suspiciousEmail}
              </Button>
            </SidePanel>
          </Stack>
        </Box>

        <Alert severity="info" sx={{ borderRadius: 3 }}>
          Submit one artifact at a time for cleaner triage and easier backend
          correlation.
        </Alert>
      </Stack>

      {/* ------------------------------------------------------------------ */}
      {/* Loading overlay                                                     */}
      {/* ------------------------------------------------------------------ */}
      <Dialog open={loadingOpen} onClose={() => {}} maxWidth="xs" fullWidth>
        <DialogContent sx={{ py: 4 }}>
          <Stack spacing={2} sx={{ alignItems: "center", textAlign: "center" }} >
            <CircularProgress />
            <Typography sx={{ fontWeight: 850 }} >Processing submission</Typography>
            <Typography variant="body2" color="text.secondary">
              Waiting for the backend to validate and queue the artifact.
            </Typography>
            <Box sx={{ width: "100%", pt: 0.5 }}>
              <LinearProgress sx={{ borderRadius: 999, height: 8 }} />
            </Box>
          </Stack>
        </DialogContent>
      </Dialog>
    </Container>
    </Skeleton>
  );
}