// src/pages/SubmitPage.tsx
import * as React from "react";
import {
  Alert,
  alpha,
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
  Stack,
  TextField,
  Typography,
  useTheme,
} from "@mui/material";
import {
  ContentCopyOutlined,
  UploadFileOutlined,
  LinkOutlined,
  FingerprintOutlined,
  CheckCircleOutlined,
  InfoOutlined,
  InsertDriveFileOutlined,
  PublicOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useDropzone } from "react-dropzone";
import { useSnackbar } from "notistack";

import { api } from "@/api/client";
import { getMe, type Me } from "@/api/auth";

type SubmitMode = "file" | "url" | "ioc";

type SubmitResult = {
  id?: string | number;
  message?: string;
};

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

/** --- API --- */
async function submitUrl(input: { url: string; context?: string }): Promise<SubmitResult> {
  const res = await api.post("/submit/url/", input);
  return res.data;
}

async function submitIoc(input: { value: string; context?: string }): Promise<SubmitResult> {
  const res = await api.post("/submit/other/", input);
  return res.data;
}

async function submitFile(input: { file: File; context?: string }): Promise<SubmitResult> {
  const form = new FormData();
  form.append("file", input.file);
  if (input.context) form.append("context", input.context);

  const res = await api.post("/submit/file/", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return res.data;
}

async function getSubmitConfig(): Promise<{ suspicious_email: string }> {
  const res = await api.get("/submit/config/");
  return res.data;
}

/** --- Validation --- */
const urlSchema = z.object({
  url: z.string().min(1, "URL is required").url("Invalid URL"),
  context: z.string().optional(),
});

const iocSchema = z.object({
  value: z.string().min(1, "Hash or IP is required"),
  context: z.string().optional(),
});

const fileSchema = z.object({
  context: z.string().optional(),
});

type UrlForm = z.infer<typeof urlSchema>;
type IocForm = z.infer<typeof iocSchema>;
type FileForm = z.infer<typeof fileSchema>;

function SoftCard(props: React.PropsWithChildren<{ sx?: any }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Card
      elevation={0}
      sx={{
        borderRadius: 4,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`,
        background: isDark
          ? `linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
          : `linear-gradient(180deg, ${alpha("#fff", 0.88)}, ${alpha(theme.palette.grey[50], 0.96)})`,
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

function PageTitle(props: { title: string; subtitle: string }) {
  return (
    <Stack spacing={0.75}>
      <Typography variant="h4" fontWeight={850} letterSpacing={-0.8}>
        {props.title}
      </Typography>
      <Typography color="text.secondary" sx={{ maxWidth: 720 }}>
        {props.subtitle}
      </Typography>
    </Stack>
  );
}

function InputTypeCard(props: {
  active: boolean;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  onClick: () => void;
  helper?: string;
}) {
  const theme = useTheme();

  return (
    <Box
      onClick={props.onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") props.onClick();
      }}
      sx={{
        cursor: "pointer",
        borderRadius: 4,
        p: 2,
        border: `1px solid ${
          props.active
            ? alpha(theme.palette.primary.main, 0.45)
            : alpha(theme.palette.divider, 0.9)
        }`,
        background: props.active
          ? alpha(theme.palette.primary.main, theme.palette.mode === "dark" ? 0.1 : 0.06)
          : "transparent",
        transition: "border-color 120ms ease, background 120ms ease, transform 120ms ease",
        "&:hover": {
          borderColor: alpha(theme.palette.primary.main, 0.35),
          background: alpha(theme.palette.primary.main, theme.palette.mode === "dark" ? 0.08 : 0.045),
        },
      }}
    >
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
        <Box
          sx={{
            width: 42,
            height: 42,
            borderRadius: 3,
            display: "grid",
            placeItems: "center",
            border: `1px solid ${alpha(theme.palette.divider, 0.9)}`,
            background: alpha(theme.palette.background.paper, 0.4),
            flexShrink: 0,
          }}
        >
          {props.icon}
        </Box>

        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
            <Typography fontWeight={800}>{props.title}</Typography>
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

function SideNote(props: React.PropsWithChildren<{ title: string; icon: React.ReactNode }>) {
  return (
    <SoftCard>
      <CardContent sx={{ p: 2.5 }}>
        <Stack spacing={1.25}>
          <Stack direction="row" spacing={1} alignItems="center">
            {props.icon}
            <Typography fontWeight={800}>{props.title}</Typography>
          </Stack>
          {props.children}
        </Stack>
      </CardContent>
    </SoftCard>
  );
}

function ModeHeader(props: { title: string; subtitle: string }) {
  return (
    <Stack spacing={0.5}>
      <Typography variant="h5" fontWeight={820} letterSpacing={-0.4}>
        {props.title}
      </Typography>
      <Typography color="text.secondary">{props.subtitle}</Typography>
    </Stack>
  );
}

export default function SubmitPage() {
  const theme = useTheme();
  const { enqueueSnackbar } = useSnackbar();

  // --- Auth ---
  const useMockMe = import.meta.env.VITE_USE_MOCK_ME === "true";
  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
    enabled: !useMockMe,
  });

  const me: Me | undefined = useMockMe
    ? ({ id: 1, username: "mockuser", email: "mockuser@example.com" } as any)
    : meQuery.data;

  // --- Config ---
  const suspiciousEmailEnv = import.meta.env.VITE_SUSPICIOUS_EMAIL as string | undefined;
  const configQuery = useQuery({
    queryKey: ["submitConfig"],
    queryFn: getSubmitConfig,
    retry: false,
    enabled: !!me && !suspiciousEmailEnv,
    initialData: { suspicious_email: suspiciousEmailEnv ?? "suspicious@example.com" },
  });
  const suspiciousEmail = suspiciousEmailEnv ?? configQuery.data.suspicious_email;

  // --- UI state ---
  const [mode, setMode] = React.useState<SubmitMode>("file");

  // --- Forms ---
  const urlForm = useForm<UrlForm>({
    resolver: zodResolver(urlSchema),
    defaultValues: { url: "", context: "" },
    mode: "onChange",
  });

  const iocForm = useForm<IocForm>({
    resolver: zodResolver(iocSchema),
    defaultValues: { value: "", context: "" },
    mode: "onChange",
  });

  const fileForm = useForm<FileForm>({
    resolver: zodResolver(fileSchema),
    defaultValues: { context: "" },
    mode: "onChange",
  });

  // --- Dropzone ---
  const [selectedFile, setSelectedFile] = React.useState<File | null>(null);

  const dropzone = useDropzone({
    multiple: false,
    onDrop: (files) => {
      const f = files?.[0];
      if (f) setSelectedFile(f);
    },
  });

  // --- Mutations ---
  const urlMutation = useMutation({
    mutationFn: submitUrl,
    onSuccess: (res) => {
      enqueueSnackbar(res?.message ?? "URL submitted.", { variant: "success" });
      urlForm.reset();
    },
    onError: () => {
      enqueueSnackbar("Submission failed (URL). Check endpoint / permissions.", { variant: "error" });
    },
  });

  const iocMutation = useMutation({
    mutationFn: submitIoc,
    onSuccess: (res) => {
      enqueueSnackbar(res?.message ?? "Indicator submitted.", { variant: "success" });
      iocForm.reset();
    },
    onError: () => {
      enqueueSnackbar("Submission failed (Hash/IP). Check endpoint / permissions.", { variant: "error" });
    },
  });

  const fileMutation = useMutation({
    mutationFn: submitFile,
    onSuccess: (res) => {
      enqueueSnackbar(res?.message ?? "File uploaded.", { variant: "success" });
      setSelectedFile(null);
      fileForm.reset();
    },
    onError: () => {
      enqueueSnackbar("Upload failed (File). Check endpoint / size limits.", { variant: "error" });
    },
  });

  const loadingOpen = urlMutation.isPending || iocMutation.isPending || fileMutation.isPending;

  if (!useMockMe && meQuery.isLoading) {
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

  async function copyEmail() {
    try {
      await navigator.clipboard.writeText(suspiciousEmail);
      enqueueSnackbar("Email address copied.", { variant: "info" });
    } catch {
      enqueueSnackbar("Copy blocked by browser.", { variant: "warning" });
    }
  }

  const submitButtonLabel =
    mode === "file" ? "Upload file" : mode === "url" ? "Submit URL" : "Submit indicator";

  return (
    <Container maxWidth="lg" sx={{ py: { xs: 3, md: 5 }, pb: 8 }}>
      <Stack spacing={3}>
        {/* Header */}
        <SoftCard>
          <CardContent sx={{ p: { xs: 2.5, md: 3.5 } }}>
            <Stack spacing={2.5}>
              <PageTitle
                title="Submit"
                subtitle="Send a file, URL, hash, or IP for security triage. Choose the input type, add brief context, and submit."
              />

              <Divider />

              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: { xs: "1fr", md: "1fr 1fr 1fr" },
                  gap: 1.5,
                }}
              >
                <InputTypeCard
                  active={mode === "file"}
                  title="File"
                  subtitle="Upload an attachment or sample for analysis."
                  icon={<UploadFileOutlined />}
                  onClick={() => setMode("file")}
                  helper="Recommended"
                />
                <InputTypeCard
                  active={mode === "url"}
                  title="URL"
                  subtitle="Submit a link for reputation and detonation workflows."
                  icon={<LinkOutlined />}
                  onClick={() => setMode("url")}
                />
                <InputTypeCard
                  active={mode === "ioc"}
                  title="Hash & IP"
                  subtitle="Submit an indicator for lookup and correlation."
                  icon={<FingerprintOutlined />}
                  onClick={() => setMode("ioc")}
                />
              </Box>
            </Stack>
          </CardContent>
        </SoftCard>

        {/* Main content */}
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
            <CardContent sx={{ p: { xs: 2.5, md: 3 } }}>
              {mode === "file" ? (
                <Stack spacing={2.5}>
                  <ModeHeader
                    title="File upload"
                    subtitle="Drop a file or browse from your device. Add short context only if it helps triage."
                  />

                  <Box
                    {...dropzone.getRootProps()}
                    sx={{
                      borderRadius: 4,
                      border: `1px dashed ${
                        dropzone.isDragActive
                          ? alpha(theme.palette.primary.main, 0.55)
                          : alpha(theme.palette.divider, 0.9)
                      }`,
                      background: dropzone.isDragActive
                        ? alpha(theme.palette.primary.main, theme.palette.mode === "dark" ? 0.08 : 0.04)
                        : alpha(theme.palette.background.default, theme.palette.mode === "dark" ? 0.24 : 0.4),
                      px: 3,
                      py: 4.5,
                      cursor: "pointer",
                      transition: "border-color 120ms ease, background 120ms ease",
                      outline: "none",
                    }}
                  >
                    <input {...dropzone.getInputProps()} />

                    <Stack spacing={1.5} alignItems="center" textAlign="center">
                      <Box
                        sx={{
                          width: 56,
                          height: 56,
                          borderRadius: 3,
                          display: "grid",
                          placeItems: "center",
                          border: `1px solid ${alpha(theme.palette.divider, 0.9)}`,
                          background: alpha(theme.palette.background.paper, 0.5),
                        }}
                      >
                        <UploadFileOutlined />
                      </Box>

                      <Box>
                        <Typography fontWeight={800}>
                          {selectedFile
                            ? "File selected"
                            : dropzone.isDragActive
                              ? "Drop file here"
                              : "Drag and drop or click to browse"}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                          One file per submission. Limits are enforced server-side.
                        </Typography>
                      </Box>

                      {selectedFile ? (
                        <Stack
                          direction="row"
                          spacing={1}
                          useFlexGap
                          flexWrap="wrap"
                          justifyContent="center"
                        >
                          <Chip label={selectedFile.name} variant="outlined" />
                          <Chip label={formatBytes(selectedFile.size)} variant="outlined" />
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

                  <Stack direction="row" justifyContent="flex-end">
                    <Button
                      variant="contained"
                      disabled={!selectedFile || fileMutation.isPending}
                      onClick={() => {
                        const ctx = fileForm.getValues("context") ?? "";
                        if (selectedFile) fileMutation.mutate({ file: selectedFile, context: ctx });
                      }}
                      sx={{ borderRadius: 3, textTransform: "none", fontWeight: 800, minWidth: 140 }}
                    >
                      {submitButtonLabel}
                    </Button>
                  </Stack>
                </Stack>
              ) : null}

              {mode === "url" ? (
                <Stack spacing={2.5}>
                  <ModeHeader
                    title="URL submission"
                    subtitle="Submit a full URL. Include short context only when it helps explain where it came from."
                  />

                  <TextField
                    label="URL"
                    placeholder="https://example.com/path"
                    error={!!urlForm.formState.errors.url}
                    helperText={urlForm.formState.errors.url?.message ?? "Use the full URL, including the path if relevant."}
                    {...urlForm.register("url")}
                  />

                  <TextField
                    label="Context (optional)"
                    placeholder="Email subject, source, observed redirect, user report, or related case."
                    multiline
                    minRows={4}
                    {...urlForm.register("context")}
                  />

                  <Stack direction="row" justifyContent="flex-end">
                    <Button
                      variant="contained"
                      disabled={!urlForm.formState.isValid || urlMutation.isPending}
                      onClick={urlForm.handleSubmit((v) => urlMutation.mutate(v))}
                      sx={{ borderRadius: 3, textTransform: "none", fontWeight: 800, minWidth: 140 }}
                    >
                      {submitButtonLabel}
                    </Button>
                  </Stack>
                </Stack>
              ) : null}

              {mode === "ioc" ? (
                <Stack spacing={2.5}>
                  <ModeHeader
                    title="Hash or IP submission"
                    subtitle="Submit a single indicator. Specify brief context if it is connected to a report or case."
                  />

                  <TextField
                    label="Hash or IP"
                    placeholder="SHA256, MD5, SHA1, or IP address"
                    error={!!iocForm.formState.errors.value}
                    helperText={iocForm.formState.errors.value?.message ?? "If you know the hash type, mention it in context."}
                    {...iocForm.register("value")}
                  />

                  <TextField
                    label="Context (optional)"
                    placeholder="Where it appeared, related submission, hostname, user report, or case reference."
                    multiline
                    minRows={4}
                    {...iocForm.register("context")}
                  />

                  <Stack direction="row" justifyContent="flex-end">
                    <Button
                      variant="contained"
                      disabled={!iocForm.formState.isValid || iocMutation.isPending}
                      onClick={iocForm.handleSubmit((v) => iocMutation.mutate(v))}
                      sx={{ borderRadius: 3, textTransform: "none", fontWeight: 800, minWidth: 140 }}
                    >
                      {submitButtonLabel}
                    </Button>
                  </Stack>
                </Stack>
              ) : null}
            </CardContent>
          </SoftCard>

          {/* Sidebar */}
          <Stack spacing={2}>
            <SideNote title="Guidance" icon={<InfoOutlined fontSize="small" />}>
              <Typography variant="body2" color="text.secondary">
                Keep context brief and factual. Prefer original artifacts. Do not modify content unless required by policy.
              </Typography>

              <Divider />

              <Stack spacing={1}>
                <Chip label="URL: include full path" variant="outlined" />
                <Chip label="Hash: specify algorithm if known" variant="outlined" />
                <Chip label="File: keep original filename" variant="outlined" />
              </Stack>
            </SideNote>

            <SideNote title="Accepted inputs" icon={<InsertDriveFileOutlined fontSize="small" />}>
              <Stack spacing={1}>
                <Stack direction="row" spacing={1} alignItems="center">
                  <InsertDriveFileOutlined fontSize="small" color="action" />
                  <Typography variant="body2" color="text.secondary">
                    Files and attachments
                  </Typography>
                </Stack>
                <Stack direction="row" spacing={1} alignItems="center">
                  <LinkOutlined fontSize="small" color="action" />
                  <Typography variant="body2" color="text.secondary">
                    URLs and links
                  </Typography>
                </Stack>
                <Stack direction="row" spacing={1} alignItems="center">
                  <FingerprintOutlined fontSize="small" color="action" />
                  <Typography variant="body2" color="text.secondary">
                    Hashes and file indicators
                  </Typography>
                </Stack>
                <Stack direction="row" spacing={1} alignItems="center">
                  <PublicOutlined fontSize="small" color="action" />
                  <Typography variant="body2" color="text.secondary">
                    IP addresses
                  </Typography>
                </Stack>
              </Stack>
            </SideNote>

            <SideNote title="Forward suspicious email" icon={<ContentCopyOutlined fontSize="small" />}>
              <Typography variant="body2" color="text.secondary">
                Alternative intake channel. Click to copy the reporting address.
              </Typography>

              <Button
                variant="outlined"
                onClick={copyEmail}
                startIcon={<ContentCopyOutlined />}
                sx={{
                  mt: 0.5,
                  borderRadius: 3,
                  textTransform: "none",
                  fontWeight: 800,
                }}
                fullWidth
              >
                {suspiciousEmail}
              </Button>
            </SideNote>
          </Stack>
        </Box>

        <Alert severity="info" sx={{ borderRadius: 3 }}>
          Submit one artifact at a time for cleaner triage and easier correlation.
        </Alert>
      </Stack>

      {/* Loading */}
      <Dialog open={loadingOpen} onClose={() => {}} maxWidth="xs" fullWidth>
        <DialogContent sx={{ py: 4 }}>
          <Stack spacing={2} alignItems="center" textAlign="center">
            <CircularProgress />
            <Typography fontWeight={800}>Processing submission</Typography>
            <Typography variant="body2" color="text.secondary">
              Waiting for the backend to accept and queue the artifact.
            </Typography>
          </Stack>
        </DialogContent>
      </Dialog>
    </Container>
  );
}