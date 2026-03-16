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

/** API */
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

/** Validation */
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
          ? alpha(theme.palette.primary.main, theme.palette.mode === "dark" ? 0.10 : 0.06)
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
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
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
          <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
            <Typography fontWeight={850}>{props.title}</Typography>

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
      <Typography variant="h5" fontWeight={850} letterSpacing={-0.4}>
        {props.title}
      </Typography>
      <Typography color="text.secondary">{props.subtitle}</Typography>
    </Stack>
  );
}

function SidePanel(props: React.PropsWithChildren<{ title: string; icon: React.ReactNode }>) {
  return (
    <SoftCard>
      <CardContent sx={{ p: 2.25 }}>
        <Stack spacing={1.25}>
          <Stack direction="row" spacing={1} alignItems="center">
            {props.icon}
            <Typography fontWeight={850}>{props.title}</Typography>
          </Stack>
          {props.children}
        </Stack>
      </CardContent>
    </SoftCard>
  );
}

export default function SubmitPage() {
  const theme = useTheme();
  const { enqueueSnackbar } = useSnackbar();

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

  const suspiciousEmailEnv = import.meta.env.VITE_SUSPICIOUS_EMAIL as string | undefined;

  const configQuery = useQuery({
    queryKey: ["submitConfig"],
    queryFn: getSubmitConfig,
    retry: false,
    enabled: !!me && !suspiciousEmailEnv,
    initialData: { suspicious_email: suspiciousEmailEnv ?? "suspicious@example.com" },
  });

  const suspiciousEmail = suspiciousEmailEnv ?? configQuery.data.suspicious_email;

  const [mode, setMode] = React.useState<SubmitMode>("file");
  const [selectedFile, setSelectedFile] = React.useState<File | null>(null);

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

  const dropzone = useDropzone({
    multiple: false,
    onDrop: (files) => {
      const f = files?.[0];
      if (f) setSelectedFile(f);
    },
  });

  const urlMutation = useMutation({
    mutationFn: submitUrl,
    onSuccess: (res) => {
      enqueueSnackbar(
        res?.id
          ? `URL submitted successfully (case #${res.id}).`
          : (res?.message ?? "URL submitted."),
        { variant: "success" }
      );
      urlForm.reset();
    },
    onError: () => {
      enqueueSnackbar("Submission failed (URL). Check endpoint / permissions.", {
        variant: "error",
      });
    },
  });

  const iocMutation = useMutation({
    mutationFn: submitIoc,
    onSuccess: (res) => {
      enqueueSnackbar(
        res?.id
          ? `Indicator submitted successfully (case #${res.id}).`
          : (res?.message ?? "Indicator submitted."),
        { variant: "success" }
      );
      iocForm.reset();
    },
    onError: () => {
      enqueueSnackbar("Submission failed (Hash/IP). Check endpoint / permissions.", {
        variant: "error",
      });
    },
  });

  const fileMutation = useMutation({
    mutationFn: submitFile,
    onSuccess: (res) => {
      enqueueSnackbar(
        res?.id
          ? `File submitted successfully (case #${res.id}).`
          : (res?.message ?? "File uploaded."),
        { variant: "success" }
      );
      setSelectedFile(null);
      fileForm.reset();
    },
    onError: () => {
      enqueueSnackbar("Upload failed (File). Check endpoint / size limits.", {
        variant: "error",
      });
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

  return (
    <Container maxWidth="lg" sx={{ py: { xs: 2.5, md: 3.5 }, pb: 8 }}>
      <Stack spacing={2}>
        {/* Header */}
        <SoftCard>
          <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
            <Stack spacing={2}>
              <Stack spacing={0.6}>
                <Typography variant="h4" fontWeight={900} letterSpacing={-0.6}>
                  Submit
                </Typography>
                <Typography color="text.secondary" sx={{ maxWidth: 760 }}>
                  Send a file, URL, hash, or IP for security triage. Choose the artifact type,
                  add short factual context, and submit it for analysis.
                </Typography>
              </Stack>

              <Divider sx={{ opacity: 0.25 }} />

              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: { xs: "1fr", md: "repeat(3, 1fr)" },
                  gap: 1.5,
                }}
              >
                <ModeSelectorCard
                  active={mode === "file"}
                  title="File"
                  subtitle="Upload an attachment or sample for analysis."
                  icon={<UploadFileOutlined />}
                  helper="Recommended"
                  onClick={() => setMode("file")}
                />
                <ModeSelectorCard
                  active={mode === "url"}
                  title="URL"
                  subtitle="Submit a link for reputation and detonation workflows."
                  icon={<LinkOutlined />}
                  onClick={() => setMode("url")}
                />
                <ModeSelectorCard
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
                        ? alpha(theme.palette.primary.main, theme.palette.mode === "dark" ? 0.08 : 0.04)
                        : alpha(theme.palette.background.default, theme.palette.mode === "dark" ? 0.24 : 0.45),
                      px: 3,
                      py: 4.5,
                      cursor: "pointer",
                      transition: "all .14s ease",
                      outline: "none",
                    }}
                  >
                    <input {...dropzone.getInputProps()} />

                    <Stack spacing={1.5} alignItems="center" textAlign="center">
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
                        <Typography fontWeight={850}>
                          {selectedFile
                            ? "File selected"
                            : dropzone.isDragActive
                              ? "Drop file here"
                              : "Drag and drop or click to browse"}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                          One file per submission. Limits and acceptance rules are enforced server-side.
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

              {mode === "url" ? (
                <Stack spacing={2.5}>
                  <SectionHeader
                    title="URL submission"
                    subtitle="Submit a full URL. Include short context only when it helps explain where it came from."
                  />

                  <TextField
                    label="URL"
                    placeholder="https://example.com/path"
                    error={!!urlForm.formState.errors.url}
                    helperText={
                      urlForm.formState.errors.url?.message ??
                      "Use the full URL, including the path if relevant."
                    }
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
                      sx={{
                        borderRadius: 2,
                        textTransform: "none",
                        fontWeight: 850,
                        minWidth: 140,
                      }}
                    >
                      Submit URL
                    </Button>
                  </Stack>
                </Stack>
              ) : null}

              {mode === "ioc" ? (
                <Stack spacing={2.5}>
                  <SectionHeader
                    title="Hash or IP submission"
                    subtitle="Submit a single indicator. Specify brief context if it is connected to a report or case."
                  />

                  <TextField
                    label="Hash or IP"
                    placeholder="SHA256, MD5, SHA1, or IP address"
                    error={!!iocForm.formState.errors.value}
                    helperText={
                      iocForm.formState.errors.value?.message ??
                      "If you know the hash type, mention it in the context."
                    }
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
                      sx={{
                        borderRadius: 2,
                        textTransform: "none",
                        fontWeight: 850,
                        minWidth: 160,
                      }}
                    >
                      Submit indicator
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
                Keep context brief and factual. Prefer original artifacts. Do not alter submitted
                content unless required by policy.
              </Typography>

              <Divider sx={{ opacity: 0.25 }} />

              <Stack spacing={1}>
                <Chip label="URL: include full path" variant="outlined" />
                <Chip label="Hash: specify algorithm if known" variant="outlined" />
                <Chip label="File: keep original filename" variant="outlined" />
              </Stack>
            </SidePanel>

            <SidePanel title="Accepted inputs" icon={<InsertDriveFileOutlined fontSize="small" />}>
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
            </SidePanel>

            <SidePanel title="Forward suspicious email" icon={<ContentCopyOutlined fontSize="small" />}>
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
          Submit one artifact at a time for cleaner triage and easier backend correlation.
        </Alert>
      </Stack>

      <Dialog open={loadingOpen} onClose={() => {}} maxWidth="xs" fullWidth>
        <DialogContent sx={{ py: 4 }}>
          <Stack spacing={2} alignItems="center" textAlign="center">
            <CircularProgress />
            <Typography fontWeight={850}>Processing submission</Typography>
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
  );
}