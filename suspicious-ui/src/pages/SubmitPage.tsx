// src/pages/SubmitPage.tsx
import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogContent,
  Divider,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import {
  ContentCopyOutlined,
  UploadFileOutlined,
  LinkOutlined,
  FingerprintOutlined,
  CheckCircleOutlined,
  InfoOutlined,
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

function GlassCard(props: React.PropsWithChildren<{ sx?: any }>) {
  return (
    <Card
      sx={{
        borderRadius: 4,
        border: "1px solid rgba(255,255,255,.10)",
        background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
        ...props.sx,
      }}
    >
      {props.children}
    </Card>
  );
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

/** --- API stubs --- */
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

function ModeTile(props: {
  active: boolean;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  onClick: () => void;
  tag?: string;
}) {
  return (
    <Card
      sx={{
        borderRadius: 4,
        border: props.active ? "1px solid rgba(255,255,255,.28)" : "1px solid rgba(255,255,255,.10)",
        background: props.active
          ? "radial-gradient(900px 240px at 10% 10%, rgba(56,189,248,.18), transparent 60%)," +
            "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))"
          : "linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02))",
        transform: props.active ? "translateY(-1px)" : "none",
        transition: "transform 120ms ease, border-color 120ms ease",
      }}
    >
      <CardActionArea onClick={props.onClick} sx={{ borderRadius: 4 }}>
        <CardContent sx={{ p: 2 }}>
          <Stack direction="row" spacing={1.5} alignItems="flex-start">
            <Box
              sx={{
                width: 44,
                height: 44,
                borderRadius: 3,
                display: "grid",
                placeItems: "center",
                border: "1px solid rgba(255,255,255,.12)",
                background: "rgba(255,255,255,.04)",
              }}
            >
              {props.icon}
            </Box>

            <Box sx={{ flex: 1 }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography fontWeight={950}>{props.title}</Typography>
                {props.tag ? <Chip size="small" label={props.tag} variant="outlined" /> : null}
                {props.active ? (
                  <Chip size="small" icon={<CheckCircleOutlined />} label="Selected" variant="outlined" />
                ) : null}
              </Stack>

              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.25 }}>
                {props.subtitle}
              </Typography>
            </Box>
          </Stack>
        </CardContent>
      </CardActionArea>
    </Card>
  );
}

export default function SubmitPage() {
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

  // --- Mutations (declare BEFORE any derived usage) ---
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

  // --- Derived loading (AFTER declarations) ---
  const loadingOpen = urlMutation.isPending || iocMutation.isPending || fileMutation.isPending;

  // --- Guards ---
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
    <Box sx={{ p: { xs: 2, md: 3 }, maxWidth: 1180, mx: "auto", pb: 8 }}>
      {/* Hero */}
      <GlassCard
        sx={{
          mb: 2,
          overflow: "hidden",
          background:
            "radial-gradient(900px 260px at 12% 10%, rgba(56,189,248,.22), transparent 60%)," +
            "radial-gradient(900px 260px at 88% 30%, rgba(120,119,198,.18), transparent 60%)," +
            "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
        }}
      >
        <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
          <Stack spacing={0.7}>
            <Typography variant="h4" fontWeight={980} letterSpacing={-0.6}>
              Submit
            </Typography>
            <Typography color="text.secondary">
              Fast intake for security triage. Choose the right input type, add minimal context, ship it.
            </Typography>
          </Stack>

          <Divider sx={{ my: 2, opacity: 0.25 }} />

          {/* Mode selector */}
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", md: "1fr 1fr 1fr" },
              gap: 1.5,
            }}
          >
            <ModeTile
              active={mode === "file"}
              title="File"
              subtitle="Upload an attachment for analysis (drag & drop)."
              icon={<UploadFileOutlined />}
              onClick={() => setMode("file")}
              tag="Recommended"
            />
            <ModeTile
              active={mode === "url"}
              title="URL"
              subtitle="Submit a link for reputation & detonation workflows."
              icon={<LinkOutlined />}
              onClick={() => setMode("url")}
            />
            <ModeTile
              active={mode === "ioc"}
              title="Hash & IP"
              subtitle="Submit an indicator (hash / IP) for correlation."
              icon={<FingerprintOutlined />}
              onClick={() => setMode("ioc")}
            />
          </Box>
        </CardContent>
      </GlassCard>

      {/* Main layout */}
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", lg: "1.25fr .75fr" },
          gap: 2,
          alignItems: "start",
        }}
      >
        {/* Form panel */}
        <GlassCard>
          <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
            {mode === "file" ? (
              <Stack spacing={2}>
                <Stack spacing={0.5}>
                  <Typography variant="h5" fontWeight={980}>
                    File upload
                  </Typography>
                  <Typography color="text.secondary">Drop a file, add context if needed, then upload.</Typography>
                </Stack>

                <Box
                  {...dropzone.getRootProps()}
                  sx={{
                    borderRadius: 4,
                    border: dropzone.isDragActive
                      ? "1px solid rgba(56,189,248,.55)"
                      : "1px dashed rgba(255,255,255,.20)",
                    background: dropzone.isDragActive ? "rgba(56,189,248,.06)" : "rgba(255,255,255,.03)",
                    p: 3,
                    cursor: "pointer",
                    transition: "border-color 120ms ease, background 120ms ease",
                    outline: "none",
                  }}
                >
                  <input {...dropzone.getInputProps()} />
                  <Stack spacing={1} alignItems="center" textAlign="center">
                    <Box
                      sx={{
                        width: 56,
                        height: 56,
                        borderRadius: 3,
                        display: "grid",
                        placeItems: "center",
                        border: "1px solid rgba(255,255,255,.12)",
                        background: "rgba(255,255,255,.04)",
                      }}
                    >
                      <UploadFileOutlined />
                    </Box>

                    <Typography fontWeight={950}>
                      {selectedFile
                        ? "File selected"
                        : dropzone.isDragActive
                          ? "Drop it here"
                          : "Drag & drop or click to browse"}
                    </Typography>

                    {selectedFile ? (
                      <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", justifyContent: "center" }}>
                        <Chip label={selectedFile.name} variant="outlined" />
                        <Chip label={formatBytes(selectedFile.size)} variant="outlined" />
                        <Button
                          size="small"
                          variant="text"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedFile(null);
                          }}
                          sx={{ textTransform: "none" }}
                        >
                          Remove
                        </Button>
                      </Stack>
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        Single file. Limits are enforced server-side.
                      </Typography>
                    )}
                  </Stack>
                </Box>

                <TextField
                  label="Context (optional)"
                  placeholder="Where did you get it? Why is it suspicious?"
                  multiline
                  minRows={3}
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
                    sx={{ borderRadius: 3, textTransform: "none", fontWeight: 950 }}
                  >
                    Upload
                  </Button>
                </Stack>
              </Stack>
            ) : null}

            {mode === "url" ? (
              <Stack spacing={2}>
                <Stack spacing={0.5}>
                  <Typography variant="h5" fontWeight={980}>
                    URL submission
                  </Typography>
                  <Typography color="text.secondary">Provide a valid URL and optional context for triage.</Typography>
                </Stack>

                <TextField
                  label="URL"
                  placeholder="https://example.com/..."
                  error={!!urlForm.formState.errors.url}
                  helperText={urlForm.formState.errors.url?.message}
                  {...urlForm.register("url")}
                />
                <TextField
                  label="Context (optional)"
                  placeholder="Source, email subject, observed behavior..."
                  multiline
                  minRows={3}
                  {...urlForm.register("context")}
                />

                <Stack direction="row" justifyContent="flex-end">
                  <Button
                    variant="contained"
                    disabled={!urlForm.formState.isValid || urlMutation.isPending}
                    onClick={urlForm.handleSubmit((v) => urlMutation.mutate(v))}
                    sx={{ borderRadius: 3, textTransform: "none", fontWeight: 950 }}
                  >
                    Submit
                  </Button>
                </Stack>
              </Stack>
            ) : null}

            {mode === "ioc" ? (
              <Stack spacing={2}>
                <Stack spacing={0.5}>
                  <Typography variant="h5" fontWeight={980}>
                    Hash & IP
                  </Typography>
                  <Typography color="text.secondary">Paste an indicator. Context helps correlation.</Typography>
                </Stack>

                <TextField
                  label="Hash or IP"
                  placeholder="SHA256 / MD5 / IP"
                  error={!!iocForm.formState.errors.value}
                  helperText={iocForm.formState.errors.value?.message}
                  {...iocForm.register("value")}
                />
                <TextField
                  label="Context (optional)"
                  placeholder="Where it appeared, related case, user report..."
                  multiline
                  minRows={3}
                  {...iocForm.register("context")}
                />

                <Stack direction="row" justifyContent="flex-end">
                  <Button
                    variant="contained"
                    disabled={!iocForm.formState.isValid || iocMutation.isPending}
                    onClick={iocForm.handleSubmit((v) => iocMutation.mutate(v))}
                    sx={{ borderRadius: 3, textTransform: "none", fontWeight: 950 }}
                  >
                    Submit
                  </Button>
                </Stack>
              </Stack>
            ) : null}
          </CardContent>
        </GlassCard>

        {/* Side panel */}
        <Stack spacing={2}>
          <GlassCard>
            <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
              <Stack spacing={1}>
                <Stack direction="row" spacing={1} alignItems="center">
                  <InfoOutlined fontSize="small" />
                  <Typography fontWeight={950}>Guidance</Typography>
                </Stack>
                <Typography variant="body2" color="text.secondary">
                  Keep context short and factual. Prefer original artifacts. Don’t sanitize content unless required by
                  policy.
                </Typography>

                <Divider sx={{ my: 1.5, opacity: 0.25 }} />

                <Stack spacing={1}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Quick checks
                  </Typography>
                  <Chip label="URL: include full path" variant="outlined" />
                  <Chip label="Hash: specify algorithm if known" variant="outlined" />
                  <Chip label="File: keep original filename" variant="outlined" />
                </Stack>
              </Stack>
            </CardContent>
          </GlassCard>

          <GlassCard>
            <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
              <Typography fontWeight={950}>Forward suspicious email</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.25 }}>
                Alternative intake channel (click to copy):
              </Typography>

              <Button
                variant="outlined"
                onClick={copyEmail}
                startIcon={<ContentCopyOutlined />}
                sx={{ mt: 1.5, borderRadius: 3, textTransform: "none", fontWeight: 950 }}
                fullWidth
              >
                {suspiciousEmail}
              </Button>
            </CardContent>
          </GlassCard>
        </Stack>
      </Box>

      {/* Loading */}
      <Dialog open={loadingOpen} onClose={() => {}} maxWidth="xs" fullWidth>
        <DialogContent sx={{ py: 3 }}>
          <Stack spacing={2} alignItems="center" textAlign="center">
            <CircularProgress />
            <Typography fontWeight={950}>Processing…</Typography>
            <Typography variant="body2" color="text.secondary">
              Waiting for the backend to accept and queue your submission.
            </Typography>
          </Stack>
        </DialogContent>
      </Dialog>
    </Box>
  );
}
