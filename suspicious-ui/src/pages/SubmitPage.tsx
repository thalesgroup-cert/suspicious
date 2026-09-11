import * as React from "react";
import {
  Alert,
  Box,
  Button,
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
  InfoOutlined,
  InsertDriveFileOutlined,
  PublicOutlined,
  CloudUploadOutlined,
  FormatListBulletedOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useDropzone } from "react-dropzone";
import { useSnackbar } from "notistack";
import { useNavigate } from "react-router";

import { env } from "@/lib/runtimeEnv";
import { getMe, type Me } from "@/api/auth";

import {
  extractIocsFromFile,
  getSubmitConfig,
  submitFile,
  submitIndicators,
} from "@/features/submit/api";
import { parseIndicators } from "@/features/submit/parseIndicators";
import {
  ModeSelectorCard,
  SectionHeader,
  SidePanel,
  SoftCard,
} from "@/features/submit/components/cards";
import {
  fileSchema,
  type FileForm,
} from "@/features/submit/schema";
import type {
  SubmitIndicatorsResponse,
  SubmitMode,
  SubmitSuccessResponse,
} from "@/features/submit/types";
import {
  extractApiErrorMessage,
  formatBytes,
  resolveId,
} from "@/features/submit/utils";

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
  const [indicatorsText, setIndicatorsText] = React.useState("");
  const [indicatorsContext, setIndicatorsContext] = React.useState("");

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

  const iocFileMutation = useMutation({
    mutationFn: extractIocsFromFile,
    onSuccess: (res) => {
      if (!res.found) {
        enqueueSnackbar("No indicators found in that file.", { variant: "warning" });
        return;
      }
      setIndicatorsText((prev) =>
        prev.trim() ? `${prev.trimEnd()}\n${res.indicators}` : res.indicators,
      );
      enqueueSnackbar(
        `Added ${res.found} indicator(s) from file${
          res.skipped.length ? ` — ${res.skipped.length} token(s) not recognised` : ""
        }. Review below, then submit.`,
        { variant: "success" },
      );
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

  const indicatorsMutation = useMutation({
    mutationFn: () =>
      submitIndicators({
        indicators: indicatorsText,
        context: indicatorsContext || undefined,
      }),
    onSuccess: (res: SubmitIndicatorsResponse) => {
      enqueueSnackbar(
        `Submitted — ${res.observable_count} indicator(s), case #${res.case_id}`,
        { variant: "success" }
      );
      if (res.skipped.length) {
        enqueueSnackbar(
          `${res.skipped.length} line(s) not recognised and skipped`,
          { variant: "warning" }
        );
      }
      navigate(
        `/submissions?q=${encodeURIComponent(
          String(res.case_id)
        )}&open=${encodeURIComponent(String(res.case_id))}`
      );
      setIndicatorsText("");
      setIndicatorsContext("");
    },
    onError: (error) => {
      enqueueSnackbar(extractApiErrorMessage(error), { variant: "error" });
    },
  });

  const indicatorsPreview = React.useMemo(
    () => parseIndicators(indicatorsText),
    [indicatorsText]
  );

  const loadingOpen =
    fileMutation.isPending ||
    indicatorsMutation.isPending ||
    iocFileMutation.isPending;

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
    <Container data-tour="submit-form" maxWidth="lg" sx={{ py: { xs: 2.5, md: 3.5 }, pb: 8 }}>
      <Stack spacing={2}>
        {/* ---------------------------------------------------------------- */}
        {/* ---------------------------------------------------------------- */}
        <SoftCard>
          <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
            <Stack spacing={2}>
              <Stack spacing={0.6}>
                <Typography variant="h4" sx={{ fontWeight: 900, letterSpacing: -0.6 }} >
                  Submit
                </Typography>
                <Typography color="text.secondary" sx={{ maxWidth: 760 }}>
                  Upload a file or email, or paste one or many indicators
                  (URL, domain, hash, IP). Types are detected automatically;
                  add short factual context and submit for analysis.
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
                  subtitle="Upload an attachment, sample or email (.eml / .msg) for analysis."
                  icon={<UploadFileOutlined />}
                  onClick={() => switchMode("file")}
                />
                <ModeSelectorCard
                  active={mode === "indicators"}
                  title="Indicators"
                  subtitle="Paste one or many URLs, IPs, hashes or domains — or upload an IOC-list file. Type is detected automatically; analysed together as one case."
                  icon={<FormatListBulletedOutlined />}
                  helper="Recommended"
                  onClick={() => switchMode("indicators")}
                />
              </Box>
            </Stack>
          </CardContent>
        </SoftCard>

        {/* ---------------------------------------------------------------- */}
        {/* ---------------------------------------------------------------- */}
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: { xs: "1fr", lg: "minmax(0, 1fr) 320px" },
            gap: 2,
            alignItems: "start",
          }}
        >
          <SoftCard>
            <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
              {/* ---------------------------------------------------------- */}
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
              {/* ---------------------------------------------------------- */}
              {mode === "indicators" ? (
                <Stack spacing={2.5}>
                  <SectionHeader
                    title="Indicators"
                    subtitle="One per line, or comma / space separated. Defanged forms (hxxp://, [.]) are accepted."
                  />

                  <Stack
                    direction="row"
                    spacing={1}
                    sx={{ alignItems: "center", flexWrap: "wrap" }}
                  >
                    <Button
                      component="label"
                      variant="outlined"
                      size="small"
                      startIcon={<UploadFileOutlined fontSize="small" />}
                      disabled={iocFileMutation.isPending}
                      sx={{ textTransform: "none", borderRadius: 2 }}
                    >
                      {iocFileMutation.isPending ? "Reading…" : "Upload IOC list"}
                      <input
                        hidden
                        type="file"
                        accept=".txt,.csv,.json"
                        onChange={(e) => {
                          const f = e.target.files?.[0];
                          if (f) iocFileMutation.mutate(f);
                          e.target.value = "";
                        }}
                      />
                    </Button>
                    <Typography variant="caption" color="text.secondary">
                      .txt / .csv / .json — indicators are added below for review, not submitted yet.
                    </Typography>
                  </Stack>

                  <TextField
                    label="Indicators"
                    placeholder={"hxxp://evil[.]com\n8.8.8.8\n<sha256>"}
                    multiline
                    minRows={6}
                    value={indicatorsText}
                    onChange={(e) => setIndicatorsText(e.target.value)}
                  />

                  {indicatorsPreview.length ? (
                    <Stack spacing={0.75}>
                      {indicatorsPreview.map((p, i) => (
                        <Stack
                          key={`${p.value}-${i}`}
                          direction="row"
                          spacing={1}
                          sx={{ alignItems: "center", justifyContent: "space-between" }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ fontFamily: "monospace", wordBreak: "break-all" }}
                          >
                            {p.value}
                          </Typography>
                          <Chip
                            size="small"
                            label={p.type ?? "unrecognised"}
                            color={p.type ? "default" : "error"}
                          />
                        </Stack>
                      ))}
                    </Stack>
                  ) : null}

                  <Typography variant="body2" color="text.secondary">
                    {indicatorsPreview.filter((p) => p.type).length} indicator(s),{" "}
                    {indicatorsPreview.filter((p) => !p.type).length} unrecognised
                  </Typography>

                  <TextField
                    label="Context (optional)"
                    placeholder="Source, related case, user report…"
                    multiline
                    minRows={4}
                    value={indicatorsContext}
                    onChange={(e) => setIndicatorsContext(e.target.value)}
                  />

                  <Stack direction="row" sx={{ justifyContent: "flex-end" }} >
                    <Button
                      variant="contained"
                      disabled={
                        indicatorsPreview.filter((p) => p.type).length === 0 ||
                        indicatorsMutation.isPending
                      }
                      onClick={() => indicatorsMutation.mutate()}
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
          Related indicators submitted together are correlated as one case.
          Keep unrelated artifacts in separate submissions.
        </Alert>
      </Stack>

      {/* ------------------------------------------------------------------ */}
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