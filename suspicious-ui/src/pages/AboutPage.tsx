// src/pages/AboutPage.tsx
import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  Dialog,
  DialogContent,
  DialogTitle,
  Divider,
  Grid,
  IconButton,
  Stack,
  Typography,
} from "@mui/material";
import {
  CloseOutlined,
  InfoOutlined,
  SecurityOutlined,
  InsertDriveFileOutlined,
  EmailOutlined,
  LinkOutlined,
  FingerprintOutlined,
  PublicOutlined,
  ShieldOutlined,
  WarningAmberOutlined,
  HelpOutlineOutlined,
    CheckCircleOutlined,    
} from "@mui/icons-material";

type AboutModalKey = "suspicious" | "phishing" | "fileAnalysis";

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

function Pill(props: { icon: React.ReactNode; label: string }) {
  return <Chip size="small" icon={props.icon as any} label={props.label} variant="outlined" />;
}

function SeverityCard(props: {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  bullets: string[];
}) {
  return (
    <Box
      sx={{
        borderRadius: 4,
        border: "1px solid rgba(255,255,255,.10)",
        p: 2,
        background: "rgba(255,255,255,.03)",
      }}
    >
      <Stack direction="row" spacing={1.25} alignItems="flex-start">
        <Box
          sx={{
            width: 40,
            height: 40,
            borderRadius: 3,
            display: "grid",
            placeItems: "center",
            border: "1px solid rgba(255,255,255,.12)",
            background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
          }}
        >
          {props.icon}
        </Box>

        <Box sx={{ flex: 1 }}>
          <Typography fontWeight={950}>{props.title}</Typography>
          <Typography variant="body2" color="text.secondary">
            {props.subtitle}
          </Typography>

          <Box component="ul" sx={{ mt: 1, mb: 0, pl: 2 }}>
            {props.bullets.map((b) => (
              <Typography key={b} component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                {b}
              </Typography>
            ))}
          </Box>
        </Box>
      </Stack>
    </Box>
  );
}

export default function AboutPage() {
  // If you want auth gating like legacy, do it at route-level; About is usually safe to show.
  const suspiciousEmail =
    (import.meta.env.VITE_SUSPICIOUS_EMAIL as string | undefined) ?? "security@example.com";

  const [open, setOpen] = React.useState<AboutModalKey | null>(null);

  return (
    <Box sx={{ p: { xs: 2, md: 3 }, maxWidth: 1180, mx: "auto" }}>
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
          <Stack spacing={1.25}>
            <Stack direction="row" spacing={1} alignItems="center">
              <Box
                sx={{
                  width: 46,
                  height: 46,
                  borderRadius: 3,
                  display: "grid",
                  placeItems: "center",
                  border: "1px solid rgba(255,255,255,.12)",
                  background: "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                }}
              >
                <InfoOutlined />
              </Box>

              <Box sx={{ flex: 1 }}>
                <Typography variant="h4" fontWeight={980} letterSpacing={-0.6}>
                  About Suspicious
                </Typography>
                <Typography color="text.secondary">
                  Security intake and automated analysis for emails, files, URLs, IPs, and hashes.
                </Typography>
              </Box>
            </Stack>

            <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
              <Pill icon={<EmailOutlined fontSize="small" />} label="Mail" />
              <Pill icon={<InsertDriveFileOutlined fontSize="small" />} label="Files" />
              <Pill icon={<LinkOutlined fontSize="small" />} label="URLs" />
              <Pill icon={<PublicOutlined fontSize="small" />} label="IPs" />
              <Pill icon={<FingerprintOutlined fontSize="small" />} label="Hashes" />
              <Pill icon={<ShieldOutlined fontSize="small" />} label="Scoring + classification" />
            </Stack>

            <Divider sx={{ opacity: 0.25 }} />

            <Alert severity="info">
              You can forward suspicious emails to{" "}
              <b style={{ userSelect: "all" }}>{suspiciousEmail}</b>.
            </Alert>
          </Stack>
        </CardContent>
      </GlassCard>

      {/* Primary cards */}
      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Card
            sx={{
              height: "100%",
              borderRadius: 4,
              border: "1px solid rgba(255,255,255,.10)",
              background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
            }}
          >
            <CardActionArea sx={{ height: "100%" }} onClick={() => setOpen("suspicious")}>
              <CardContent sx={{ p: 2.5 }}>
                <Stack spacing={1.25}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <SecurityOutlined />
                    <Typography variant="h6" fontWeight={950} letterSpacing={-0.2}>
                      What is Suspicious?
                    </Typography>
                  </Stack>
                  <Typography variant="body2" color="text.secondary">
                    How intake works, what gets analyzed, and how classification is computed.
                  </Typography>
                  <Button
                    variant="outlined"
                    sx={{ alignSelf: "flex-start", borderRadius: 3, textTransform: "none", fontWeight: 900 }}
                  >
                    Read
                  </Button>
                </Stack>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card
            sx={{
              height: "100%",
              borderRadius: 4,
              border: "1px solid rgba(255,255,255,.10)",
              background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
            }}
          >
            <CardActionArea sx={{ height: "100%" }} onClick={() => setOpen("phishing")}>
              <CardContent sx={{ p: 2.5 }}>
                <Stack spacing={1.25}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <WarningAmberOutlined />
                    <Typography variant="h6" fontWeight={950} letterSpacing={-0.2}>
                      What is phishing?
                    </Typography>
                  </Stack>
                  <Typography variant="body2" color="text.secondary">
                    Definition, typical attacker tactics, and why rapid reporting matters.
                  </Typography>
                  <Button
                    variant="outlined"
                    sx={{ alignSelf: "flex-start", borderRadius: 3, textTransform: "none", fontWeight: 900 }}
                  >
                    Read
                  </Button>
                </Stack>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card
            sx={{
              height: "100%",
              borderRadius: 4,
              border: "1px solid rgba(255,255,255,.10)",
              background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
            }}
          >
            <CardActionArea sx={{ height: "100%" }} onClick={() => setOpen("fileAnalysis")}>
              <CardContent sx={{ p: 2.5 }}>
                <Stack spacing={1.25}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <InsertDriveFileOutlined />
                    <Typography variant="h6" fontWeight={950} letterSpacing={-0.2}>
                      File analysis
                    </Typography>
                  </Stack>
                  <Typography variant="body2" color="text.secondary">
                    What’s extracted, what’s compared, and what the platform never does.
                  </Typography>
                  <Button
                    variant="outlined"
                    sx={{ alignSelf: "flex-start", borderRadius: 3, textTransform: "none", fontWeight: 900 }}
                  >
                    Read
                  </Button>
                </Stack>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
      </Grid>

      {/* Classification quick view */}
      <GlassCard sx={{ mt: 2 }}>
        <CardContent sx={{ p: { xs: 2.25, md: 3 } }}>
          <Stack spacing={1.25}>
            <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
              <Stack direction="row" spacing={1} alignItems="center">
                <HelpOutlineOutlined />
                <Typography variant="h6" fontWeight={950} letterSpacing={-0.2}>
                  Classification and guidance
                </Typography>
              </Stack>
              <Chip size="small" label="Operator summary" variant="outlined" />
            </Stack>

            <Typography color="text.secondary">
              Suspicious computes an overall classification from analyzer reports. Use it as a decision aid,
              not a replacement for review.
            </Typography>

            <Divider sx={{ opacity: 0.25 }} />

            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <SeverityCard
                  title="Dangerous"
                  subtitle="High confidence malicious"
                  icon={<WarningAmberOutlined />}
                  bullets={[
                    "Do not open or execute.",
                    "Treat content as untrusted.",
                    "Escalate / isolate if needed.",
                  ]}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <SeverityCard
                  title="Suspicious"
                  subtitle="Indicators suggest risk"
                  icon={<ShieldOutlined />}
                  bullets={[
                    "Avoid opening attachments/links.",
                    "Prefer analyst validation.",
                    "Monitor related activity.",
                  ]}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <SeverityCard
                  title="Inconclusive"
                  subtitle="Insufficient signal"
                  icon={<HelpOutlineOutlined />}
                  bullets={[
                    "Proceed with caution.",
                    "Sources may be unknown.",
                    "Request more context if possible.",
                  ]}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <SeverityCard
                  title="Safe"
                  subtitle="Low signal detected"
                  icon={<CheckCircleOutlined />}
                  bullets={[
                    "No strong indicators found.",
                    "Still apply normal hygiene.",
                    "Re-submit if behavior changes.",
                  ]}
                />
              </Grid>
            </Grid>
          </Stack>
        </CardContent>
      </GlassCard>

      {/* Dialogs */}
      <Dialog open={open !== null} onClose={() => setOpen(null)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ pr: 6 }}>
          {open === "suspicious"
            ? "What is Suspicious?"
            : open === "phishing"
              ? "What is phishing?"
              : open === "fileAnalysis"
                ? "File analysis"
                : ""}
          <IconButton
            onClick={() => setOpen(null)}
            sx={{ position: "absolute", right: 10, top: 10 }}
            aria-label="Close"
          >
            <CloseOutlined />
          </IconButton>
        </DialogTitle>

        <DialogContent dividers>
          {open === "suspicious" ? (
            <Stack spacing={1.5}>
              <Typography variant="h6" fontWeight={950}>
                Overview
              </Typography>
              <Typography color="text.secondary">
                Suspicious is a web application that collects submissions (emails, files, IPs, URLs, hashes) and
                runs automated analysis to help classify risk and support triage workflows.
              </Typography>

              <Divider sx={{ opacity: 0.25 }} />

              <Typography variant="h6" fontWeight={950}>
                How it works
              </Typography>
              <Box component="ol" sx={{ pl: 2, m: 0 }}>
                <Typography component="li" color="text.secondary" sx={{ mb: 0.75 }}>
                  A reporter submits data (UI upload, URL/IP/hash form, or forwarded email).
                </Typography>
                <Typography component="li" color="text.secondary" sx={{ mb: 0.75 }}>
                  The submission is split into relevant parts (e.g., mail headers/body/attachments) and analyzed.
                </Typography>
                <Typography component="li" color="text.secondary" sx={{ mb: 0.75 }}>
                  Analyzers generate individual reports; Suspicious aggregates results into a score and classification.
                </Typography>
              </Box>

              <Divider sx={{ opacity: 0.25 }} />

              <Typography variant="h6" fontWeight={950}>
                Classification
              </Typography>
              <Typography color="text.secondary">
                Common classes: <b>Dangerous</b>, <b>Suspicious</b>, <b>Inconclusive</b>, <b>Safe</b>. The class is derived
                from analyzer outputs and weighting.
              </Typography>

              <Alert severity="info">
                Forwarding address: <b style={{ userSelect: "all" }}>{suspiciousEmail}</b>
              </Alert>
            </Stack>
          ) : null}

          {open === "phishing" ? (
            <Stack spacing={1.5}>
              <Typography variant="h6" fontWeight={950}>
                Definition
              </Typography>
              <Typography color="text.secondary">
                Phishing is a social engineering attack where an attacker impersonates a trusted entity to trick a
                recipient into revealing credentials, transferring money, or executing malicious content.
              </Typography>

              <Divider sx={{ opacity: 0.25 }} />

              <Typography variant="h6" fontWeight={950}>
                Typical outcomes
              </Typography>
              <Box component="ul" sx={{ pl: 2, m: 0 }}>
                <Typography component="li" color="text.secondary" sx={{ mb: 0.5 }}>
                  Credential theft (SSO, email, banking).
                </Typography>
                <Typography component="li" color="text.secondary" sx={{ mb: 0.5 }}>
                  Malware/ransomware installation via links or attachments.
                </Typography>
                <Typography component="li" color="text.secondary" sx={{ mb: 0.5 }}>
                  Business email compromise (invoice and payment fraud).
                </Typography>
              </Box>

              <Divider sx={{ opacity: 0.25 }} />

              <Typography variant="h6" fontWeight={950}>
                Why Suspicious helps
              </Typography>
              <Typography color="text.secondary">
                It speeds up triage by analyzing artifacts and summarizing risk signals, helping you decide whether to
                escalate, isolate, or dismiss.
              </Typography>
            </Stack>
          ) : null}

          {open === "fileAnalysis" ? (
            <Stack spacing={1.5}>
              <Typography variant="h6" fontWeight={950}>
                What happens when you submit a file
              </Typography>
              <Typography color="text.secondary">
                Suspicious can compute file fingerprints (hashes) and inspect metadata. Hashes may be compared against
                known sources and internal history to detect prior sightings.
              </Typography>

              <Divider sx={{ opacity: 0.25 }} />

              <Typography variant="h6" fontWeight={950}>
                Safety model
              </Typography>
              <Box component="ul" sx={{ pl: 2, m: 0 }}>
                <Typography component="li" color="text.secondary" sx={{ mb: 0.5 }}>
                  Files are analyzed for identification and attributes; avoid executing unknown content.
                </Typography>
                <Typography component="li" color="text.secondary" sx={{ mb: 0.5 }}>
                  Results are used to classify risk and help responders prioritize.
                </Typography>
              </Box>

              <Divider sx={{ opacity: 0.25 }} />

              <Alert severity="warning">
                Treat unknown attachments as untrusted until analysis and review are complete.
              </Alert>
            </Stack>
          ) : null}
        </DialogContent>
      </Dialog>
    </Box>
  );
}
