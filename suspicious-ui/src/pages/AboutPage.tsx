// src/pages/AboutPage.tsx
import * as React from "react";
import {
  Alert,
  Box,
  Card,
  Chip,
  Container,
  Divider,
  Stack,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  ExpandMoreRounded,
  InfoOutlined,
  SecurityOutlined,
  InsertDriveFileOutlined,
  EmailOutlined,
  LinkOutlined,
  PublicOutlined,
  FingerprintOutlined,
  ShieldOutlined,
  WarningAmberOutlined,
  HelpOutlineOutlined,
  CheckCircleOutlined,
  DescriptionOutlined,
  PolicyOutlined,
  ArrowForwardOutlined,
} from "@mui/icons-material";

type Severity = "dangerous" | "suspicious" | "inconclusive" | "safe";

// ---------------------------------------------------------------------------
// SoftCard — exactly mirrors the rest of the app
// ---------------------------------------------------------------------------

function SoftCard(props: React.PropsWithChildren<{ sx?: object }>) {
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

// Tighter inner card — same as SettingsPage / ProfilePage
function InnerCard(props: React.PropsWithChildren<{ sx?: object }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Box
      sx={{
        borderRadius: 2.5,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.14 : 0.55)}`,
        background: isDark
          ? alpha("#fff", 0.025)
          : alpha(theme.palette.background.paper, 0.6),
        ...props.sx,
      }}
    >
      {props.children}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Shared icon badge
// ---------------------------------------------------------------------------

function IconBadge({
  icon,
  size = 40,
  color,
}: {
  icon: React.ReactNode;
  size?: number;
  color?: string;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Box
      sx={{
        width: size,
        height: size,
        borderRadius: size <= 36 ? 2 : 3,
        display: "grid",
        placeItems: "center",
        flexShrink: 0,
        border: `1px solid ${
          color
            ? alpha(color, isDark ? 0.32 : 0.35)
            : alpha(theme.palette.divider, isDark ? 0.22 : 0.6)
        }`,
        background: color
          ? alpha(color, isDark ? 0.1 : 0.08)
          : "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
        color: color ?? "text.primary",
        "& svg": { fontSize: size * 0.46 },
      }}
    >
      {icon}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Section header — consistent with other pages
// ---------------------------------------------------------------------------

function SectionHeader({
  title,
  subtitle,
}: {
  title: string;
  subtitle?: string;
}) {
  return (
    <Stack spacing={0.5} sx={{ mb: 2 }}>
      <Typography variant="h5" fontWeight={950} letterSpacing={-0.4}>
        {title}
      </Typography>
      {subtitle ? (
        <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 720 }}>
          {subtitle}
        </Typography>
      ) : null}
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// CaptionLabel — reused from SettingsPage / ProfilePage
// ---------------------------------------------------------------------------

function CaptionLabel({ children }: { children: React.ReactNode }) {
  return (
    <Typography
      variant="caption"
      color="text.disabled"
      sx={{
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: 0.6,
        fontSize: 10.5,
        display: "block",
      }}
    >
      {children}
    </Typography>
  );
}

// ---------------------------------------------------------------------------
// InfoPill — artifact type chips in the hero
// ---------------------------------------------------------------------------

function InfoPill(props: { icon: React.ReactElement; label: string }) {
  return (
    <Chip
      icon={props.icon}
      label={props.label}
      size="small"
      variant="outlined"
      sx={{
        borderRadius: 2.5,
        height: 28,
        fontWeight: 700,
        "& .MuiChip-label": { px: 1.1 },
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// SeverityCard — classification outcome card, enhanced
// ---------------------------------------------------------------------------

const SEVERITY_CONFIG: Record<
  Severity,
  { icon: React.ReactNode; colorKey: "error" | "warning" | "info" | "success"; label: string }
> = {
  dangerous:    { icon: <WarningAmberOutlined />,   colorKey: "error",   label: "Dangerous" },
  suspicious:   { icon: <ShieldOutlined />,         colorKey: "warning", label: "Suspicious" },
  inconclusive: { icon: <HelpOutlineOutlined />,    colorKey: "info",    label: "Inconclusive" },
  safe:         { icon: <CheckCircleOutlined />,    colorKey: "success", label: "Safe" },
};

function SeverityCard(props: {
  severity: Severity;
  title: string;
  subtitle: string;
  bullets: readonly string[];
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const cfg = SEVERITY_CONFIG[props.severity];
  const tone = theme.palette[cfg.colorKey].main;

  return (
    <SoftCard sx={{ height: "100%" }}>
      {/* Top accent line */}
      <Box
        sx={{
          height: 3,
          borderRadius: "16px 16px 0 0",
          background: `linear-gradient(90deg, ${tone}, ${alpha(tone, 0.3)})`,
        }}
      />

      <Box sx={{ p: 2.25 }}>
        <Stack spacing={1.75}>
          {/* Header */}
          <Stack direction="row" spacing={1.25} alignItems="center">
            <IconBadge icon={cfg.icon} size={40} color={tone} />
            <Box>
              <Typography fontWeight={950} fontSize={15} sx={{ color: tone }}>
                {props.title}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12 }}>
                {props.subtitle}
              </Typography>
            </Box>
          </Stack>

          <Divider sx={{ opacity: isDark ? 0.14 : 0.45 }} />

          {/* Bullets */}
          <Stack spacing={0.6}>
            {props.bullets.map((bullet) => (
              <Stack direction="row" spacing={0.75} alignItems="center">
                <Box
                  sx={{
                    width: 5,
                    height: 5,
                    borderRadius: 99,
                    bgcolor: tone,
                    flexShrink: 0,
                    opacity: 0.75,
                  }}
                />
                <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12.5, lineHeight: 1.55 }}>
                  {bullet}
                </Typography>
              </Stack>
            ))}
          </Stack>
        </Stack>
      </Box>
    </SoftCard>
  );
}

// ---------------------------------------------------------------------------
// StepCard — numbered flow step
// ---------------------------------------------------------------------------

function StepCard(props: {
  number: number;
  title: string;
  description: string;
  isLast?: boolean;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <SoftCard sx={{ height: "100%", position: "relative", overflow: "visible" }}>
      <Box sx={{ p: 2.5 }}>
        <Stack spacing={1.25}>
          {/* Step number badge */}
          <Stack direction="row" spacing={1.5} alignItems="center">
            <Box
              sx={{
                width: 36,
                height: 36,
                borderRadius: 2.5,
                display: "grid",
                placeItems: "center",
                background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, isDark ? 0.25 : 0.15)}, ${alpha(theme.palette.primary.main, isDark ? 0.12 : 0.07)})`,
                border: `1px solid ${alpha(theme.palette.primary.main, isDark ? 0.35 : 0.3)}`,
                flexShrink: 0,
              }}
            >
              <Typography
                sx={{
                  fontWeight: 950,
                  fontSize: 14,
                  color: theme.palette.primary.main,
                  lineHeight: 1,
                }}
              >
                {props.number}
              </Typography>
            </Box>

            <Typography fontWeight={950} fontSize={15}>{props.title}</Typography>

            {!props.isLast ? (
              <ArrowForwardOutlined
                sx={{
                  fontSize: 16,
                  color: "text.disabled",
                  ml: "auto",
                  display: { xs: "none", md: "block" },
                }}
              />
            ) : null}
          </Stack>

          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
            {props.description}
          </Typography>
        </Stack>
      </Box>
    </SoftCard>
  );
}

// ---------------------------------------------------------------------------
// TopicCard
// ---------------------------------------------------------------------------

function TopicCard(props: {
  icon: React.ReactNode;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <SoftCard sx={{ height: "100%" }}>
      <Box sx={{ p: 2.5 }}>
        <Stack spacing={1.75}>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <IconBadge icon={props.icon} size={42} />
            <Box>
              <Typography fontWeight={950} fontSize={15} letterSpacing={-0.2}>
                {props.title}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12 }}>
                {props.description}
              </Typography>
            </Box>
          </Stack>

          <Divider sx={{ opacity: isDark ? 0.14 : 0.45 }} />

          <Box>{props.children}</Box>
        </Stack>
      </Box>
    </SoftCard>
  );
}

// ---------------------------------------------------------------------------
// SimpleAccordion — same style as SubmissionsPage / InvestigationPage
// ---------------------------------------------------------------------------

function SimpleAccordion(props: {
  icon: React.ReactNode;
  title: string;
  summary: string;
  children: React.ReactNode;
  defaultExpanded?: boolean;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Accordion
      disableGutters
      defaultExpanded={props.defaultExpanded}
      elevation={0}
      sx={{
        borderRadius: "16px !important",
        overflow: "hidden",
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`,
        background: isDark
          ? `linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
          : `linear-gradient(180deg, ${alpha("#fff", 0.88)}, ${alpha(theme.palette.grey[50], 0.96)})`,
        boxShadow: isDark
          ? "0 6px 20px rgba(0,0,0,.22)"
          : "0 4px 14px rgba(15,23,42,.05)",
        "&:before": { display: "none" },
      }}
    >
      <AccordionSummary
        expandIcon={<ExpandMoreRounded />}
        sx={{
          px: 2.5,
          py: 0.5,
          minHeight: 68,
          "& .MuiAccordionSummary-content": { my: 1.25 },
        }}
      >
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ pr: 2 }}>
          <IconBadge icon={props.icon} size={36} />
          <Box>
            <Typography fontWeight={900} fontSize={14}>{props.title}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12.5 }}>
              {props.summary}
            </Typography>
          </Box>
        </Stack>
      </AccordionSummary>

      <AccordionDetails sx={{ px: 2.5, pb: 2.5 }}>
        <Divider sx={{ mb: 2, opacity: isDark ? 0.14 : 0.45 }} />
        {props.children}
      </AccordionDetails>
    </Accordion>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function AboutPage() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const suspiciousEmail =
    (import.meta.env.VITE_SUSPICIOUS_EMAIL as string | undefined) ?? "security@example.com";

  return (
    <Container maxWidth="lg" sx={{ py: { xs: 2.5, md: 4 }, pb: 8 }}>
      <Stack spacing={4}>

        {/* ──────────────────────────────────────────────────────────────── */}
        {/* 1. HERO                                                          */}
        {/* ──────────────────────────────────────────────────────────────── */}
        <SoftCard
          sx={{
            overflow: "hidden",
            background: isDark
              ? `radial-gradient(900px 300px at 5% 0%, ${alpha("#4FB3FF", 0.1)}, transparent 60%),
                 radial-gradient(700px 260px at 95% 40%, ${alpha("#7C3AED", 0.08)}, transparent 60%),
                 linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
              : `radial-gradient(900px 300px at 5% 0%, ${alpha("#3B82F6", 0.07)}, transparent 60%),
                 radial-gradient(700px 260px at 95% 40%, ${alpha("#7C3AED", 0.05)}, transparent 60%),
                 linear-gradient(180deg, ${alpha("#fff", 0.92)}, ${alpha(theme.palette.grey[50], 0.98)})`,
          }}
        >
          <Box sx={{ p: { xs: 2.5, md: 3.5 } }}>
            <Stack spacing={2.5}>
              {/* Identity row */}
              <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }}>
                <Stack direction="row" spacing={1.75} alignItems="center" sx={{ flex: 1, minWidth: 0 }}>
                  <IconBadge icon={<InfoOutlined />} size={52} />
                  <Box>
                    <Typography variant="h4" fontWeight={950} letterSpacing={-0.8} sx={{ lineHeight: 1.15 }}>
                      About Suspicious
                    </Typography>
                    <Typography color="text.secondary" sx={{ mt: 0.35, fontSize: 14 }}>
                      Security intake and automated analysis for emails, files, URLs, IPs, and hashes.
                    </Typography>
                  </Box>
                </Stack>
              </Stack>

              {/* Artifact type pills */}
              <Stack direction="row" spacing={0.75} useFlexGap flexWrap="wrap">
                <InfoPill icon={<EmailOutlined fontSize="small" />} label="Mail" />
                <InfoPill icon={<InsertDriveFileOutlined fontSize="small" />} label="Files" />
                <InfoPill icon={<LinkOutlined fontSize="small" />} label="URLs" />
                <InfoPill icon={<PublicOutlined fontSize="small" />} label="IPs" />
                <InfoPill icon={<FingerprintOutlined fontSize="small" />} label="Hashes" />
                <InfoPill icon={<ShieldOutlined fontSize="small" />} label="Scoring & classification" />
              </Stack>

              <Divider sx={{ opacity: isDark ? 0.18 : 0.45 }} />

              {/* Report address */}
              <Alert severity="info" sx={{ borderRadius: 3 }}>
                Forward suspicious emails to{" "}
                <Box component="span" sx={{ fontWeight: 900, userSelect: "all" }}>
                  {suspiciousEmail}
                </Box>
              </Alert>
            </Stack>
          </Box>
        </SoftCard>

        {/* ──────────────────────────────────────────────────────────────── */}
        {/* 2. CLASSIFICATION — moved up, first thing after hero            */}
        {/* ──────────────────────────────────────────────────────────────── */}
        <Box>
          <SectionHeader
            title="Classification outcomes"
            subtitle="Every submission resolves to one of four outcomes. These drive triage priority and the recommended action."
          />

          <Grid container spacing={2}>
            {(
              [
                {
                  severity: "dangerous" as Severity,
                  title: "Dangerous",
                  subtitle: "High confidence malicious",
                  bullets: [
                    "Do not open or execute.",
                    "Treat all content as untrusted.",
                    "Escalate or isolate immediately.",
                  ],
                },
                {
                  severity: "suspicious" as Severity,
                  title: "Suspicious",
                  subtitle: "Indicators suggest risk",
                  bullets: [
                    "Avoid opening links or attachments.",
                    "Prefer validation by an analyst.",
                    "Monitor related activity.",
                  ],
                },
                {
                  severity: "inconclusive" as Severity,
                  title: "Inconclusive",
                  subtitle: "Insufficient signal",
                  bullets: [
                    "Proceed with caution.",
                    "Source trust may be unclear.",
                    "Request more context where possible.",
                  ],
                },
                {
                  severity: "safe" as Severity,
                  title: "Safe",
                  subtitle: "Low signal detected",
                  bullets: [
                    "No strong indicators found.",
                    "Still apply normal hygiene.",
                    "Re-submit if behavior changes.",
                  ],
                },
              ] as const
            ).map((card) => (
              <Grid key={card.severity} size={{ xs: 12, sm: 6, md: 3 }}>
                <SeverityCard {...card} />
              </Grid>
            ))}
          </Grid>
        </Box>

        {/* ──────────────────────────────────────────────────────────────── */}
        {/* 3. HOW IT WORKS                                                  */}
        {/* ──────────────────────────────────────────────────────────────── */}
        <Box>
          <SectionHeader
            title="How it works"
            subtitle="The platform collects submitted artifacts, runs analysis, and summarizes risk to support review and triage."
          />

          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 4 }}>
              <StepCard
                number={1}
                title="Submit"
                description="Users submit emails, files, URLs, IPs, or hashes through the interface or by forwarding suspicious mail."
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <StepCard
                number={2}
                title="Analyze"
                description="Relevant parts are extracted and checked by analyzers to identify signals, metadata, and known matches."
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <StepCard
                number={3}
                title="Classify"
                isLast
                description="Analyzer outputs are aggregated into a score and classification to help prioritize the right response."
              />
            </Grid>
          </Grid>
        </Box>

        {/* ──────────────────────────────────────────────────────────────── */}
        {/* 4. KEY TOPICS                                                    */}
        {/* ──────────────────────────────────────────────────────────────── */}
        <Box>
          <SectionHeader
            title="Key topics"
            subtitle="Common questions answered inline — no modals, no extra navigation."
          />

          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 4 }}>
              <TopicCard
                icon={<SecurityOutlined />}
                title="What is Suspicious?"
                description="Platform purpose and scope."
              >
                <Stack spacing={1.25}>
                  <Typography variant="body2" color="text.secondary">
                    Suspicious is a triage-oriented platform for collecting suspicious content and running automated
                    analysis to help determine whether it should be escalated, reviewed, or dismissed.
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    It is a decision aid — it helps structure and accelerate review, but does not replace analyst judgment.
                  </Typography>
                </Stack>
              </TopicCard>
            </Grid>

            <Grid size={{ xs: 12, md: 4 }}>
              <TopicCard
                icon={<WarningAmberOutlined />}
                title="What is phishing?"
                description="A short explanation for users who may be unfamiliar."
              >
                <Stack spacing={1.25}>
                  <Typography variant="body2" color="text.secondary">
                    Phishing is a social engineering attack where an attacker imitates a trusted source to obtain
                    credentials, payments, access, or execute malicious content.
                  </Typography>
                  <Stack spacing={0.5}>
                    {["Credential theft", "Malware delivery", "Invoice or payment fraud"].map((b) => (
                      <Stack key={b} direction="row" spacing={0.75} alignItems="center">
                        <Box sx={{ width: 5, height: 5, borderRadius: 99, bgcolor: "warning.main", flexShrink: 0, opacity: 0.75 }} />
                        <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12.5 }}>{b}</Typography>
                      </Stack>
                    ))}
                  </Stack>
                </Stack>
              </TopicCard>
            </Grid>

            <Grid size={{ xs: 12, md: 4 }}>
              <TopicCard
                icon={<InsertDriveFileOutlined />}
                title="File analysis"
                description="What is extracted and what users should assume."
              >
                <Stack spacing={1.25}>
                  <Typography variant="body2" color="text.secondary">
                    Submitted files may be fingerprinted, inspected for metadata, and compared against prior sightings or
                    known references.
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Unknown files should be treated as untrusted until review is complete.
                  </Typography>
                </Stack>
              </TopicCard>
            </Grid>
          </Grid>
        </Box>

        {/* ──────────────────────────────────────────────────────────────── */}
        {/* 5. DETAILS — accordions                                          */}
        {/* ──────────────────────────────────────────────────────────────── */}
        <Box>
          <SectionHeader
            title="Details"
            subtitle="Secondary information stays accessible without overloading the first screen."
          />

          <Stack spacing={1.25}>
            <SimpleAccordion
              defaultExpanded
              icon={<DescriptionOutlined />}
              title="What gets analyzed"
              summary="Supported submission types and typical processing behavior."
            >
              <Stack spacing={1.5}>
                <InnerCard sx={{ p: 2 }}>
                  <Stack spacing={0.75}>
                    <CaptionLabel>Submission types</CaptionLabel>
                    <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
                      {["Emails", "Files", "URLs", "IP addresses", "Hashes"].map((t) => (
                        <Chip key={t} size="small" label={t} variant="outlined"
                          sx={{ borderRadius: 2, height: 24, fontWeight: 700, "& .MuiChip-label": { px: 1 } }} />
                      ))}
                    </Stack>
                  </Stack>
                </InnerCard>

                <Typography variant="body2" color="text.secondary">
                  Depending on the submission type, analysis may include structure parsing, metadata extraction,
                  indicator comparison, and correlation with previous observations.
                </Typography>

                <Typography variant="body2" color="text.secondary">
                  For emails, relevant elements may include headers, body content, links, sender information,
                  and attachments.
                </Typography>
              </Stack>
            </SimpleAccordion>

            <SimpleAccordion
              icon={<PolicyOutlined />}
              title="How to use the result"
              summary="Classification should guide action, not replace review."
            >
              <Stack spacing={1.5}>
                <Typography variant="body2" color="text.secondary">
                  The overall result should be used as a triage aid. It helps decide whether to isolate, escalate,
                  request more context, or close the case.
                </Typography>
                <InnerCard sx={{ p: 2 }}>
                  <Stack spacing={0.5}>
                    <CaptionLabel>Good outcomes to consider</CaptionLabel>
                    {["Isolate the artifact", "Escalate to security team", "Request context from the reporter", "Close with note if safe"].map((o) => (
                      <Stack key={o} direction="row" spacing={0.75} alignItems="center">
                        <Box sx={{ width: 5, height: 5, borderRadius: 99, bgcolor: "primary.main", flexShrink: 0, opacity: 0.7 }} />
                        <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12.5 }}>{o}</Typography>
                      </Stack>
                    ))}
                  </Stack>
                </InnerCard>
                <Typography variant="body2" color="text.secondary">
                  Final handling should still consider context, user report quality, and any supporting analyst review.
                </Typography>
              </Stack>
            </SimpleAccordion>

            <SimpleAccordion
              icon={<EmailOutlined />}
              title="Reporting suspicious email"
              summary="The simplest path for users who only want to submit a suspicious message."
            >
              <Stack spacing={1.5}>
                <Typography variant="body2" color="text.secondary">
                  Users can forward suspicious messages directly to the reporting address below. The subject and body
                  will be parsed automatically.
                </Typography>
                <Alert severity="info" sx={{ borderRadius: 2.5 }}>
                  Forwarding address:{" "}
                  <Box component="span" sx={{ fontWeight: 900, userSelect: "all" }}>
                    {suspiciousEmail}
                  </Box>
                </Alert>
              </Stack>
            </SimpleAccordion>
          </Stack>
        </Box>

        {/* ──────────────────────────────────────────────────────────────── */}
        {/* Footer note                                                      */}
        {/* ──────────────────────────────────────────────────────────────── */}
        <InnerCard sx={{ px: 2.5, py: 1.75 }}>
          <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12.5 }}>
            Classification outcomes are guidance, not verdicts.
          </Typography>
        </InnerCard>

      </Stack>
    </Container>
  );
}