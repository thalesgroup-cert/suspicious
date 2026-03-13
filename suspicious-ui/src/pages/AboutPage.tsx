// src/pages/AboutPage.tsx
import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  Container,
  Divider,
  Link,
  Stack,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Card,
  Grid,
  useTheme,
  alpha,
} from "@mui/material";
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
} from "@mui/icons-material";

type Severity = "dangerous" | "suspicious" | "inconclusive" | "safe";

function PageSection(props: React.PropsWithChildren<{ title?: string; subtitle?: string }>) {
  return (
    <Box>
      {props.title ? (
        <Stack spacing={0.75} sx={{ mb: 2 }}>
          <Typography variant="h5" fontWeight={800} letterSpacing={-0.4}>
            {props.title}
          </Typography>
          {props.subtitle ? (
            <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 760 }}>
              {props.subtitle}
            </Typography>
          ) : null}
        </Stack>
      ) : null}
      {props.children}
    </Box>
  );
}

function SoftCard(props: React.PropsWithChildren<{ sx?: any }>) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Card
      elevation={0}
      sx={{
        borderRadius: 4,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.3 : 0.9)}`,
        background: isDark
          ? `linear-gradient(180deg, ${alpha("#fff", 0.03)}, ${alpha("#fff", 0.02)})`
          : `linear-gradient(180deg, ${alpha("#fff", 0.9)}, ${alpha(theme.palette.grey[50], 0.96)})`,
        boxShadow: isDark
          ? "0 10px 30px rgba(0,0,0,.28)"
          : "0 8px 24px rgba(15,23,42,.06)",
        ...props.sx,
      }}
    >
      {props.children}
    </Card>
  );
}

function InfoPill(props: { icon: React.ReactElement; label: string }) {
  return (
    <Chip
      icon={props.icon}
      label={props.label}
      size="small"
      variant="outlined"
      sx={{
        borderRadius: 2.5,
        height: 30,
        "& .MuiChip-label": {
          px: 1.25,
          fontWeight: 600,
        },
      }}
    />
  );
}

function TopicCard(props: {
  icon: React.ReactNode;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  const theme = useTheme();

  return (
    <SoftCard sx={{ height: "100%" }}>
      <Box sx={{ p: 2.5 }}>
        <Stack spacing={1.5}>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <Box
              sx={{
                width: 40,
                height: 40,
                borderRadius: 3,
                display: "grid",
                placeItems: "center",
                border: `1px solid ${alpha(theme.palette.divider, 0.8)}`,
                background: alpha(theme.palette.primary.main, 0.08),
                color: "text.primary",
              }}
            >
              {props.icon}
            </Box>
            <Typography variant="h6" fontWeight={800} letterSpacing={-0.25}>
              {props.title}
            </Typography>
          </Stack>

          <Typography variant="body2" color="text.secondary">
            {props.description}
          </Typography>

          <Divider />

          <Box>{props.children}</Box>
        </Stack>
      </Box>
    </SoftCard>
  );
}

function SeverityCard(props: {
  severity: Severity;
  title: string;
  subtitle: string;
  bullets: string[];
}) {
  const theme = useTheme();

  const config = {
    dangerous: {
      icon: <WarningAmberOutlined fontSize="small" />,
      tone: theme.palette.error.main,
    },
    suspicious: {
      icon: <ShieldOutlined fontSize="small" />,
      tone: theme.palette.warning.main,
    },
    inconclusive: {
      icon: <HelpOutlineOutlined fontSize="small" />,
      tone: theme.palette.info.main,
    },
    safe: {
      icon: <CheckCircleOutlined fontSize="small" />,
      tone: theme.palette.success.main,
    },
  }[props.severity];

  return (
    <SoftCard sx={{ height: "100%" }}>
      <Box sx={{ p: 2.25 }}>
        <Stack spacing={1.5}>
          <Stack direction="row" spacing={1.25} alignItems="flex-start">
            <Box
              sx={{
                width: 38,
                height: 38,
                borderRadius: 2.5,
                display: "grid",
                placeItems: "center",
                border: `1px solid ${alpha(config.tone, 0.28)}`,
                background: alpha(config.tone, 0.12),
                color: config.tone,
                flexShrink: 0,
              }}
            >
              {config.icon}
            </Box>

            <Box>
              <Typography fontWeight={800}>{props.title}</Typography>
              <Typography variant="body2" color="text.secondary">
                {props.subtitle}
              </Typography>
            </Box>
          </Stack>

          <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
            {props.bullets.map((bullet) => (
              <Typography
                key={bullet}
                component="li"
                variant="body2"
                color="text.secondary"
                sx={{ mb: 0.75 }}
              >
                {bullet}
              </Typography>
            ))}
          </Box>
        </Stack>
      </Box>
    </SoftCard>
  );
}

function SimpleAccordion(props: {
  icon: React.ReactNode;
  title: string;
  summary: string;
  children: React.ReactNode;
  defaultExpanded?: boolean;
}) {
  const theme = useTheme();

  return (
    <Accordion
      disableGutters
      defaultExpanded={props.defaultExpanded}
      elevation={0}
      sx={{
        borderRadius: "16px !important",
        overflow: "hidden",
        border: `1px solid ${alpha(theme.palette.divider, 0.8)}`,
        background: "transparent",
        "&:before": { display: "none" },
      }}
    >
      <AccordionSummary
        expandIcon={<ExpandMoreRounded />}
        sx={{
          px: 2,
          py: 0.25,
          minHeight: 72,
          "& .MuiAccordionSummary-content": { my: 1.25 },
        }}
      >
        <Stack direction="row" spacing={1.25} alignItems="center" sx={{ pr: 2 }}>
          <Box sx={{ color: "text.secondary", display: "grid", placeItems: "center" }}>{props.icon}</Box>
          <Box>
            <Typography fontWeight={700}>{props.title}</Typography>
            <Typography variant="body2" color="text.secondary">
              {props.summary}
            </Typography>
          </Box>
        </Stack>
      </AccordionSummary>

      <AccordionDetails sx={{ px: 2, pb: 2 }}>
        <Divider sx={{ mb: 2 }} />
        {props.children}
      </AccordionDetails>
    </Accordion>
  );
}

export default function AboutPage() {
  const suspiciousEmail =
    (import.meta.env.VITE_SUSPICIOUS_EMAIL as string | undefined) ?? "security@example.com";

  return (
    <Container maxWidth="lg" sx={{ py: { xs: 3, md: 5 } }}>
      <Stack spacing={3}>
        {/* Hero */}
        <SoftCard>
          <Box sx={{ p: { xs: 2.5, md: 3.5 } }}>
            <Stack spacing={2}>
              <Stack spacing={1.25}>
                <Stack direction="row" spacing={1.25} alignItems="center">
                  <Box
                    sx={{
                      width: 44,
                      height: 44,
                      borderRadius: 3,
                      display: "grid",
                      placeItems: "center",
                      bgcolor: "action.hover",
                      border: (theme) => `1px solid ${alpha(theme.palette.divider, 0.8)}`,
                    }}
                  >
                    <InfoOutlined />
                  </Box>

                  <Box>
                    <Typography variant="h4" fontWeight={850} letterSpacing={-0.8}>
                      About Suspicious
                    </Typography>
                    <Typography color="text.secondary" sx={{ mt: 0.25 }}>
                      Security intake and automated analysis for emails, files, URLs, IPs, and hashes.
                    </Typography>
                  </Box>
                </Stack>

                <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                  <InfoPill icon={<EmailOutlined fontSize="small" />} label="Mail" />
                  <InfoPill icon={<InsertDriveFileOutlined fontSize="small" />} label="Files" />
                  <InfoPill icon={<LinkOutlined fontSize="small" />} label="URLs" />
                  <InfoPill icon={<PublicOutlined fontSize="small" />} label="IPs" />
                  <InfoPill icon={<FingerprintOutlined fontSize="small" />} label="Hashes" />
                  <InfoPill icon={<ShieldOutlined fontSize="small" />} label="Scoring & classification" />
                </Stack>
              </Stack>

              <Alert
                severity="info"
                sx={{
                  borderRadius: 3,
                  alignItems: "center",
                }}
              >
                You can forward suspicious emails to{" "}
                <Box component="span" sx={{ fontWeight: 700, userSelect: "all" }}>
                  {suspiciousEmail}
                </Box>
                .
              </Alert>
            </Stack>
          </Box>
        </SoftCard>

        {/* Quick explanation */}
        <PageSection
          title="How it works"
          subtitle="The platform collects submitted artifacts, runs analysis, and summarizes risk to support review and triage."
        >
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <SoftCard sx={{ height: "100%" }}>
                <Box sx={{ p: 2.25 }}>
                  <Stack spacing={1}>
                    <Typography fontWeight={800}>1. Submit</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Users submit emails, files, URLs, IPs, or hashes through the interface or by forwarding mail.
                    </Typography>
                  </Stack>
                </Box>
              </SoftCard>
            </Grid>

            <Grid item xs={12} md={4}>
              <SoftCard sx={{ height: "100%" }}>
                <Box sx={{ p: 2.25 }}>
                  <Stack spacing={1}>
                    <Typography fontWeight={800}>2. Analyze</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Relevant parts are extracted and checked by analyzers to identify signals, metadata, and known matches.
                    </Typography>
                  </Stack>
                </Box>
              </SoftCard>
            </Grid>

            <Grid item xs={12} md={4}>
              <SoftCard sx={{ height: "100%" }}>
                <Box sx={{ p: 2.25 }}>
                  <Stack spacing={1}>
                    <Typography fontWeight={800}>3. Classify</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Analyzer outputs are aggregated into a score and an overall classification to help prioritize action.
                    </Typography>
                  </Stack>
                </Box>
              </SoftCard>
            </Grid>
          </Grid>
        </PageSection>

        {/* Main info blocks */}
        <PageSection
          title="Key topics"
          subtitle="The most common questions are answered here without forcing users into another page or modal."
        >
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <TopicCard
                icon={<SecurityOutlined />}
                title="What is Suspicious?"
                description="A concise explanation of the platform, its purpose, and what it does with submitted artifacts."
              >
                <Stack spacing={1.25}>
                  <Typography variant="body2" color="text.secondary">
                    Suspicious is a triage-oriented platform for collecting suspicious content and running automated analysis
                    to help determine whether it should be escalated, reviewed, or dismissed.
                  </Typography>

                  <Typography variant="body2" color="text.secondary">
                    It is a decision aid. It helps structure and accelerate review, but it does not replace analyst judgment.
                  </Typography>
                </Stack>
              </TopicCard>
            </Grid>

            <Grid item xs={12} md={4}>
              <TopicCard
                icon={<WarningAmberOutlined />}
                title="What is phishing?"
                description="A short explanation of phishing and the main attack outcomes users should recognize."
              >
                <Stack spacing={1}>
                  <Typography variant="body2" color="text.secondary">
                    Phishing is a social engineering attack where an attacker imitates a trusted source to get credentials,
                    payments, access, or execution of malicious content.
                  </Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                    <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                      Credential theft
                    </Typography>
                    <Typography component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                      Malware delivery
                    </Typography>
                    <Typography component="li" variant="body2" color="text.secondary">
                      Invoice or payment fraud
                    </Typography>
                  </Box>
                </Stack>
              </TopicCard>
            </Grid>

            <Grid item xs={12} md={4}>
              <TopicCard
                icon={<InsertDriveFileOutlined />}
                title="File analysis"
                description="What is extracted, what may be compared, and what users should assume about unknown files."
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
        </PageSection>

        {/* Detailed sections */}
        <PageSection
          title="Details"
          subtitle="Secondary information stays available, but does not overload the first screen."
        >
          <Stack spacing={1.5}>
            <SimpleAccordion
              defaultExpanded
              icon={<DescriptionOutlined />}
              title="What gets analyzed"
              summary="Supported submission types and typical processing behavior."
            >
              <Stack spacing={1.25}>
                <Typography variant="body2" color="text.secondary">
                  The platform accepts emails, files, URLs, IP addresses, and hashes. Depending on the submission type,
                  analysis may include structure parsing, metadata extraction, indicator comparison, and correlation with
                  previous observations.
                </Typography>

                <Typography variant="body2" color="text.secondary">
                  For emails, relevant elements may include headers, body content, links, sender information, and attachments.
                </Typography>
              </Stack>
            </SimpleAccordion>

            <SimpleAccordion
              icon={<PolicyOutlined />}
              title="How to use the result"
              summary="Classification should guide action, not replace review."
            >
              <Stack spacing={1.25}>
                <Typography variant="body2" color="text.secondary">
                  The overall result should be used as a triage aid. It helps decide whether to isolate, escalate, request
                  more context, or close the case.
                </Typography>
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
              <Stack spacing={1.25}>
                <Typography variant="body2" color="text.secondary">
                  Users can forward suspicious messages directly to the reporting address below.
                </Typography>
                <Alert severity="info" sx={{ borderRadius: 3 }}>
                  Forwarding address:{" "}
                  <Box component="span" sx={{ fontWeight: 700, userSelect: "all" }}>
                    {suspiciousEmail}
                  </Box>
                </Alert>
              </Stack>
            </SimpleAccordion>
          </Stack>
        </PageSection>

        {/* Classification */}
        <PageSection
          title="Classification and guidance"
          subtitle="The four outcomes should be visually distinct and immediately actionable."
        >
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <SeverityCard
                severity="dangerous"
                title="Dangerous"
                subtitle="High confidence malicious"
                bullets={[
                  "Do not open or execute.",
                  "Treat content as untrusted.",
                  "Escalate or isolate if required.",
                ]}
              />
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <SeverityCard
                severity="suspicious"
                title="Suspicious"
                subtitle="Indicators suggest risk"
                bullets={[
                  "Avoid opening links or attachments.",
                  "Prefer validation by an analyst.",
                  "Monitor related activity.",
                ]}
              />
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <SeverityCard
                severity="inconclusive"
                title="Inconclusive"
                subtitle="Insufficient signal"
                bullets={[
                  "Proceed with caution.",
                  "Source trust may be unclear.",
                  "Request more context where possible.",
                ]}
              />
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <SeverityCard
                severity="safe"
                title="Safe"
                subtitle="Low signal detected"
                bullets={[
                  "No strong indicators found.",
                  "Still apply normal hygiene.",
                  "Re-submit if behavior changes.",
                ]}
              />
            </Grid>
          </Grid>
        </PageSection>

        {/* Small footer/help */}
        <Box sx={{ pt: 0.5 }}>
          <Typography variant="body2" color="text.secondary">
            This page is intended to help users understand what the platform does and how to interpret its output.
          </Typography>
        </Box>
      </Stack>
    </Container>
  );
}