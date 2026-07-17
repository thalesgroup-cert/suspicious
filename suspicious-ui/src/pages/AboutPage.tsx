import * as React from "react";
import { env } from "@/lib/runtimeEnv";
import {
  Alert,
  Box,
  Chip,
  Container,
  Divider,
  Stack,
  Typography,
  Grid,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  InfoOutlined,
  SecurityOutlined,
  InsertDriveFileOutlined,
  EmailOutlined,
  LinkOutlined,
  PublicOutlined,
  FingerprintOutlined,
  ShieldOutlined,
  WarningAmberOutlined,
  DescriptionOutlined,
  PolicyOutlined,
} from "@mui/icons-material";

import {
  CaptionLabel,
  IconBadge,
  InfoPill,
  InnerCard,
  SectionHeader,
  SoftCard,
} from "@/features/about/components/cards";
import {
  SeverityCard,
  SimpleAccordion,
  StepCard,
  TopicCard,
  type Severity,
} from "@/features/about/components/content";

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function AboutPage() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const suspiciousEmail = env("VITE_SUSPICIOUS_EMAIL") ?? "security@example.com";

  return (
    <Container maxWidth="lg" sx={{ py: { xs: 2.5, md: 4 }, pb: 8 }}>
      <Stack spacing={4}>

        {/* ──────────────────────────────────────────────────────────────── */}
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
              <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ alignItems: { sm: "center" } }} >
                <Stack direction="row" spacing={1.75} sx={{ flex: 1, minWidth: 0, alignItems: "center" }}>
                  <IconBadge icon={<InfoOutlined />} size={52} />
                  <Box>
                    <Typography variant="h4" sx={{ lineHeight: 1.15, fontWeight: 950, letterSpacing: -0.8 }}>
                      About Suspicious
                    </Typography>
                    <Typography color="text.secondary" sx={{ mt: 0.35, fontSize: 14 }}>
                      Security intake and automated analysis for emails, files, URLs, IPs, and hashes.
                    </Typography>
                  </Box>
                </Stack>
              </Stack>

              <Stack direction="row" spacing={0.75} useFlexGap sx={{ flexWrap: "wrap" }} >
                <InfoPill icon={<EmailOutlined fontSize="small" />} label="Mail" />
                <InfoPill icon={<InsertDriveFileOutlined fontSize="small" />} label="Files" />
                <InfoPill icon={<LinkOutlined fontSize="small" />} label="URLs" />
                <InfoPill icon={<PublicOutlined fontSize="small" />} label="IPs" />
                <InfoPill icon={<FingerprintOutlined fontSize="small" />} label="Hashes" />
                <InfoPill icon={<ShieldOutlined fontSize="small" />} label="Scoring & classification" />
              </Stack>

              <Divider sx={{ opacity: isDark ? 0.18 : 0.45 }} />

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
                      <Stack key={b} direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
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
                    <Stack direction="row" spacing={0.75} useFlexGap sx={{ flexWrap: "wrap" }} >
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
                      <Stack key={o} direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
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