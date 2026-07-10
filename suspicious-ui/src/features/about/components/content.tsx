import * as React from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Divider,
  Stack,
  Typography,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  ArrowForwardOutlined,
  CheckCircleOutlined,
  ExpandMoreRounded,
  HelpOutlineOutlined,
  ShieldOutlined,
  WarningAmberOutlined,
} from "@mui/icons-material";

import { IconBadge, SoftCard } from "@/features/about/components/cards";

export type Severity = "dangerous" | "suspicious" | "inconclusive" | "safe";

const SEVERITY_CONFIG: Record<
  Severity,
  { icon: React.ReactNode; colorKey: "error" | "warning" | "info" | "success"; label: string }
> = {
  dangerous:    { icon: <WarningAmberOutlined />,   colorKey: "error",   label: "Dangerous" },
  suspicious:   { icon: <ShieldOutlined />,         colorKey: "warning", label: "Suspicious" },
  inconclusive: { icon: <HelpOutlineOutlined />,    colorKey: "info",    label: "Inconclusive" },
  safe:         { icon: <CheckCircleOutlined />,    colorKey: "success", label: "Safe" },
};

export function SeverityCard(props: {
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
      <Box
        sx={{
          height: 3,
          borderRadius: "16px 16px 0 0",
          background: `linear-gradient(90deg, ${tone}, ${alpha(tone, 0.3)})`,
        }}
      />

      <Box sx={{ p: 2.25 }}>
        <Stack spacing={1.75}>
          <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }} >
            <IconBadge icon={cfg.icon} size={40} color={tone} />
            <Box>
              <Typography sx={{ color: tone, fontWeight: 950, fontSize: 15 }}>
                {props.title}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12 }}>
                {props.subtitle}
              </Typography>
            </Box>
          </Stack>

          <Divider sx={{ opacity: isDark ? 0.14 : 0.45 }} />

          <Stack spacing={0.6}>
            {props.bullets.map((bullet) => (
              <Stack key={bullet} direction="row" spacing={0.75} sx={{ alignItems: "center" }} >
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

export function StepCard(props: {
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
          <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }} >
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

            <Typography sx={{ fontWeight: 950, fontSize: 15 }} >{props.title}</Typography>

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

export function TopicCard(props: {
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
          <Stack direction="row" spacing={1.25} sx={{ alignItems: "center" }} >
            <IconBadge icon={props.icon} size={42} />
            <Box>
              <Typography sx={{ fontWeight: 950, fontSize: 15, letterSpacing: -0.2 }} >
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

export function SimpleAccordion(props: {
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
        <Stack direction="row" spacing={1.5} sx={{ pr: 2, alignItems: "center" }}>
          <IconBadge icon={props.icon} size={36} />
          <Box>
            <Typography sx={{ fontWeight: 900, fontSize: 14 }} >{props.title}</Typography>
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
