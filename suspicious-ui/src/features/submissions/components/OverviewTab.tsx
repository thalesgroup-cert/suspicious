import * as React from "react";
import { Box, Button, Chip, LinearProgress, Stack, Typography } from "@mui/material";
import { alpha } from "@mui/material/styles";
import type { SubmissionAnalyzerReport, SubmissionCaseInfos, SubmissionRow } from "@/features/submissions/api";
import { ResultChip } from "@/shared/components/ResultChip";
import { CopyIconButton } from "@/shared/components/CopyIconButton";
import MailPreview from "@/shared/components/MailPreview";
import { getRiskTone, normalizeScore } from "@/shared/lib/scoreUtils";
import { monoStack } from "@/styles/themes";

const BADGE_W = 132;

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <Typography variant="subtitle2" component="h3" color="text.secondary" sx={{ mb: 1 }}>
      {children}
    </Typography>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Box component="section" sx={{ px: 2.25, py: 2 }}>
      <SectionTitle>{title}</SectionTitle>
      {children}
    </Box>
  );
}

function Stat({ label, value, pct, hex }: { label: string; value: string | null; pct: number; hex?: string }) {
  return (
    <Box>
      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{label}</Typography>
      <Typography variant="h3" component="p" sx={{ my: 0.5 }}>{value ?? "—"}</Typography>
      {value != null ? (
        <LinearProgress
          variant="determinate"
          value={pct}
          aria-label={label}
          // Themes paint bars with their accent gradient; the verdict colour replaces it here.
          sx={hex ? {
            height: 4, borderRadius: 999, bgcolor: alpha(hex, 0.2),
            "& .MuiLinearProgress-bar": { bgcolor: hex, backgroundImage: "none", boxShadow: "none" },
          } : { height: 4, borderRadius: 999 }}
        />
      ) : null}
    </Box>
  );
}

/** Risk label in the theme's error/warning palette (themes restyle Chip colours, so set them explicitly). */
function RiskChip({ label, tone }: { label: string; tone: "error" | "warning" }) {
  return (
    <Chip
      size="small"
      variant="outlined"
      label={label}
      sx={(theme) => {
        const c = theme.palette[tone];
        return {
          flexShrink: 0,
          color: theme.palette.mode === "dark" ? c.light : c.dark,
          borderColor: alpha(c.main, 0.5),
          bgcolor: alpha(c.main, 0.1),
        };
      }}
    />
  );
}

export type OverviewTabProps = {
  row: SubmissionRow;
  reports: SubmissionAnalyzerReport[];
  ci: SubmissionCaseInfos | undefined;
  multi: boolean;
  observableCount: number;
  noAnalyzersRan: boolean;
  verdictHex?: string;
  onSeeAll: () => void;
};

export function OverviewTab({ row, reports, ci, multi, observableCount, noAnalyzersRan, verdictHex, onSeeAll }: OverviewTabProps) {
  // Highest-risk successful analyzers above "Low risk": a failed run carries no verdict signal.
  const topRisks = React.useMemo(
    () =>
      reports
        .filter((r) => String(r.status).toLowerCase() === "success" && getRiskTone(r.score).label !== "Low risk")
        .sort((a, b) => normalizeScore(b.score) - normalizeScore(a.score))
        .slice(0, 3),
    [reports]
  );
  const hasAi = !!ci && [ci.classification_ai, ci.score_ai, ci.confidence_ai, ci.category_ai].some((v) => v != null && v !== "");
  const aiUnclassified = !!ci && ci.score_ai === 0 && ci.confidence_ai === 0;

  return (
    <Stack>
      <Box sx={{ px: 2.25, pt: 2, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2.5 }}>
        <Stat label="Score" value={ci?.score != null ? `${ci.score}/10` : null} pct={normalizeScore(ci?.score)} hex={verdictHex} />
        <Stat label="Confidence" value={ci?.confidence != null ? `${ci.confidence}%` : null} pct={Math.min(100, ci?.confidence ?? 0)} hex={verdictHex} />
      </Box>

      {noAnalyzersRan ? (
        <Box sx={{ px: 2.25, pt: 2 }}>
          <Typography variant="body2" color="text.secondary">
            No analyzers ran for this submission.
          </Typography>
        </Box>
      ) : null}

      {topRisks.length > 0 ? (
        <Section title="Why this verdict">
          <Stack component="ul" spacing={1} sx={{ m: 0, p: 0, listStyle: "none" }}>
            {topRisks.map((r) => {
              const tone = getRiskTone(r.score);
              return (
                <Stack component="li" key={r.id} direction="row" spacing={1.5} sx={{ alignItems: "center", minWidth: 0 }}>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography variant="body2" sx={{ fontWeight: 650 }}>{r.analyzer_name || "Unknown analyzer"}</Typography>
                    {r.target?.value ? (
                      <Typography variant="caption" color="text.secondary" noWrap title={r.target.value}
                        sx={{ display: "block", fontFamily: monoStack }}>
                        {r.target.value}
                      </Typography>
                    ) : null}
                  </Box>
                  <RiskChip label={tone.label} tone={tone.label === "High risk" ? "error" : "warning"} />
                </Stack>
              );
            })}
          </Stack>
          <Button size="small" onClick={onSeeAll} sx={{ mt: 1.25 }}>
            See all {reports.length} in Analysis
          </Button>
        </Section>
      ) : null}

      {ci ? (
        <Section title="Sources">
          <Stack spacing={1.5}>
            <Box>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>Verdict</Typography>
              <Stack direction="row" useFlexGap spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
                <ResultChip result={String(ci.classification ?? "UNKNOWN")} minWidth={BADGE_W} />
                <Chip size="small" label={`Score ${ci.score ?? "—"}/10`} variant="outlined" />
                <Chip size="small" label={`Confidence ${ci.confidence ?? "—"}%`} variant="outlined" />
              </Stack>
            </Box>
            {hasAi ? (
              <Box>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>AI classifier</Typography>
                {aiUnclassified ? (
                  <Typography variant="body2" color="text.secondary">Not classified</Typography>
                ) : (
                  <Stack direction="row" useFlexGap spacing={0.75} sx={{ flexWrap: "wrap" }}>
                    {[
                      ci.classification_ai ? String(ci.classification_ai) : null,
                      `score ${ci.score_ai ?? "—"}`,
                      `conf ${ci.confidence_ai ?? "—"}%`,
                      ci.category_ai ? `cat ${ci.category_ai}` : null,
                    ].filter((l): l is string => !!l).map((label) => (
                      <Chip key={label} size="small" label={label} variant="outlined" sx={{ typography: "caption" }} />
                    ))}
                  </Stack>
                )}
              </Box>
            ) : null}
          </Stack>
        </Section>
      ) : null}

      {multi ? (
        <Section title="Summary">
          <Typography variant="body2">{row.artifact || "—"}</Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
            {observableCount} observable{observableCount !== 1 ? "s" : ""}
          </Typography>
        </Section>
      ) : (
        <Section title={String(row.type).toUpperCase() === "MAIL" ? "Subject" : "Artifact"}>
          <Stack direction="row" spacing={0.5}
            sx={{ alignItems: "flex-start", p: 1.25, borderRadius: 1, bgcolor: "action.hover", border: 1, borderColor: "divider" }}>
            <Typography variant="body2" sx={{ flex: 1, minWidth: 0, fontFamily: monoStack, wordBreak: "break-all" }}>
              {row.artifact || "—"}
            </Typography>
            {row.artifact ? <CopyIconButton text={row.artifact} title="Copy artifact" /> : null}
          </Stack>
        </Section>
      )}

      {row.mail_preview_url ? (
        <Section title="Email preview">
          <MailPreview url={row.mail_preview_url} variant="full" alt={`Preview of email for case ${row.id}`} />
        </Section>
      ) : null}
    </Stack>
  );
}
