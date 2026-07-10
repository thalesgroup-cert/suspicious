/**
 * FeederHealthBadge — live runtime status of the email_feeder service.
 *
 * Polls GET /api/feeder/health/ (Admin/CERT-gated) every 30 s and
 * renders a coloured Chip:
 *   - green  "Online"          everything fine, recent poll
 *   - amber  "Stale"           feeder responds but has not polled in 5+ min
 *   - red    "Offline"         feeder /health unreachable
 *   - grey   "Loading…"        initial fetch
 *
 * Hovering the chip opens a Tooltip with the full payload (last poll,
 * emails processed, errors, error reason if offline) so an operator
 * can triage at a glance.
 */
import { Chip, Tooltip, Stack, Typography, Box, type ChipProps } from "@mui/material";
import CircleIcon from "@mui/icons-material/Circle";
import { useQuery } from "@tanstack/react-query";
import { getFeederHealth, type FeederHealth } from "@/features/settings/api";

type Tone = "online" | "stale" | "offline" | "loading";

const TONE_TO_COLOR: Record<Tone, ChipProps["color"]> = {
  online: "success",
  stale: "warning",
  offline: "error",
  loading: "default",
};

const TONE_TO_LABEL: Record<Tone, string> = {
  online: "Online",
  stale: "Stale",
  offline: "Offline",
  loading: "Loading…",
};

function classify(h: FeederHealth | undefined): Tone {
  if (!h) return "loading";
  if (!h.online) return "offline";
  if (h.stale) return "stale";
  return "online";
}

function fmtUnix(ts: number | null): string {
  if (!ts) return "never";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

function fmtDuration(seconds: number): string {
  if (seconds <= 0) return "0 s";
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${Math.round(seconds / 3600)} h`;
}

export type FeederHealthBadgeProps = {
  /** Set false to skip the polling query (e.g. user not Admin/CERT). */
  enabled?: boolean;
  /** Override label prefix shown before the tone (defaults to "Feeder"). */
  label?: string;
  size?: "small" | "medium";
};

export default function FeederHealthBadge({
  enabled = true,
  label = "Feeder",
  size = "small",
}: FeederHealthBadgeProps) {
  const query = useQuery<FeederHealth>({
    queryKey: ["feeder", "health"],
    queryFn: getFeederHealth,
    enabled,
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
    retry: false,
    staleTime: 15_000,
  });

  if (!enabled) return null;

  const tone = classify(query.data);
  const health = query.data;

  const tooltipBody = (
    <Stack spacing={0.5} sx={{ minWidth: 220 }}>
      <Typography variant="caption" sx={{ fontWeight: 800 }}>
        Email feeder · {TONE_TO_LABEL[tone]}
      </Typography>
      {health ? (
        <>
          <Row k="Last poll" v={fmtUnix(health.last_successful_poll)} />
          {health.online && health.last_successful_poll ? (
            <Row k="Polled" v={`${fmtDuration(health.stale_seconds)} ago`} />
          ) : null}
          <Row k="Processed" v={health.emails_processed_total.toString()} />
          <Row k="Errors" v={health.errors_total.toString()} />
          {health.online && health.checks?.imap ? (
            <Row
              k="IMAP"
              v={
                health.checks.imap.ok
                  ? `${health.checks.imap.healthy}/${health.checks.imap.configured} OK`
                  : `${health.checks.imap.healthy}/${health.checks.imap.configured} stale`
              }
            />
          ) : null}
          {health.online && health.checks?.minio ? (
            <Row k="MinIO" v={health.checks.minio.ok ? "OK" : "stale"} />
          ) : null}
          {health.error ? <Row k="Reason" v={health.error} /> : null}
          <Row k="Checked" v={fmtUnix(health.checked_at)} />
        </>
      ) : (
        <Typography variant="caption" color="text.secondary">
          Fetching status…
        </Typography>
      )}
    </Stack>
  );

  return (
    <Tooltip title={tooltipBody} arrow placement="bottom">
      <Chip
        size={size}
        color={TONE_TO_COLOR[tone]}
        icon={<CircleIcon sx={{ fontSize: 10 }} />}
        label={`${label}: ${TONE_TO_LABEL[tone]}`}
        sx={{ fontWeight: 800 }}
      />
    </Tooltip>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <Stack direction="row" spacing={1} sx={{ justifyContent: "space-between" }}>
      <Typography variant="caption" color="text.secondary">{k}</Typography>
      <Box sx={{ ml: "auto" }}>
        <Typography variant="caption" sx={{ fontWeight: 700 }}>{v}</Typography>
      </Box>
    </Stack>
  );
}
