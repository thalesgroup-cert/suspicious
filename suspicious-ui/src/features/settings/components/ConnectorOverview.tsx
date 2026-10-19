import { Box, Link, Typography } from "@mui/material";

import { FactList, type Fact } from "@/features/settings/components/FactList";
import { StatusLabel, connectorStatus } from "@/features/settings/components/StatusLabel";
import type { Connector } from "@/features/settings/components/connectors";
import { scheduleText } from "@/features/settings/connectorConfig";

const visuallyHidden = {
  position: "absolute", width: "1px", height: "1px", overflow: "hidden", clip: "rect(0 0 0 0)", whiteSpace: "nowrap",
} as const;

// A javascript: or data: URL from a connector manifest must never become a clickable href.
function safeHttpUrl(raw: string): string | null {
  try {
    const url = new URL(raw);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}

function health(c: Connector) {
  if (c.last_health_ok === null) return { tone: "neutral", label: "Not checked yet" } as const;
  return c.last_health_ok
    ? ({ tone: "ok", label: "Healthy" } as const)
    : ({ tone: "danger", label: "Unhealthy" } as const);
}

export function ConnectorOverview({ connector }: { connector: Connector }) {
  const status = connectorStatus(connector);
  const h = health(connector);
  const docs = safeHttpUrl(connector.docs_url);
  const items: Fact[] = [
    { key: "Status", value: <StatusLabel tone={status.tone} label={status.label} /> },
    {
      key: "Health",
      value: (
        <Box>
          <StatusLabel tone={h.tone} label={h.label} />
          {connector.last_health_detail && (
            <Typography variant="body2" color="text.secondary">{connector.last_health_detail}</Typography>
          )}
        </Box>
      ),
    },
    { key: "Events", value: connector.events.length ? connector.events.join(", ") : "None" },
    {
      key: "Schedules",
      value: connector.schedules.length
        ? connector.schedules.map((s) => <Box key={s.name}>{`${s.name}: ${scheduleText(s.interval_seconds)}`}</Box>)
        : "None",
    },
    { key: "Author", value: connector.author || "Not provided" },
    { key: "Version", value: connector.version },
    {
      key: "Documentation",
      value: docs ? (
        <Link href={docs} target="_blank" rel="noopener noreferrer" underline="always">
          {docs}
          <Box component="span" sx={visuallyHidden}>{" "}(opens in a new tab)</Box>
        </Link>
      ) : (
        "Not provided"
      ),
    },
  ];
  return <FactList items={items} />;
}
