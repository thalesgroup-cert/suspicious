import type { ConfigField, Connector, ConnectorDelivery } from "@/features/settings/components/connectors";

const ACRONYMS = new Set(["url", "api", "id", "ip", "ssl", "tls", "smtp", "imap"]);

/** The schema carries no label today, so de-snaking the key is the normal path. */
export function fieldLabel(field: Pick<ConfigField, "key"> & { label?: string }): string {
  if (field.label) return field.label;
  return field.key
    .split(/[._]+/)
    .filter(Boolean)
    .map((w) => (ACRONYMS.has(w.toLowerCase()) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(" ");
}

// Descriptions end with an internal "See docs/..." pointer that means nothing to an operator.
// The pointer must be a whole sentence (path, then a period before whitespace/end), or text
// such as "See docs/x.md for details." would be cut in half.
const DOCS_POINTER = /(?<=^|[.!?]\s+)See\s+(?:also\s+)?docs\/\S+?\.(?=\s|$)\s*/g;

export function cleanDescription(text: string): string {
  return text.replace(DOCS_POINTER, "").trimEnd();
}

export const CONNECTOR_STATUS_LABEL: Record<Connector["status"], string> = {
  connected: "Connected",
  partial: "Incomplete",
  disabled: "Disabled",
};

export const DELIVERY_STATUS_LABEL: Record<ConnectorDelivery["status"], string> = {
  success: "Delivered",
  failed: "Failed",
  skipped: "Skipped",
};
