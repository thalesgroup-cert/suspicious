import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";

export type ConfigField = {
  key: string;
  type: "str" | "int" | "bool" | "url" | "secret";
  required: boolean;
  default: unknown;
  help: string;
};

export type Connector = {
  name: string;
  version: string;
  description: string;
  author: string;
  docs_url: string;
  events: string[];
  schedules: { name: string; interval_seconds: number }[];
  config_schema: ConfigField[];
  enabled: boolean;
  enabled_by_default: boolean;
  last_health_ok: boolean | null;
  last_health_detail: string;
  last_health_at: string | null;
};

export type ConnectorDelivery = {
  id: number;
  event: string;
  case_id: number | null;
  status: "success" | "failed" | "skipped";
  error: string;
  duration_ms: number;
  attempt: number;
  created_at: string;
};

export async function listConnectors(): Promise<{
  connectors: Connector[];
  load_errors: Record<string, string>;
}> {
  const { data } = await api.get(endpoints.connectors);
  return data;
}

export async function setConnectorEnabled(name: string, enabled: boolean) {
  const { data } = await api.patch(`${endpoints.connectors}${name}/`, { enabled });
  return data as Connector;
}

export async function getConnectorConfig(name: string) {
  const { data } = await api.get(`${endpoints.connectors}${name}/config/`);
  return data.config as Record<string, unknown>;
}

export async function putConnectorConfig(
  name: string,
  config: Record<string, unknown>,
) {
  const { data } = await api.put(`${endpoints.connectors}${name}/config/`, config);
  return data.config as Record<string, unknown>;
}

export async function testConnector(name: string) {
  const { data } = await api.post(`${endpoints.connectors}${name}/test/`);
  return data as { ok: boolean; detail: string };
}

export async function listDeliveries(name: string, limit = 10) {
  const { data } = await api.get(
    `${endpoints.connectors}${name}/deliveries/?limit=${limit}`,
  );
  return data.results as ConnectorDelivery[];
}
