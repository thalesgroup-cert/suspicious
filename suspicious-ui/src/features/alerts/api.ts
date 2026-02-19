import { api } from "@/api/client";

export type Alert = {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  created_at: string;
};

export async function listAlerts(): Promise<Alert[]> {
  const res = await api.get("/alerts/");
  return res.data;
}
