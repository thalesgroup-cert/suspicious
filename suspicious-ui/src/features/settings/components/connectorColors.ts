import type { ResultColors } from "@/styles/colorStore";
import type { Connector, ConnectorDelivery } from "./connectors";

export function getConnectorStatusColor(
  status: Connector["status"],
  colors: ResultColors,
): string {
  switch (status) {
    case "connected":
      return colors.safe.main;
    case "partial":
      return colors.suspicious.main;
    case "disabled":
    default:
      return colors.inconclusive.main;
  }
}

export function getDeliveryStatusColor(
  status: ConnectorDelivery["status"],
  colors: ResultColors,
): string {
  switch (status) {
    case "success":
      return colors.safe.main;
    case "failed":
      return colors.dangerous.main;
    case "skipped":
    default:
      return colors.inconclusive.main;
  }
}
