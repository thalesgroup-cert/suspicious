import { describe, expect, it } from "vitest";
import { PRESET_DEFAULT } from "@/styles/colorStore";
import { getConnectorStatusColor, getDeliveryStatusColor } from "../connectorColors";

describe("getConnectorStatusColor", () => {
  it("maps connected to the safe color", () => {
    expect(getConnectorStatusColor("connected", PRESET_DEFAULT.result)).toBe(
      PRESET_DEFAULT.result.safe.main,
    );
  });

  it("maps partial to the suspicious color", () => {
    expect(getConnectorStatusColor("partial", PRESET_DEFAULT.result)).toBe(
      PRESET_DEFAULT.result.suspicious.main,
    );
  });

  it("maps disabled to the inconclusive color", () => {
    expect(getConnectorStatusColor("disabled", PRESET_DEFAULT.result)).toBe(
      PRESET_DEFAULT.result.inconclusive.main,
    );
  });
});

describe("getDeliveryStatusColor", () => {
  it("maps success to the safe color", () => {
    expect(getDeliveryStatusColor("success", PRESET_DEFAULT.result)).toBe(
      PRESET_DEFAULT.result.safe.main,
    );
  });

  it("maps failed to the dangerous color", () => {
    expect(getDeliveryStatusColor("failed", PRESET_DEFAULT.result)).toBe(
      PRESET_DEFAULT.result.dangerous.main,
    );
  });

  it("maps skipped to the inconclusive color", () => {
    expect(getDeliveryStatusColor("skipped", PRESET_DEFAULT.result)).toBe(
      PRESET_DEFAULT.result.inconclusive.main,
    );
  });
});
