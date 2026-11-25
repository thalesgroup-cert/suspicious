import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/api/client";
import { setConnectorEnabled } from "../connectors";

describe("setConnectorEnabled", () => {
  const patch = vi.spyOn(api, "patch");
  beforeEach(() => patch.mockReset().mockResolvedValue({ data: {} }));

  it("sends no force key by default", async () => {
    await setConnectorEnabled("cortex", false);
    expect(patch.mock.calls[0][1]).toEqual({ enabled: false });
  });

  it("sends force: true when asked", async () => {
    await setConnectorEnabled("cortex", false, true);
    expect(patch.mock.calls[0][1]).toEqual({ enabled: false, force: true });
  });
});
