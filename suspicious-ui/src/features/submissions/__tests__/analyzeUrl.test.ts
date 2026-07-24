import { describe, it, expect, vi } from "vitest";
import { api } from "@/api/client";
import { analyzeUrl } from "@/features/submissions/api";

vi.mock("@/api/client", () => ({
  api: { post: vi.fn().mockResolvedValue({ data: { status: "queued", url_id: 7 } }) },
}));

describe("analyzeUrl", () => {
  it("POSTs to the on-demand endpoint and returns data", async () => {
    const res = await analyzeUrl(3, 7);
    expect(api.post).toHaveBeenCalledWith("/submissions/3/urls/7/analyze/");
    expect(res).toEqual({ status: "queued", url_id: 7 });
  });
});
