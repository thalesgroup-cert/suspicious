import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/api/client";
import { analyzeUrl } from "@/features/submissions/api";

vi.mock("@/api/client", () => ({ api: { post: vi.fn() } }));

describe("analyzeUrl", () => {
  beforeEach(() => vi.clearAllMocks());

  it("POSTs to the on-demand endpoint and returns data", async () => {
    (api.post as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { status: "queued", url_id: 7 },
    });
    const res = await analyzeUrl(3, 7);
    expect(api.post).toHaveBeenCalledWith("/submissions/3/urls/7/analyze/");
    expect(res).toEqual({ status: "queued", url_id: 7 });
  });
});
