import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/api/client";
import { getCampaignSummary, getMailVolume, getNeighbours, getPca } from "../api";

vi.mock("@/api/client", () => ({ api: { get: vi.fn() } }));

describe("campaigns api", () => {
  beforeEach(() => vi.mocked(api.get).mockReset());

  it("requests the period on summary and volume", async () => {
    vi.mocked(api.get).mockResolvedValue({ data: {} });
    await getCampaignSummary(30);
    expect(api.get).toHaveBeenCalledWith("/campaigns/summary/", { params: { days: 30 } });
    await getMailVolume(7);
    expect(api.get).toHaveBeenCalledWith("/campaigns/mail-volume/", { params: { days: 7 } });
  });

  it("normalises a sparse summary: numbers default to 0, nullable fields stay null", async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: {
        days: 15,
        messages: 3,
        dangerous_share: null,
        mix: { SAFE: 2 },
        campaigns: [{ name: "a.example", first_seen: "2026-10-01T00:00:00Z", last_seen: "2026-10-02T00:00:00Z", case_ids: ["1", 2] }],
      },
    });
    const s = await getCampaignSummary(15);
    expect(s.messages).toBe(3);
    expect(s.previous_messages).toBe(0);
    expect(s.dangerous_share).toBeNull();
    expect(s.previous_dangerous_share).toBeNull();
    expect(s.peak_day).toBeNull();
    expect(s.largest_campaign).toBeNull();
    expect(s.mix).toEqual({ SAFE: 2, UNWANTED: 0, SUSPICIOUS: 0, DANGEROUS: 0 });
    expect(s.active_window_hours).toBe(0);
    // not sent: what the list holds is all that is known, and no case-id limit is claimed
    expect(s.campaigns_total).toBe(1);
    expect(s.max_case_ids).toBe(0);
    expect(s.campaigns[0]).toMatchObject({ name: "a.example", messages: 0, active: false, sample_subject: null, case_ids: ["1"] });
  });

  it("keeps the campaign count before the backend's cut and the case-id limit", async () => {
    vi.mocked(api.get).mockResolvedValue({ data: { campaigns: [{ name: "a" }], campaigns_total: 412, max_case_ids: 20 } });
    const s = await getCampaignSummary(15);
    expect(s.campaigns_total).toBe(412);
    expect(s.max_case_ids).toBe(20);
  });

  it("keeps z, date and three variance ratios on PCA", async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: { explained_variance: [0.3, 0.2, 0.1], points: [{ x: 1, y: 2, z: 3, label: "SAFE", date: "2026-10-01" }, { x: 1, y: 1, label: "SAFE" }] },
    });
    const p = await getPca(100);
    expect(api.get).toHaveBeenCalledWith("/campaigns/pca/", { params: { limit: 100 } });
    expect(p.explained_variance).toEqual([0.3, 0.2, 0.1]);
    expect(p.points[0]).toMatchObject({ z: 3, date: "2026-10-01" });
    expect(p.points[1]).toMatchObject({ z: 0, date: null });
  });

  it("normalises neighbours with nullable case ids and similarity", async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: { k: 10, near_known_bad: [{ label: "SAFE", score: 0.7, suspicious_case_id: "3" }] },
    });
    const n = await getNeighbours(500);
    expect(api.get).toHaveBeenCalledWith("/campaigns/neighbours/", { params: { limit: 500 } });
    expect(n.k).toBe(10);
    expect(n.bad_share_threshold).toBe(0);
    expect(n.novel).toEqual([]);
    expect(n.near_known_bad[0]).toEqual({
      suspicious_case_id: "3", mail_subject: null, label: "SAFE", date: null, score: 0.7,
      nearest_dangerous_case_id: null, nearest_dangerous_similarity: null,
    });
  });
});
