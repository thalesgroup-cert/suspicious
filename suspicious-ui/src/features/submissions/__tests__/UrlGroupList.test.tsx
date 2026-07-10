import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/api/client", () => ({
  api: { post: vi.fn().mockResolvedValue({ data: { status: "queued", url_id: 2 } }) },
}));

import { UrlGroupList } from "@/features/submissions/components/UrlGroupList";
import { api } from "@/api/client";
import type { UrlArtifact } from "@/features/submissions/api";

const urls: UrlArtifact[] = [
  {
    id: 1,
    address: "https://shop.example.com/product/a",
    analysis_status: "analyzed",
    interestingness: 10,
    canonical_key: "shop.example.com/product/a",
    analyzed_url_id: 42,
  },
  {
    id: 2,
    address: "https://shop.example.com/cart?id=1",
    analysis_status: "skipped",
    interestingness: 2,
    canonical_key: "shop.example.com/cart",
    analyzed_url_id: null,
  },
];

describe("UrlGroupList", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders the registered domain as a group header", () => {
    render(<UrlGroupList submissionId={5} urls={urls} />);
    const headings = screen.getAllByText(/example\.com/);
    expect(headings.some((el) => el.textContent === "example.com")).toBe(true);
  });

  it("shows an Analyze button only on the skipped row", () => {
    render(<UrlGroupList submissionId={5} urls={urls} />);
    const buttons = screen.getAllByRole("button", { name: /^analyze$/i });
    expect(buttons).toHaveLength(1);
  });

  it("calls analyzeUrl(submissionId, urlId) when Analyze is clicked", async () => {
    vi.mocked(api.post).mockResolvedValue({ data: { status: "queued", url_id: 2 } });
    const user = userEvent.setup();

    render(<UrlGroupList submissionId={5} urls={urls} />);
    await user.click(screen.getByRole("button", { name: /^analyze$/i }));

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith("/submissions/5/urls/2/analyze/");
    });
  });
});
