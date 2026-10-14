import { describe, it, expect } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { RecentSubmissionsList } from "@/features/home/components/RecentSubmissionsList";
import type { SubmissionRow } from "@/features/home/api";

const HASH = "a".repeat(64);
const rows: SubmissionRow[] = [
  { id: 101, status: "DONE", artifact: HASH, created_at: "2026-06-22T10:00:00Z", type: "hash", result: "DANGEROUS" },
  { id: 102, status: "DONE", artifact: "invoice.eml", created_at: "2026-06-21T10:00:00Z", type: "mail", result: "SAFE" },
];

describe("RecentSubmissionsList", () => {
  it("shows ids and verdicts for every row", () => {
    renderWithProviders(<RecentSubmissionsList rows={rows} hrefFor={(r) => `/submissions?open=${r.id}`} />);
    expect(screen.getByText("101")).toBeInTheDocument();
    expect(screen.getByText("102")).toBeInTheDocument();
    expect(screen.getByText("DANGEROUS")).toBeInTheDocument();
    expect(screen.getByText("SAFE")).toBeInTheDocument();
  });

  it("keeps a 64-char hash on one line with an ellipsis", () => {
    renderWithProviders(<RecentSubmissionsList rows={rows} hrefFor={(r) => `/submissions?open=${r.id}`} />);
    const style = getComputedStyle(screen.getByText(HASH));
    expect(style.textOverflow).toBe("ellipsis");
    expect(style.whiteSpace).toBe("nowrap");
  });

  it("renders list items with the id as a real link", () => {
    renderWithProviders(<RecentSubmissionsList rows={rows} hrefFor={(r) => `/submissions?open=${r.id}`} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByRole("link", { name: /101/ })).toHaveAttribute("href", "/submissions?open=101");
  });
});
