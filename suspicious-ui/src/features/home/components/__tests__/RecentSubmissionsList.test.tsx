import { describe, it, expect, vi } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
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
    renderWithProviders(<RecentSubmissionsList rows={rows} onOpen={() => {}} />);
    expect(screen.getByText("101")).toBeInTheDocument();
    expect(screen.getByText("102")).toBeInTheDocument();
    expect(screen.getByText("DANGEROUS")).toBeInTheDocument();
    expect(screen.getByText("SAFE")).toBeInTheDocument();
  });

  it("keeps a 64-char hash on one line with an ellipsis", () => {
    renderWithProviders(<RecentSubmissionsList rows={rows} onOpen={() => {}} />);
    const style = getComputedStyle(screen.getByText(HASH));
    expect(style.textOverflow).toBe("ellipsis");
    expect(style.whiteSpace).toBe("nowrap");
  });

  it("opens the row from the id chip", () => {
    const onOpen = vi.fn();
    renderWithProviders(<RecentSubmissionsList rows={rows} onOpen={onOpen} />);
    fireEvent.click(screen.getByText("101"));
    expect(onOpen).toHaveBeenCalledWith(101);
  });
});
