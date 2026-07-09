import { describe, expect, it, vi } from "vitest";
import { screen, fireEvent } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { CommentThread } from "../CommentThread";
import type { CaseComment } from "../api";

const fixtureComments: CaseComment[] = [
  { id: 1, author_email: "a@example.com", body: "first comment", is_internal: false, created_at: "2026-07-09T10:00:00Z" },
];

describe("CommentThread", () => {
  it("renders existing comments", () => {
    renderWithProviders(
      <CommentThread title="Your comments" comments={fixtureComments} isLoading={false} onAdd={vi.fn()} isAdding={false} />
    );
    expect(screen.getByText("first comment")).toBeInTheDocument();
    expect(screen.getByText("a@example.com")).toBeInTheDocument();
  });

  it("shows empty state when there are no comments", () => {
    renderWithProviders(
      <CommentThread title="Your comments" comments={[]} isLoading={false} onAdd={vi.fn()} isAdding={false} />
    );
    expect(screen.getByText("No comments yet.")).toBeInTheDocument();
  });

  it("calls onAdd with trimmed body and clears the draft", () => {
    const onAdd = vi.fn();
    renderWithProviders(
      <CommentThread title="Your comments" comments={[]} isLoading={false} onAdd={onAdd} isAdding={false} />
    );
    const textarea = screen.getByPlaceholderText("Add a comment…");
    fireEvent.change(textarea, { target: { value: "  new comment  " } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(onAdd).toHaveBeenCalledWith("new comment");
    expect((textarea as HTMLTextAreaElement).value).toBe("");
  });

  it("disables Add when the draft is blank", () => {
    renderWithProviders(
      <CommentThread title="Your comments" comments={[]} isLoading={false} onAdd={vi.fn()} isAdding={false} />
    );
    expect(screen.getByRole("button", { name: "Add" })).toBeDisabled();
  });
});
