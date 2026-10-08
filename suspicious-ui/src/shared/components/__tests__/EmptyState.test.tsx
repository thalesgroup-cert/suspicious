import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { EmptyState } from "@/shared/components/EmptyState";

describe("EmptyState", () => {
  it("shows title, hint and action", () => {
    render(<EmptyState title="No submissions yet" hint="Submit an item to see its verdict here." action={<button>Submit</button>} />);
    expect(screen.getByText("No submissions yet")).toBeInTheDocument();
    expect(screen.getByText(/verdict here/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Submit" })).toBeInTheDocument();
  });
});
