import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { UserAvatar } from "@/features/profile/components/UserAvatar";

describe("UserAvatar", () => {
  it("renders an img when avatar config is set", () => {
    render(<UserAvatar avatar={{ style: "bottts", seed: "abc123" }} initials="AB" />);
    const img = screen.getByRole("img");
    expect(img.getAttribute("src")).toMatch(/^data:image\/svg\+xml/);
  });

  it("renders initials when no avatar", () => {
    render(<UserAvatar avatar={null} initials="AB" />);
    expect(screen.getByText("AB")).toBeInTheDocument();
  });

  it("renders initials when avatar has empty style", () => {
    render(<UserAvatar avatar={{ style: "", seed: "" }} initials="CD" />);
    expect(screen.getByText("CD")).toBeInTheDocument();
  });
});
