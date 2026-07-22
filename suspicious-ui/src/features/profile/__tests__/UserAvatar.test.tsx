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

  it("renders real initials for the initials style even if a stale random seed is stored", () => {
    render(<UserAvatar avatar={{ style: "initials", seed: "zz9k2x" }} initials="JD" />);
    const img = screen.getByRole("img");
    const src = img.getAttribute("src")!;
    const svg = decodeURIComponent(src.replace("data:image/svg+xml;utf8,", ""));
    expect(svg).toContain(">JD<");
    expect(svg).not.toContain("zz9k2x");
  });

  it("renders the uploaded photo when style is upload and a url is present", () => {
    render(
      <UserAvatar
        avatar={{ style: "upload", seed: "avatars/1/x.jpg", url: "https://rustfs/signed" }}
        initials="EF"
      />
    );
    const img = screen.getByRole("img");
    expect(img.getAttribute("src")).toBe("https://rustfs/signed");
  });

  it("falls back to initials when style is upload but url is missing", () => {
    render(
      <UserAvatar avatar={{ style: "upload", seed: "avatars/1/x.jpg" }} initials="GH" />
    );
    expect(screen.getByText("GH")).toBeInTheDocument();
  });
});
