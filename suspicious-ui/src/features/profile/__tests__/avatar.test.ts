import { describe, it, expect } from "vitest";
import {
  AVATAR_STYLES,
  renderAvatarDataUri,
  randomSeed,
} from "@/features/profile/avatar";

describe("avatar helper", () => {
  it("exposes the agreed style allowlist", () => {
    const keys = AVATAR_STYLES.map((s) => s.key).sort();
    expect(keys).toEqual(
      ["avataaars", "bottts", "funEmoji", "identicon", "initials", "notionists", "shapes", "thumbs"],
    );
  });

  it("renders a deterministic svg data uri", () => {
    const a = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    const b = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    expect(a).toBe(b);
    expect(a.startsWith("data:image/svg+xml")).toBe(true);
  });

  it("produces different output for different seeds", () => {
    const a = renderAvatarDataUri({ style: "bottts", seed: "abc123" });
    const b = renderAvatarDataUri({ style: "bottts", seed: "zzz999" });
    expect(a).not.toBe(b);
  });

  it("falls back safely on unknown style", () => {
    const uri = renderAvatarDataUri({ style: "nope", seed: "x" });
    expect(uri).toBe("");
  });

  it("randomSeed returns a non-empty short string", () => {
    const s = randomSeed();
    expect(typeof s).toBe("string");
    expect(s.length).toBeGreaterThan(0);
    expect(s.length).toBeLessThanOrEqual(64);
  });
});
