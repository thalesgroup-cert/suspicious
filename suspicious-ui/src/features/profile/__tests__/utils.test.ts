import { describe, it, expect, beforeEach } from "vitest";
import {
  apiErrorText,
  initials,
  LOCAL_PROFILE_KEY,
  readLocalProfile,
  writeLocalProfile,
} from "@/features/profile/utils";

describe("initials", () => {
  it("builds upper-cased initials from first/last", () => {
    expect(initials("Alice", "Smith")).toBe("AS");
    expect(initials("bob", "")).toBe("B");
  });

  it("falls back to 'U' when nothing usable is given", () => {
    expect(initials()).toBe("U");
    expect(initials("  ", "  ")).toBe("U");
  });
});

describe("apiErrorText", () => {
  it("prefixes the HTTP status when present", () => {
    expect(apiErrorText({ message: "boom", response: { status: 500 } })).toBe("500: boom");
  });

  it("reads detail / error / string body fields", () => {
    expect(apiErrorText({ response: { data: { detail: "nope" } } })).toBe("nope");
    expect(apiErrorText({ response: { data: "raw text" } })).toBe("raw text");
  });

  it("defaults to a generic message", () => {
    expect(apiErrorText({})).toBe("Request failed");
  });
});

describe("local profile persistence", () => {
  beforeEach(() => localStorage.removeItem(LOCAL_PROFILE_KEY));

  it("returns null when nothing is stored", () => {
    expect(readLocalProfile()).toBeNull();
  });

  it("merges successive patches", () => {
    writeLocalProfile({ theme: "metal" } as never);
    writeLocalProfile({ auto_seasonal: true } as never);
    expect(readLocalProfile()).toEqual({ theme: "metal", auto_seasonal: true });
  });

  it("returns null on a corrupt payload", () => {
    localStorage.setItem(LOCAL_PROFILE_KEY, "{not json");
    expect(readLocalProfile()).toBeNull();
  });
});
