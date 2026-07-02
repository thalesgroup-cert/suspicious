import { describe, it, expect, afterEach } from "vitest";
import { env } from "@/lib/runtimeEnv";

afterEach(() => {
  delete window.__ENV__;
});

describe("env", () => {
  it("prefers a non-empty runtime value from window.__ENV__", () => {
    window.__ENV__ = { VITE_API_BASE: "https://runtime.example/api" };
    expect(env("VITE_API_BASE")).toBe("https://runtime.example/api");
  });

  it("ignores an empty runtime value and falls through to build-time", () => {
    // VITE_API_BASE has a build-time value ("/api") in this env; an empty
    // runtime override must be skipped so the build value wins.
    window.__ENV__ = { VITE_API_BASE: "" };
    expect(env("VITE_API_BASE")).toBe("/api");
  });

  it("skips an empty runtime value for a key with no build-time value", () => {
    window.__ENV__ = { VITE_UNSET_KEY: "" };
    expect(env("VITE_UNSET_KEY")).toBeUndefined();
  });

  it("returns undefined for an unknown key", () => {
    expect(env("VITE_DEFINITELY_NOT_SET")).toBeUndefined();
  });

  it("does not throw when window.__ENV__ is absent", () => {
    expect(() => env("VITE_API_BASE")).not.toThrow();
  });
});
