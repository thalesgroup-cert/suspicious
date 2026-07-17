import { describe, it, expect } from "vitest";
import type { SubmitSuccessResponse } from "@/features/submit/types";
import {
  classifyArtifact,
  extractApiErrorMessage,
  formatBytes,
  normaliseUrl,
  resolveId,
} from "@/features/submit/utils";

describe("classifyArtifact", () => {
  it("routes full URLs and bare domains to 'url'", () => {
    expect(classifyArtifact("https://evil.com")).toBe("url");
    expect(classifyArtifact("http://x.io/a?b=1")).toBe("url");
    expect(classifyArtifact("evil.com")).toBe("url");
    expect(classifyArtifact("sub.evil.co.uk/path?q=1")).toBe("url");
  });

  it("routes IPs, hashes and free text to 'ioc'", () => {
    expect(classifyArtifact("192.168.1.1")).toBe("ioc");
    expect(classifyArtifact("abc123deadbeef")).toBe("ioc");
    expect(classifyArtifact("malware")).toBe("ioc");
  });

  it("trims before classifying", () => {
    expect(classifyArtifact("  evil.com  ")).toBe("url");
  });
});

describe("normaliseUrl", () => {
  it("leaves schemed URLs untouched", () => {
    expect(normaliseUrl("https://x.com")).toBe("https://x.com");
  });

  it("prepends http:// to bare domains (Django URLField needs a scheme)", () => {
    expect(normaliseUrl("evil.com")).toBe("http://evil.com");
    expect(normaliseUrl("  evil.com  ")).toBe("http://evil.com");
  });
});

describe("formatBytes", () => {
  it("scales through B/KB/MB with one decimal beyond bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(1048576)).toBe("1.0 MB");
  });
});

describe("resolveId", () => {
  it("prefers case_id, then id, then null", () => {
    expect(resolveId({ case_id: 5 } as SubmitSuccessResponse)).toBe(5);
    expect(resolveId({ case_id: null, id: 7 } as SubmitSuccessResponse)).toBe(7);
    expect(resolveId({ case_id: null, id: null } as SubmitSuccessResponse)).toBeNull();
  });
});

describe("extractApiErrorMessage", () => {
  const axiosErr = (over: Record<string, unknown>) =>
    ({ isAxiosError: true, message: "boom", ...over });

  it("returns a generic message for non-axios errors", () => {
    expect(extractApiErrorMessage(new Error("x"))).toBe("Request failed.");
    expect(extractApiErrorMessage("nope")).toBe("Request failed.");
  });

  it("prefers a string detail field", () => {
    expect(
      extractApiErrorMessage(axiosErr({ response: { data: { detail: "Bad input" } } }))
    ).toBe("Bad input");
  });

  it("flattens field errors when there is no detail", () => {
    const msg = extractApiErrorMessage(
      axiosErr({ response: { data: { value: ["required", "too long"], context: "bad" } } })
    );
    expect(msg).toContain("value: required");
    expect(msg).toContain("value: too long");
    expect(msg).toContain("context: bad");
  });

  it("falls back to the error message when there is no response data", () => {
    expect(extractApiErrorMessage(axiosErr({ message: "timeout" }))).toBe("timeout");
  });
});
