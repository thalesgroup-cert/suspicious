import { describe, it, expect, afterEach } from "vitest";
import { initialSsoError, SSO_ERROR_MESSAGES } from "@/features/login/config";

const setSearch = (s: string) => history.replaceState({}, "", s);

afterEach(() => history.replaceState({}, "", "/"));

describe("initialSsoError", () => {
  it("returns null when there is no sso_error param", () => {
    setSearch("/login");
    expect(initialSsoError()).toBeNull();
  });

  it("maps a known sso_error code to its friendly message", () => {
    setSearch("/login?sso_error=state_mismatch");
    expect(initialSsoError()).toBe(SSO_ERROR_MESSAGES.state_mismatch);
  });

  it("falls back to a generic message for an unknown code", () => {
    setSearch("/login?sso_error=mystery");
    expect(initialSsoError()).toBe("SSO error: mystery");
  });
});
