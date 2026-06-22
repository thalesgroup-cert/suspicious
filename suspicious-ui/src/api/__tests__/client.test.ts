import { describe, it, expect } from "vitest";
import { api } from "@/api/client";

describe("api client", () => {
  it("sends credentials so the httpOnly knox_token cookie is included", () => {
    expect(api.defaults.withCredentials).toBe(true);
  });

  it("defaults the base URL to /api", () => {
    expect(api.defaults.baseURL).toBe("/api");
  });
});
