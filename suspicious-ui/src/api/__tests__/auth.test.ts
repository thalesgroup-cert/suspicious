import { describe, it, expect, vi, beforeEach } from "vitest";

const { apiGet, apiPost, hydrateFromProfile, hydrateThemeFromServer } = vi.hoisted(() => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
  hydrateFromProfile: vi.fn(),
  hydrateThemeFromServer: vi.fn(),
}));

vi.mock("@/api/client", () => ({ api: { get: apiGet, post: apiPost } }));
vi.mock("@/styles/colorStore", () => ({
  useColorStore: { getState: () => ({ hydrateFromProfile }) },
}));
vi.mock("@/styles/ThemeStore", () => ({ hydrateThemeFromServer }));

import { getMe, hydrateColorsAfterSso, login, logout } from "@/api/auth";
import { endpoints } from "@/api/endpoints";

const baseMe = {
  id: 1,
  username: "alice",
  email: "alice@example.com",
  groups: ["CERT"],
};

const colors = {
  result: { SAFE: "#0f0" },
  status: { DONE: "#00f" },
};

describe("login / logout", () => {
  beforeEach(() => vi.clearAllMocks());

  it("posts credentials to the login endpoint and returns the body", async () => {
    apiPost.mockResolvedValue({ data: { expiry: null, user: baseMe } });

    const res = await login("alice", "secret");

    expect(apiPost).toHaveBeenCalledWith(endpoints.login, {
      username: "alice",
      password: "secret",
    });
    expect(res.user.username).toBe("alice");
  });

  it("posts to the logout endpoint", async () => {
    apiPost.mockResolvedValue({ data: {} });
    await logout();
    expect(apiPost).toHaveBeenCalledWith(endpoints.logout);
  });

  it("propagates a logout request failure to the caller (try/finally, no catch)", async () => {
    apiPost.mockRejectedValue(new Error("network"));
    await expect(logout()).rejects.toThrow("network");
  });
});

describe("getMe appearance hydration", () => {
  beforeEach(() => vi.clearAllMocks());

  it("returns the user and hydrates colors when semantic_colors are present", async () => {
    apiGet.mockResolvedValue({ data: { ...baseMe, semantic_colors: colors } });

    const me = await getMe();

    expect(apiGet).toHaveBeenCalledWith(endpoints.me);
    expect(me.username).toBe("alice");
    expect(hydrateFromProfile).toHaveBeenCalledWith(colors);
  });

  it("hydrates the theme when theme / auto_seasonal are present", async () => {
    apiGet.mockResolvedValue({ data: { ...baseMe, theme: "metal", auto_seasonal: true } });

    await getMe();

    expect(hydrateThemeFromServer).toHaveBeenCalledWith("metal", true);
  });

  it("skips color hydration when semantic_colors are absent", async () => {
    apiGet.mockResolvedValue({ data: baseMe });

    await getMe();

    expect(hydrateFromProfile).not.toHaveBeenCalled();
  });

  it("never lets a hydration error escape the auth flow", async () => {
    hydrateFromProfile.mockImplementation(() => { throw new Error("store boom"); });
    apiGet.mockResolvedValue({ data: { ...baseMe, semantic_colors: colors } });

    await expect(getMe()).resolves.toMatchObject({ username: "alice" });
  });
});

describe("hydrateColorsAfterSso", () => {
  beforeEach(() => vi.clearAllMocks());

  it("calls getMe and swallows failures", async () => {
    apiGet.mockRejectedValue(new Error("401"));
    await expect(hydrateColorsAfterSso()).resolves.toBeUndefined();
    expect(apiGet).toHaveBeenCalledWith(endpoints.me);
  });
});
