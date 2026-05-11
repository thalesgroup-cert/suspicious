import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the axios wrapper so we never touch the network. Tests assert
// that each settings helper hits the right URL with the right body —
// the layer guarded by the audit's M1 "Settings: toggle change persists,
// blacklist add/remove" requirement.

vi.mock("@/api/client", () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  },
}));

import { api } from "@/api/client";
import {
  addItems,
  listItems,
  removeItem,
  setFeederStatus,
  getFeederStatus,
} from "@/features/settings/api";

const mockGet = vi.mocked(api.get);
const mockPost = vi.mocked(api.post);
const mockPatch = vi.mocked(api.patch);
const mockDelete = vi.mocked(api.delete);

describe("settings api helpers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("listItems(section) GETs /settings/list/<section>/", async () => {
    mockGet.mockResolvedValueOnce({
      data: [{ id: "1", value: "evil.example" }],
    });

    const items = await listItems("domains_deny");

    expect(mockGet).toHaveBeenCalledWith("/settings/list/domains_deny/");
    expect(items).toEqual([{ id: "1", value: "evil.example" }]);
  });

  it("addItems(section, values) POSTs the values array", async () => {
    mockPost.mockResolvedValueOnce({
      data: { created: [42], duplicates: [], watcher_conflicts: [] },
    });

    const result = await addItems("domains_deny", ["bad.example"]);

    expect(mockPost).toHaveBeenCalledWith(
      "/settings/list/domains_deny/",
      { values: ["bad.example"] }
    );
    expect(result.created).toEqual([42]);
  });

  it("removeItem(section, id) DELETEs the item by id", async () => {
    mockDelete.mockResolvedValueOnce({ data: { deleted: true } });

    await removeItem("domains_deny", "42");

    expect(mockDelete).toHaveBeenCalledWith("/settings/list/domains_deny/42/");
  });

  it("setFeederStatus(true) PATCHes the email-feeder toggle", async () => {
    mockPatch.mockResolvedValueOnce({ data: { enabled: true } });

    const res = await setFeederStatus(true);

    expect(mockPatch).toHaveBeenCalledWith(
      "/settings/email-feeder/",
      { enabled: true }
    );
    expect(res.enabled).toBe(true);
  });

  it("getFeederStatus() GETs the feeder enable state", async () => {
    mockGet.mockResolvedValueOnce({ data: { enabled: false } });

    const res = await getFeederStatus();

    expect(mockGet).toHaveBeenCalledWith("/settings/email-feeder/");
    expect(res.enabled).toBe(false);
  });
});
