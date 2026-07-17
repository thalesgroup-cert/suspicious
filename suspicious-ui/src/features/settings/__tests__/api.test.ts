import { describe, it, expect, vi, beforeEach } from "vitest";


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
  listAnalyzers,
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

  it("listItems(section) pages a paginated /settings/list/<section>/", async () => {
    mockGet.mockResolvedValueOnce({
      data: { count: 1, next: null, previous: null, results: [{ id: "1", value: "evil.example" }] },
    });

    const items = await listItems("domains_deny");

    expect(mockGet).toHaveBeenCalledWith("/settings/list/domains_deny/?page=1&page_size=1000");
    expect(items).toEqual([{ id: "1", value: "evil.example" }]);
  });

  it("listItems(section) walks every page and flattens the results", async () => {
    mockGet
      .mockResolvedValueOnce({
        data: { count: 2, next: "next-url", previous: null, results: [{ id: "1", value: "a" }] },
      })
      .mockResolvedValueOnce({
        data: { count: 2, next: null, previous: "prev-url", results: [{ id: "2", value: "b" }] },
      });

    const items = await listItems("domains_deny");

    expect(items).toEqual([{ id: "1", value: "a" }, { id: "2", value: "b" }]);
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(mockGet).toHaveBeenNthCalledWith(2, "/settings/list/domains_deny/?page=2&page_size=1000");
  });

  it("listItems(section) tolerates a non-paginated bare array", async () => {
    mockGet.mockResolvedValueOnce({ data: [{ id: "1", value: "evil.example" }] });

    const items = await listItems("domains_deny");

    expect(items).toEqual([{ id: "1", value: "evil.example" }]);
  });

  it("listAnalyzers() pages the paginated /settings/analyzers/", async () => {
    mockGet.mockResolvedValueOnce({
      data: { count: 1, next: null, previous: null, results: [{ id: 1, name: "Yara", weight: 0.2 }] },
    });

    const analyzers = await listAnalyzers();

    expect(mockGet).toHaveBeenCalledWith("/settings/analyzers/?page=1&page_size=1000");
    expect(analyzers).toEqual([{ id: 1, name: "Yara", weight: 0.2 }]);
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
