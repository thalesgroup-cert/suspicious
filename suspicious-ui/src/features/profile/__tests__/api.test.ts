import { describe, it, expect, vi } from "vitest";
import { api } from "@/api/client";
import { uploadAvatar } from "@/features/profile/api";

vi.mock("@/api/client", () => ({
  api: { post: vi.fn() },
}));

describe("uploadAvatar", () => {
  it("POSTs the file as multipart form data to the upload endpoint", async () => {
    const fakeProfile = { id: 1, avatar: { style: "upload", seed: "avatars/1/x.jpg", url: "https://x" } };
    vi.mocked(api.post).mockResolvedValue({ data: fakeProfile });

    const file = new File(["bytes"], "photo.jpg", { type: "image/jpeg" });
    const result = await uploadAvatar(file);

    expect(result).toEqual(fakeProfile);
    expect(api.post).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(api.post).mock.calls[0];
    expect(url).toBe("/profile/avatar/upload/");
    expect(body).toBeInstanceOf(FormData);
    expect((body as FormData).get("avatar")).toBe(file);
  });
});
