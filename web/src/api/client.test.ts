import { afterEach, describe, expect, it, vi } from "vitest";
import { call } from "./client";

describe("generated user API client", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("dispatches a user operation through the user OpenAPI base path", async () => {
    const fetch = vi.fn(async (request: Request) => {
      expect(request.url).toBe(`${location.origin}/api/v1/workspaces/ws-1/members`);
      expect(request.method).toBe("GET");
      return new Response(JSON.stringify([]), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetch);
    await expect(call("listMyWorkspaceMembers", { surface: "user", path: { workspaceId: "ws-1" } })).resolves.toEqual([]);
    expect(fetch).toHaveBeenCalledOnce();
  });
});
