import { describe, expect, it, vi } from "vitest";
import type { AuthChallengeResponse } from "../src/main/api/models";

vi.mock("electron", () => ({
  app: {
    getPath: () => "/tmp/levik-vpn-macos-test",
    getVersion: () => "1.0.0",
    isPackaged: true,
  },
}));

vi.mock("../src/main/update/appUpdater", () => ({
  AppUpdater: class AppUpdater {
    on(): this {
      return this;
    }
  },
}));

import { AppController } from "../src/main/appController";
import { nodeIdForHost } from "../src/main/platform/favoriteNodes";

describe("AppController login lifecycle", () => {
  it("does not resume login after cancellation while the challenge is pending", async () => {
    let resolveChallenge: ((challenge: AuthChallengeResponse) => void) | undefined;
    const createChallenge = vi.fn(
      () => new Promise<AuthChallengeResponse>((resolve) => {
        resolveChallenge = resolve;
      }),
    );
    const pollStatus = vi.fn();
    const controller = new AppController();
    Reflect.set(controller, "api", { createChallenge, pollStatus });
    Reflect.set(controller, "identity", {
      publicKeySpkiBase64Url: () => "public-key",
    });
    Reflect.set(controller, "secureStore", { get: vi.fn(() => Promise.resolve(null)), put: vi.fn() });
    controller.cancelLogin();

    const changed = vi.fn();
    controller.on("changed", changed);
    const login = controller.beginLogin();
    await vi.waitFor(() => expect(createChallenge).toHaveBeenCalledOnce());
    controller.cancelLogin();
    const snapshotAfterCancellation = controller.snapshot();
    const changesAfterCancellation = changed.mock.calls.length;

    resolveChallenge?.({
      ok: true,
      loginToken: "login-token",
      activationUriComplete: "https://leviknet.com/activate?code=ABCD-EFGH",
      activationCode: "ABCD-EFGH",
      pollIntervalSeconds: 2,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });

    await expect(login).rejects.toThrow("Вход отменён");
    expect(createChallenge).toHaveBeenCalledWith(expect.objectContaining({ numberMatchSupported: true }));
    expect(createChallenge).not.toHaveBeenCalledWith(expect.objectContaining({ accountHint: expect.anything() }));
    expect(pollStatus).not.toHaveBeenCalled();
    expect(controller.snapshot()).toEqual(snapshotAfterCancellation);
    expect(changed).toHaveBeenCalledTimes(changesAfterCancellation);
  });

  it("moves off a server before its maintenance and says so", async () => {
    const server = (id: string, address: string) => ({
      id, tag: id, name: id.toUpperCase(), countryCode: "DE", outbound: { protocol: "vless", settings: { vnext: [{ address }] } },
    });
    const controller = new AppController();
    controller.cancelLogin();
    const now = Date.now();
    Reflect.set(controller, "remoteStored", {
      config: { maintenance: [{ nodeId: nodeIdForHost("de1.example.net"), startsAt: now + 60_000, endsAt: now + 3_600_000 }] },
    });
    Reflect.set(controller, "xray", { isRunning: () => true });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, {
      status: "connected",
      busy: false,
      servers: [server("de1", "de1.example.net"), server("de2", "de2.example.net"), server("nl1", "nl1.example.net")],
      selectedServerId: "de1",
      serverLatencies: { de1: 20, de2: 60, nl1: 40 },
    });
    const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();
    const notify = vi.fn();
    controller.on("notify", notify);

    await (Reflect.get(controller, "checkMaintenance") as () => Promise<void>).call(controller);

    expect(selectServer).toHaveBeenCalledWith("nl1");
    expect(notify).toHaveBeenCalledWith(expect.objectContaining({ title: "Сервер «DE1» уходит на обслуживание" }));
    expect(controller.snapshot().serverMaintenance).toEqual({ de1: now + 3_600_000 });
  });

  it("ends a declined sign-in so it can start again", async () => {
    vi.useFakeTimers();
    try {
      const controller = new AppController();
      const put = vi.fn();
      Reflect.set(controller, "secureStore", { get: vi.fn(() => Promise.resolve(null)), put });
      Reflect.set(controller, "identity", { publicKeySpkiBase64Url: () => "public-key" });
      Reflect.set(controller, "api", {
        createChallenge: vi.fn(() => Promise.resolve({
          ok: true,
          loginToken: "login-token",
          activationUriComplete: "https://leviknet.org/activate?code=ABCD-EFGH",
          activationCode: "ABCD-EFGH",
          pollIntervalSeconds: 2,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          matchNumber: 37,
          approvalRequested: true,
          telegramUriComplete: "https://t.me.example.net/levikvpnbot?start=web_" + "x".repeat(43),
        })),
        pollStatus: vi.fn(() => Promise.resolve({ ok: true, state: "declined" })),
      });
      controller.cancelLogin();

      const challenge = await controller.beginLogin();
      expect(challenge).toMatchObject({ matchNumber: 37, approvalRequested: true, telegramUri: null });
      expect(controller.snapshot().loginPending).toBe(true);

      await vi.advanceTimersByTimeAsync(2_000);
      expect(controller.snapshot()).toMatchObject({ loginPending: false, sessionAvailable: false });
      expect(controller.snapshot().statusDetail).toContain("Вход отменён");
      expect(put).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
