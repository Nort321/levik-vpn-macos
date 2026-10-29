import { afterEach, describe, expect, it, vi } from "vitest";
vi.mock("electron", () => ({ app: { getPath: () => "/tmp/levik-sharing-controller-test", getVersion: () => "1.0.0", isPackaged: true } }));
vi.mock("../src/main/update/appUpdater", () => ({ AppUpdater: class { on(): this { return this; } } }));
vi.mock("node:os", async (original) => ({ ...(await original<typeof import("node:os")>()), networkInterfaces: () => ({ en0: [{ address: "192.168.43.2", netmask: "255.255.255.0", family: "IPv4", internal: false, mac: "00:00:00:00:00:00", cidr: "192.168.43.2/24" }] }) }));
vi.mock("../src/main/vpn/tunnelHealth", async (original) => ({ ...(await original<typeof import("../src/main/vpn/tunnelHealth")>()), isTunnelHealthy: vi.fn(async () => true) }));
import { AppController } from "../src/main/appController";

function create() {
  const controller = new AppController();
  controller.cancelLogin();
  let protectedTraffic = false;
  const xray = { isRunning: vi.fn(() => false), start: vi.fn(async () => {}), stop: vi.fn(async () => {}), isHealthy: vi.fn(async () => true), serviceRoutes: { stop: vi.fn() } };
  const kill = { enable: vi.fn(async () => { protectedTraffic = true; }), allowTunnel: vi.fn(async () => {}), disable: vi.fn(async () => { protectedTraffic = false; }), isActive: () => protectedTraffic };
  const dns = { enable: vi.fn(async () => {}), disable: vi.fn(async () => {}) };
  Reflect.set(controller, "xray", xray); Reflect.set(controller, "killSwitch", kill); Reflect.set(controller, "dnsLeakProtection", dns);
  Reflect.set(controller, "homeRoad", { stop: vi.fn(async () => {}) });
  const state = Reflect.get(controller, "state") as Record<string, unknown>;
  state.selectedSubscriptionId = "saved-subscription"; state.selectedServerId = "saved-server";
  const profile = { profileId: "saved-profile" };
  Reflect.set(controller, "profile", profile);
  const value = { v: 1, host: "192.168.43.1", port: 43123, method: "aes-256-gcm", password: Buffer.alloc(32, 9).toString("base64url"), name: "Phone", expiresAt: Date.now() + 60_000 };
  const raw = `levik-share://v1/${Buffer.from(JSON.stringify(value)).toString("base64url")}`;
  return { controller, xray, kill, dns, profile, raw };
}
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

describe("guest controller ownership", () => {
  it("connects before login while preserving the saved account profile", async () => {
    vi.useFakeTimers();
    const { controller, xray, profile, raw } = create();
    await controller.connectGuest(raw);
    expect(controller.snapshot().guest?.phase).toBe("connected");
    expect(controller.snapshot().sessionAvailable).toBe(false);
    expect(controller.snapshot().selectedSubscriptionId).toBe("saved-subscription");
    expect(Reflect.get(controller, "profile")).toBe(profile);
    expect(xray.start).toHaveBeenCalledOnce();
    await controller.connect("auto_connect");
    expect(xray.start).toHaveBeenCalledOnce();
    await controller.disconnectGuest(false);
    expect(controller.snapshot().guest).toBeNull();
    expect(Reflect.get(controller, "profile")).toBe(profile);
  });
  it("ignores late account status and protection-setting updates during a guest session", async () => {
    vi.useFakeTimers();
    const { controller, kill, raw } = create();
    await controller.connectGuest(raw);
    const patch = Reflect.get(controller, "patch") as (patch: Record<string, unknown>) => void;
    patch.call(controller, { status: "disconnected", statusDetail: "Account expired", busy: false });
    expect(controller.snapshot().status).toBe("connected");
    expect(controller.snapshot().statusDetail).not.toContain("Account expired");
    await controller.updateSettings({ killSwitch: false }, "sync");
    expect(kill.disable).not.toHaveBeenCalled();
    const stop = Reflect.get(controller, "stopConnection") as (by: string, reason: string) => Promise<void>;
    await stop.call(controller, "error", "auth_deadline");
    expect(kill.disable).not.toHaveBeenCalled();
    await controller.disconnectGuest(false);
  });
  it("waits for an earlier normal disconnect before enabling guest protection", async () => {
    vi.useFakeTimers();
    const { controller, kill, raw } = create();
    let finish: (() => void) | undefined;
    kill.disable.mockImplementationOnce(() => new Promise<void>((resolve) => { finish = resolve; }));
    const stopping = controller.disconnect();
    const connecting = controller.connectGuest(raw);
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
    expect(kill.enable).not.toHaveBeenCalled();
    finish?.();
    await stopping; await connecting;
    expect(controller.snapshot().guest?.phase).toBe("connected");
    expect(kill.enable).toHaveBeenCalledOnce();
    await controller.disconnectGuest(false);
  });
});
