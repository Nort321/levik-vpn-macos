import { afterEach, describe, expect, it, vi } from "vitest";
import type { NetworkInterfaceInfoIPv4 } from "node:os";
import { buildGuestConfig, guestInterface, parseGuestInvitation, type GuestInvitation } from "../src/main/vpn/guestSession";
import { GuestConnection, type GuestConnectionDependencies } from "../src/main/vpn/guestConnection";

const now = 1_800_000_000_000;
const invitation: GuestInvitation = { v: 1, host: "192.168.43.1", port: 43123, method: "aes-256-gcm", password: Buffer.alloc(32, 7).toString("base64url"), name: "Телефон", expiresAt: now + 60_000 };
const encode = (value: unknown) => `levik-share://v1/${Buffer.from(JSON.stringify(value)).toString("base64url")}`;
const adapter = (address: string, netmask = "255.255.255.0"): NetworkInterfaceInfoIPv4 => ({ address, netmask, family: "IPv4", mac: "00:00:00:00:00:00", internal: false, cidr: null });
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

describe("phone guest invitation boundary", () => {
  it("accepts the shared Android format without an account profile", () => {
    expect(parseGuestInvitation(encode(invitation), now)).toEqual(invitation);
  });
  it("rejects public, special and malformed hosts and secret/config injection", () => {
    for (const host of ["8.8.8.8", "127.0.0.1", "169.254.1.1", "100.64.1.1", "172.32.1.1", "::1", "192.168.43.1/path", "192.168.043.1"]) {
      expect(() => parseGuestInvitation(encode({ ...invitation, host }), now)).toThrow();
    }
    for (const patch of [{ port: 0 }, { port: 65536 }, { port: 1.2 }, { name: "phone\nunsafe" }, { method: "none" }, { password: "bad" }, { outbounds: [] }]) {
      expect(() => parseGuestInvitation(encode({ ...invitation, ...patch }), now)).toThrow();
    }
    expect(() => parseGuestInvitation(encode({ ...invitation, expiresAt: now }), now)).toThrow(/истёк/);
    expect(() => parseGuestInvitation(encode({ ...invitation, expiresAt: now + 63 * 60_000 }), now)).toThrow();
    expect(() => parseGuestInvitation(encode(invitation) + "=", now)).toThrow();
  });
  it("selects the phone subnet instead of an unrelated default interface", () => {
    expect(guestInterface(invitation.host, { en0: [adapter("192.168.43.2")], en1: [adapter("192.168.1.2")] })).toBe("en0");
    expect(() => guestInterface(invitation.host, { en0: [adapter("192.168.1.2")] })).toThrow();
    expect(() => guestInterface(invitation.host, { en0: [adapter("192.168.43.2")], en1: [adapter("192.168.43.3")] })).toThrow();
    expect(() => guestInterface(invitation.host, { utun30: [adapter("192.168.43.2")] })).toThrow();
  });
  it("has no direct outbound and routes DNS through the encrypted guest hop", () => {
    const config = buildGuestConfig(invitation);
    const outbounds = config.outbounds as Array<{ protocol: string; tag: string }>;
    expect(outbounds.some((item) => item.protocol === "freedom")).toBe(false);
    expect(outbounds[0]).toMatchObject({ protocol: "shadowsocks", tag: "levik-sharing-guest" });
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    expect(routing.rules).toContainEqual(expect.objectContaining({ inboundTag: ["levik-tun-in"], port: "53", outboundTag: "levik-dns-out" }));
    expect(routing.rules).toContainEqual(expect.objectContaining({ ip: expect.arrayContaining(["::/0", "127.0.0.0/8"]), outboundTag: "levik-block" }));
    expect(JSON.stringify(config)).not.toContain("bypassRu");
  });
});

function harness() {
  let protection = false;
  const deps: GuestConnectionDependencies = {
    interfaceFor: () => "en0",
    enableProtection: vi.fn(async () => { protection = true; }), protectionActive: () => protection,
    start: vi.fn(async () => {}), allowTunnel: vi.fn(async () => {}), healthy: vi.fn(async () => true),
    stop: vi.fn(async () => {}), releaseProtection: vi.fn(async () => { protection = false; }), changed: vi.fn(),
  };
  return { deps, connection: new GuestConnection(deps) };
}

describe("isolated guest lifecycle", () => {
  it("expires with protection retained until explicit exit and exposes no access key", async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    const { deps, connection } = harness();
    await connection.connect(invitation);
    expect(connection.snapshot?.phase).toBe("connected");
    expect(JSON.stringify(connection.snapshot)).not.toContain(invitation.password);
    await vi.advanceTimersByTimeAsync(60_001);
    expect(connection.snapshot?.phase).toBe("expired");
    expect(deps.stop).toHaveBeenCalled();
    expect(deps.releaseProtection).not.toHaveBeenCalled();
    await connection.disconnect();
    expect(connection.active).toBe(false);
    expect(deps.releaseProtection).toHaveBeenCalledOnce();
  });
  it("does not select an account server after three failed guest probes", async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    const { deps, connection } = harness();
    await connection.connect(invitation);
    vi.mocked(deps.healthy).mockResolvedValue(false);
    await connection.probe(); await connection.probe(); await connection.probe();
    expect(connection.snapshot?.phase).toBe("blocked");
    expect(deps.start).toHaveBeenCalledOnce();
    expect(deps.releaseProtection).not.toHaveBeenCalled();
    await connection.disconnect();
  });
  it("does not claim protection when the operating system refused it", async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    const { deps, connection } = harness();
    vi.mocked(deps.enableProtection).mockRejectedValue(new Error("permission"));
    await connection.connect(invitation);
    expect(connection.snapshot?.phase).toBe("blocked");
    expect(deps.start).not.toHaveBeenCalled();
    expect(vi.mocked(deps.changed).mock.calls.at(-1)?.[1]).toContain("может оставаться доступным");
    await connection.disconnect();
  });
  it("cancels an in-flight start without publishing a late connected state", async () => {
    vi.useFakeTimers(); vi.setSystemTime(now);
    const { deps, connection } = harness();
    let finish: (() => void) | undefined;
    vi.mocked(deps.start).mockImplementation(() => new Promise<void>((resolve) => { finish = resolve; }));
    const pending = connection.connect(invitation);
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
    const ending = connection.disconnect();
    finish?.();
    await pending; await ending;
    expect(connection.snapshot).toBeNull();
    expect(vi.mocked(deps.changed).mock.calls.some(([state]) => state?.phase === "connected")).toBe(false);
  });
});
