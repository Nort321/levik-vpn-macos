import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  probe: vi.fn<() => Promise<boolean>>(),
  query: vi.fn(), close: vi.fn(),
  helper: { connected: true, request: vi.fn(), status: vi.fn(), killSwitch: true, dnsProtection: true },
}));
vi.mock("../src/main/vpn/tunnelHealth", () => ({ isTunnelHealthy: mocks.probe }));
vi.mock("../src/main/vpn/xrayStats", () => ({ XrayStatsClient: class { query = mocks.query; close = mocks.close; } }));
vi.mock("../src/main/macos/helperClient", () => ({ macHelper: mocks.helper }));
import { XrayManager } from "../src/main/vpn/xrayManager";

describe("macOS traffic recovery", () => {
  let manager: XrayManager;
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    mocks.helper.request.mockResolvedValue({});
    mocks.query.mockResolvedValue({ uplink: 0, downlink: 0 });
    mocks.probe.mockResolvedValue(false);
    manager = new XrayManager();
  });
  afterEach(async () => { await manager.stop(); vi.useRealTimers(); });

  it("does not confuse a working stats API with internet access after sleep", async () => {
    await manager.start({});
    await expect(manager.isHealthy()).resolves.toBe(false);
    mocks.probe.mockResolvedValue(true);
    await expect(manager.isHealthy()).resolves.toBe(true);
  });

  it("requires three failures and resets the count on successful traffic", async () => {
    const exit = vi.fn();
    manager.on("exit", exit);
    await manager.start({});
    await vi.advanceTimersByTimeAsync(60_000);
    expect(exit).not.toHaveBeenCalled();
    mocks.probe.mockResolvedValueOnce(true);
    await vi.advanceTimersByTimeAsync(30_000);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(exit).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(exit).toHaveBeenCalledExactlyOnceWith(null, false);
    expect(manager.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("discards a pending failure when the tunnel is replaced", async () => {
    const exit = vi.fn();
    manager.on("exit", exit);
    await manager.start({});
    await vi.advanceTimersByTimeAsync(60_000);
    let complete: ((healthy: boolean) => void) | undefined;
    mocks.probe.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
    await vi.advanceTimersByTimeAsync(30_000);
    await manager.stop();
    await manager.start({});
    complete?.(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(exit).not.toHaveBeenCalled();
    expect(manager.isRunning()).toBe(true);
  });

  it("does not restart a tunnel after disconnect during a pending check", async () => {
    const exit = vi.fn();
    manager.on("exit", exit);
    await manager.start({});
    let complete: ((healthy: boolean) => void) | undefined;
    mocks.probe.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
    await vi.advanceTimersByTimeAsync(30_000);
    await manager.stop();
    complete?.(false);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(exit).not.toHaveBeenCalled();
    expect(manager.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });
});
