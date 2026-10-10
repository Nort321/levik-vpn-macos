import { EventEmitter } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TunnelServer } from "../src/shared/contracts";

vi.mock("electron", () => ({
  app: {
    getPath: () => "/tmp/levik-vpn-macos-test",
    getVersion: () => "1.1.0",
    isPackaged: true,
    setLoginItemSettings: () => undefined,
  },
}));
vi.mock("../src/main/update/appUpdater", () => ({
  AppUpdater: class AppUpdater { on(): this { return this; } },
}));
vi.mock("../src/main/security/secureStore", () => ({
  SecureStore: class SecureStore {
    async put(): Promise<void> {}
    async get(): Promise<null> { return null; }
    async remove(): Promise<void> {}
  },
}));
vi.mock("../src/main/macos/helperClient", () => ({ macHelper: { shutdown: vi.fn(async () => undefined) } }));
vi.mock("../src/main/macos/protection", () => ({
  MacKillSwitch: class MacKillSwitch {
    prepareForTunnelStart(): void {}
    async enable(): Promise<void> {}
    async allowTunnel(): Promise<void> {}
    async disable(): Promise<void> {}
    isActive(): boolean { return false; }
  },
  DnsLeakProtection: class DnsLeakProtection {
    async enable(): Promise<void> {}
    async disable(): Promise<void> {}
  },
}));
vi.mock("../src/main/macos/networkType", () => ({ defaultRouteNetworkType: vi.fn(async () => "wifi") }));
vi.mock("../src/main/vpn/serverPinger", () => ({ measureServerLatencies: vi.fn(async () => ({})) }));
vi.mock("../src/main/vpn/xrayConfig", () => ({ buildXrayConfig: () => ({}) }));
vi.mock("../src/main/vpn/xrayManager", () => ({
  XrayManager: class XrayManager extends EventEmitter {
    running = false;
    start = vi.fn(async () => { this.running = true; });
    stop = vi.fn(async () => { this.running = false; });
    isRunning = () => this.running;
    isHealthy = vi.fn(async () => true);
  },
}));

import { AppController } from "../src/main/appController";
import { ConnectionTelemetry } from "../src/main/telemetry/connectionTelemetry";
import type { SessionRecorder, TelemetrySessionBody } from "../src/main/telemetry/sessionRecorder";
import type { TelemetryClient } from "../src/main/telemetry/telemetryClient";

interface FakeXray extends EventEmitter {
  running: boolean;
  start: ReturnType<typeof vi.fn>;
  stop: ReturnType<typeof vi.fn>;
}

function server(id: string, name: string): TunnelServer {
  return {
    id: id.repeat(64).slice(0, 64), tag: id, name, countryCode: "NL",
    outbound: { protocol: "vless", streamSettings: { network: "tcp", security: "reality" } },
  };
}

describe("macOS connection telemetry", () => {
  let directory: string;
  let telemetry: ConnectionTelemetry;
  const first = server("a", "Amsterdam");
  const second = server("b", "Frankfurt");

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "levik-mac-telemetry-"));
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  });
  afterEach(async () => {
    vi.clearAllTimers();
    vi.useRealTimers();
    // Switching off waits for queued writes and removes the queue.
    await telemetry.setEnabled(false);
    await rm(directory, { recursive: true, force: true });
  });

  async function setup(settings: { autoReconnect?: boolean } = {}) {
    const controller = new AppController();
    const xray = Reflect.get(controller, "xray") as FakeXray;
    const http = {
      send: vi.fn(async () => "sent" as const),
      networkToken: vi.fn(async () => ({ token: "net.token", expiresAt: Date.now() + 60_000 })),
    };
    telemetry = new ConnectionTelemetry(directory, { platform: "macos", app: "1.1.0", os: "15" }, http as unknown as TelemetryClient);
    await telemetry.setEnabled(true);
    Reflect.set(controller, "telemetry", telemetry);
    Reflect.apply(Reflect.get(controller, "bindCoreEvents") as () => void, controller, []);
    Reflect.set(controller, "profile", { subscriptionId: "sub", servers: [first, second] });
    const state = Reflect.get(controller, "state") as { servers: TunnelServer[]; selectedServerId: string | null; serverLatencies: Record<string, number>; settings: Record<string, unknown> };
    state.servers = [first, second];
    state.selectedServerId = first.id;
    state.serverLatencies = { [first.id]: 10, [second.id]: 20 };
    state.settings = { ...state.settings, automaticServer: false, connectionTelemetry: true, telemetryNoticeShown: true, ...settings };
    const current = () => Reflect.get(telemetry, "session") as SessionRecorder | null;
    return { controller, xray, http, current };
  }

  function sentSession(http: { send: ReturnType<typeof vi.fn> }): TelemetrySessionBody {
    const [request] = http.send.mock.calls.at(-1) as [string];
    return (JSON.parse(request) as { sessions: TelemetrySessionBody[] }).sessions[0]!;
  }

  it("records probe failures, the restart and a user disconnect in one session", async () => {
    const { controller, xray, current } = await setup();
    await controller.connect();
    const session = current()!;
    xray.emit("health", ["timeout", "tls"]);
    xray.emit("health", ["timeout"]);
    xray.emit("unhealthy");
    xray.running = false;
    xray.emit("exit", null, false);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(controller.snapshot().status).toBe("connected");
    await controller.disconnect();

    const body = session.snapshot();
    expect(body).toMatchObject({ final: true, trigger: "user", net: { type: "wifi", token: "net.token" }, end: { by: "user", code: "user" } });
    expect(body.timeline.map((event) => event.e)).toEqual([
      "attempt", "connected", "probe_fail", "probe_fail", "recovery", "attempt", "connected",
    ]);
    expect(body.timeline[0]).toMatchObject({ node: "Amsterdam", proto: "vless-reality", cause: "initial" });
    expect(body.timeline[4]).toMatchObject({ action: "reconnect_same" });
    expect(body.timeline[5]).toMatchObject({ cause: "reconnect" });
  });

  it("ends a failed first attempt with the step the helper reported", async () => {
    const { controller, xray, http } = await setup();
    xray.start.mockRejectedValueOnce(new Error("VPN-сервер не передаёт данные: Ошибка согласования REALITY."));
    await expect(controller.connect()).rejects.toThrow("REALITY");
    await vi.waitFor(() => expect(http.send).toHaveBeenCalled());
    const body = sentSession(http);
    expect(body).toMatchObject({ final: true, end: { by: "error", code: "reality_auth" } });
    expect(body.timeline.at(-1)).toMatchObject({ e: "attempt_failed", stage: "handshake", code: "reality_auth" });
  });

  it("reports a core crash without automatic recovery as the session end", async () => {
    const { controller, xray, http } = await setup({ autoReconnect: false });
    await controller.connect();
    xray.running = false;
    xray.emit("exit", 2, false);
    await vi.waitFor(() => expect(http.send).toHaveBeenCalled());
    const body = sentSession(http);
    expect(body).toMatchObject({ final: true, end: { by: "error", code: "core_exited" } });
    expect(body.timeline.slice(-2)).toMatchObject([{ e: "core_exit", code: 2, expected: false }, { e: "recovery" }]);
  });

  it("keeps a server change within the same session", async () => {
    const { controller, current } = await setup();
    await controller.connect();
    const session = current();
    await controller.selectServer(second.id);
    expect(current()).toBe(session);
    const attempts = session!.snapshot().timeline.filter((event) => event.e === "attempt");
    expect(attempts.map((event) => event.cause)).toEqual(["initial", "server_switch"]);
  });
});
