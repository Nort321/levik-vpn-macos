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
      config: { maintenance: [{ nodeId: nodeIdForHost("de1.example.net"), startsAt: now + 60_000, endsAt: now + 3_600_000 }], nodeLoad: {} },
      fetchedAt: now,
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

  it("moves to the same country before maintenance, abroad when it has no other server", async () => {
    const server = (id: string, address: string, countryCode: string) => ({
      id, tag: id, name: id.toUpperCase(), countryCode, outbound: { protocol: "vless", settings: { vnext: [{ address }] } },
    });
    const controller = new AppController();
    controller.cancelLogin();
    const now = Date.now();
    const windows = ["de1.example.net", "de2.example.net"].map((host) => ({ nodeId: nodeIdForHost(host), startsAt: now + 60_000, endsAt: now + 3_600_000 }));
    Reflect.set(controller, "remoteStored", { config: { maintenance: windows, nodeLoad: {} }, fetchedAt: now });
    Reflect.set(controller, "xray", { isRunning: () => true });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, {
      status: "connected",
      busy: false,
      servers: [server("de1", "de1.example.net", "DE"), server("de2", "de2.example.net", "DE"), server("nl1", "nl1.example.net", "NL")],
      selectedServerId: "de1",
      serverLatencies: { de1: 20, de2: 60, nl1: 40 },
    });
    const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();
    const check = Reflect.get(controller, "checkMaintenance") as () => Promise<void>;

    await check.call(controller);
    expect(selectServer).toHaveBeenCalledWith("nl1");

    // Only de1 is under maintenance now: slower de2 wins over faster nl1 abroad.
    Reflect.set(controller, "remoteStored", { config: { maintenance: windows.slice(0, 1), nodeLoad: {} }, fetchedAt: now });
    selectServer.mockClear();
    await check.call(controller);
    expect(selectServer).toHaveBeenCalledWith("de2");
  });

  it("chooses the best server of a country and keeps one already selected", async () => {
    const server = (id: string, address: string, countryCode: string) => ({
      id, tag: id, name: id.toUpperCase(), countryCode, outbound: { protocol: "vless", settings: { vnext: [{ address }] } },
    });
    const controller = new AppController();
    controller.cancelLogin();
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, {
      servers: [server("nl1", "nl1.example.net", "NL"), server("de1", "de1.example.net", "DE"), server("de2", "de2.example.net", "DE")],
      selectedServerId: "nl1",
      serverLatencies: { nl1: 10, de1: 90, de2: 30 },
    });
    const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();

    await controller.selectCountry("de");
    expect(selectServer).toHaveBeenCalledWith("de2");

    state.selectedServerId = "de1";
    selectServer.mockClear();
    await controller.selectCountry("DE");
    expect(selectServer).not.toHaveBeenCalled();
    await expect(controller.selectCountry("FI")).rejects.toThrow("Страна не найдена");
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

describe("AppController while the Mac sleeps", () => {
  const server = (id: string, address: string, protocol = "vless") => ({
    id, tag: id, name: id.toUpperCase(), countryCode: "DE", outbound: { protocol, settings: { vnext: [{ address }] } },
  });

  it("does not move off a server before maintenance while asleep", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    const now = Date.now();
    Reflect.set(controller, "remoteStored", {
      config: { maintenance: [{ nodeId: nodeIdForHost("de1.example.net"), startsAt: now + 60_000, endsAt: now + 3_600_000 }], nodeLoad: {} },
      fetchedAt: now,
    });
    Reflect.set(controller, "xray", { isRunning: () => true, setSuspended: vi.fn() });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, {
      status: "connected",
      busy: false,
      servers: [server("de1", "de1.example.net"), server("de2", "de2.example.net")],
      selectedServerId: "de1",
      serverLatencies: { de1: 20, de2: 60 },
    });
    const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();
    const check = Reflect.get(controller, "checkMaintenance") as () => Promise<void>;

    controller.recordPowerEvent("suspend");
    await check.call(controller);
    expect(selectServer).not.toHaveBeenCalled();

    controller.recordPowerEvent("resume");
    await check.call(controller);
    expect(selectServer).toHaveBeenCalledWith("de2");
  });

  it("reconnects on wake a connection that failed on its own, through the server that last worked", async () => {
    vi.useFakeTimers();
    try {
      const controller = new AppController();
      controller.cancelLogin();
      Reflect.set(controller, "xray", { isRunning: () => false, setSuspended: vi.fn() });
      Reflect.set(controller, "accessToken", "token");
      Reflect.set(controller, "lastWorkingServerId", "de1");
      const state = Reflect.get(controller, "state") as Record<string, unknown>;
      Object.assign(state, {
        status: "error",
        busy: false,
        servers: [server("de1", "de1.example.net"), server("pl1", "pl1.example.net", "hysteria2")],
        selectedServerId: "pl1",
      });
      const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();
      const connect = vi.spyOn(controller, "connect").mockResolvedValue();

      const restore = controller.restoreAfterSystemResume();
      await vi.advanceTimersByTimeAsync(1_500);
      await restore;

      expect(selectServer).toHaveBeenCalledWith("de1");
      expect(connect).toHaveBeenCalledWith("resume");
    } finally {
      vi.useRealTimers();
    }
  });

  it("leaves an error alone when the user turned the VPN off or never got it working", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    Reflect.set(controller, "xray", { isRunning: () => false, setSuspended: vi.fn() });
    Reflect.set(controller, "accessToken", "token");
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, { status: "error", busy: false, servers: [server("de1", "de1.example.net")], selectedServerId: "de1" });
    const connect = vi.spyOn(controller, "connect").mockResolvedValue();

    await controller.restoreAfterSystemResume();

    expect(connect).not.toHaveBeenCalled();
  });

  it("does not check traffic or climb to another protocol while asleep", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    Reflect.set(controller, "xray", { isRunning: () => true, setSuspended: vi.fn(), serviceRoutes: { active: false } });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, {
      status: "connected",
      servers: [server("de1", "de1.example.net"), server("se1", "se1.example.net", "hysteria2")],
      selectedServerId: "de1",
      serverLatencies: { de1: 20, se1: 60 },
    });
    const selectServer = vi.spyOn(controller, "selectServer").mockResolvedValue();
    controller.recordPowerEvent("suspend");

    (Reflect.get(controller, "launchTrafficCheck") as (delayMs: number, alarm?: boolean) => void).call(controller, 0, true);
    expect(Reflect.get(controller, "trafficCheck")).toBeNull();
    const climb = Reflect.get(controller, "climbProtocolLadder") as (failed: unknown, protocol: string) => Promise<void>;
    await climb.call(controller, (state.servers as unknown[])[0], "vless-tcp");
    expect(selectServer).not.toHaveBeenCalled();
  });
});

describe("AppController Smart Auto ladder", () => {
  it("connects again when the next protocol does not connect, instead of staying off", async () => {
    const server = (id: string, address: string, protocol: string) => ({
      id, tag: id, name: id.toUpperCase(), countryCode: "DE", outbound: { protocol, settings: { vnext: [{ address }] } },
    });
    const controller = new AppController();
    controller.cancelLogin();
    Reflect.set(controller, "xray", { isRunning: () => false, setSuspended: vi.fn(), serviceRoutes: { active: false } });
    Reflect.set(controller, "protocolHistory", {
      networkKey: () => null, current: () => ({ networks: [], winners: {} }), localSalt: () => "salt", update: vi.fn(),
    });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    const servers = [server("de1", "de1.example.net", "vless"), server("pl1", "pl1.example.net", "hysteria2")];
    Object.assign(state, { status: "connected", servers, selectedServerId: "de1", serverLatencies: { de1: 20, pl1: 60 } });
    const selectServer = vi.spyOn(controller, "selectServer").mockImplementation(async (id: string) => {
      state.selectedServerId = id;
      if (id === "pl1") {
        state.status = "error";
        throw new Error("Не найден исходящий сетевой интерфейс");
      }
    });
    const connect = vi.spyOn(controller, "connect").mockResolvedValue();

    const climb = Reflect.get(controller, "climbProtocolLadder") as (failed: unknown, protocol: string) => Promise<void>;
    await climb.call(controller, servers[0], "vless-tcp");

    expect(selectServer.mock.calls.map(([id]) => id)).toEqual(["pl1", "de1"]);
    expect(connect).toHaveBeenCalledOnce();
  });
});

describe("AppController account rules", () => {
  it("checks rule changes one at a time", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    const order: string[] = [];
    let release: (() => void) | undefined;
    const now = vi.spyOn(controller as unknown as { applyAccountRulesNow: () => Promise<void> }, "applyAccountRulesNow")
      .mockImplementationOnce(() => new Promise<void>((resolve) => {
        order.push("first start");
        release = () => { order.push("first end"); resolve(); };
      }))
      .mockImplementationOnce(async () => { order.push("second"); });
    const apply = Reflect.get(controller, "applyAccountRules") as () => Promise<void>;

    const first = apply.call(controller);
    const second = apply.call(controller);
    await vi.waitFor(() => expect(release).toBeDefined());
    expect(order).toEqual(["first start"]);
    release?.();
    await Promise.all([first, second]);

    expect(order).toEqual(["first start", "first end", "second"]);
    expect(now).toHaveBeenCalledTimes(2);
  });
});

describe("AppController server pings", () => {
  it("keeps the last direct pings while the tunnel would answer them itself", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    const running = { value: true };
    Reflect.set(controller, "xray", { isRunning: () => running.value, setSuspended: vi.fn() });
    const refreshLiveLoad = vi.spyOn(controller as unknown as { refreshLiveLoad: () => Promise<void> }, "refreshLiveLoad").mockResolvedValue();
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, {
      servers: [{ id: "de1", tag: "de1", name: "DE1", countryCode: "DE", outbound: { protocol: "vless", settings: { vnext: [{ address: "192.0.2.1", port: 9 }] } } }],
      serverLatencies: { de1: 48 },
    });

    await controller.pingServers();

    expect(refreshLiveLoad).toHaveBeenCalled();
    expect(controller.snapshot().serverLatencies).toEqual({ de1: 48 });
  });
});


describe("Smart Auto full-route controller integration", () => {
  it("ranks and displays actual cascade latency, keeps endpoint refresh from overriding it and invalidates on a new network", () => {
    const controller = new AppController();
    controller.cancelLogin();
    const server = (id: string, address: string) => ({ id, tag: id, name: id, countryCode: "DE", outbound: { protocol: "vless", settings: { vnext: [{ address, port: 443 }] } } });
    const cascade = server("cascade", "moscow.example"), direct = server("direct", "de.example");
    let network = "network-one";
    Reflect.set(controller, "protocolHistory", { current: () => ({ networks: [], winners: {} }), networkKey: () => network, localSalt: () => "local-salt" });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, { servers: [cascade, direct], serverLatencies: { cascade: 5, direct: 60 } });
    Reflect.set(controller, "endpointLatencies", { cascade: 5, direct: 60 });
    const now = Date.now();
    const observation = (medianMs: number) => ({ measuredAt: now, confidence: "measured", medianMs, jitterMs: 2, failureRate: 0, targets: 2, samples: 6, setupMs: 100, downMbps: 100, upMbps: 30 });
    Reflect.set(controller, "routeMeasurements", { cascade: observation(190), direct: observation(55) });
    Reflect.set(controller, "routeMeasurementNetwork", network);
    const key = Reflect.get(controller, "routeMeasurementKey") as (server: typeof cascade) => string;
    Reflect.set(controller, "routeMeasurementKeys", { cascade: key.call(controller, cascade), direct: key.call(controller, direct) });
    const rank = Reflect.get(controller, "rankServers") as (servers: Array<typeof cascade>) => Array<{ id: string }>;
    const display = Reflect.get(controller, "displayedRouteLatencies") as (raw: Record<string, number | null>) => Record<string, number | null>;
    expect(rank.call(controller, [cascade, direct])[0]?.id).toBe("direct");
    expect(display.call(controller, { cascade: 1, direct: 2 })).toEqual({ cascade: 190, direct: 55 });
    network = "network-two";
    expect(display.call(controller, { cascade: 1, direct: 2 })).toEqual({ cascade: 1, direct: 2 });
  });

  it("does not begin a stale session when OFF happens during the post-probe selection write", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    const server = { id: "a", tag: "a", name: "a", countryCode: "DE", outbound: { protocol: "vless", settings: { vnext: [{ address: "de.example", port: 443 }] } } };
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    const settings = state.settings as Record<string, unknown>;
    Object.assign(settings, { automaticServer: true, gameEnabled: false });
    Object.assign(state, { status: "disconnected", servers: [server], serverLatencies: { a: 30 }, selectedServerId: "a", elevated: true });
    Reflect.set(controller, "profile", { profileId: "test", subscriptionId: "test", subscriptionExpiresAt: null, servers: [server], directDomains: [], proxyDomains: [], directCidrs: [] });
    Reflect.set(controller, "xray", { isRunning: () => false });
    Reflect.set(controller, "latenciesMeasuredAt", Date.now());
    Reflect.set(controller, "refreshLiveLoad", vi.fn(async () => {}));
    Reflect.set(controller, "refreshRouteMeasurements", vi.fn(async () => true));
    Reflect.set(controller, "stopConnection", vi.fn(async () => {}));
    const begin = vi.fn();
    Reflect.set(controller, "telemetry", { active: false, begin });
    let release: (() => void) | undefined;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    const follow = vi.fn(async () => await pending);
    Reflect.set(controller, "followBestServer", follow);
    const operation = controller.connect();
    await vi.waitFor(() => expect(follow).toHaveBeenCalledOnce());
    await controller.disconnect();
    release?.();
    await operation;
    expect(begin).not.toHaveBeenCalled();
  });
});


describe("Smart Auto probe cancellation boundaries", () => {
  it("aborts preflight immediately when a manual server is selected", async () => {
    const controller = new AppController();
    controller.cancelLogin();
    const abort = new AbortController();
    Reflect.set(controller, "routeProbeAbort", abort);
    Reflect.set(controller, "xray", { isRunning: () => false });
    Reflect.set(controller, "secureStore", { put: vi.fn(async () => {}) });
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    Object.assign(state, { servers: [{ id: "manual", tag: "manual", name: "manual", countryCode: "DE", outbound: {} }] });
    const intent = Reflect.get(controller, "connectionIntent");
    await controller.selectServer("manual");
    expect(abort.signal.aborted).toBe(true);
    expect(Reflect.get(controller, "connectionIntent")).toBeGreaterThan(intent);
    expect(controller.snapshot().selectedServerId).toBe("manual");
  });

  it("invalidates effective transport measurements when settings or profile scope changes", () => {
    const controller = new AppController();
    controller.cancelLogin();
    const server = { id: "a", tag: "a", name: "a", countryCode: "DE", outbound: { protocol: "vless" } };
    const key = Reflect.get(controller, "routeMeasurementKey") as (input: typeof server) => string;
    const first = key.call(controller, server);
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    const settings = state.settings as Record<string, unknown>;
    settings.antiDpiEnabled = !settings.antiDpiEnabled;
    expect(key.call(controller, server)).not.toBe(first);
    const abort = new AbortController();
    Reflect.set(controller, "routeProbeAbort", abort);
    Reflect.set(controller, "routeMeasurements", { a: { medianMs: 50 } });
    const invalidate = Reflect.get(controller, "invalidateRouteMeasurements") as () => void;
    invalidate.call(controller);
    expect(abort.signal.aborted).toBe(true);
    expect(Reflect.get(controller, "routeMeasurements")).toEqual({});
  });
});


describe("Smart Auto hot mode controller", () => {
  it("enables the existing ordinary owner without selecting/restarting the connected server", async () => {
    const controller = new AppController(); controller.cancelLogin();
    const state = Reflect.get(controller, "state") as Record<string, unknown>;
    const settings = state.settings as Record<string, unknown>; settings.automaticServer = false;
    Object.assign(state, { status: "connected", selectedServerId: "manual" });
    const enabled = vi.fn(async () => true), refresh = vi.fn(async () => {}), start = vi.fn(), stop = vi.fn();
    Reflect.set(controller, "xray", { isRunning: () => true, start, stop,
      serviceRoutes: { automaticAvailable: true, smartAutoActive: true, setAutomaticEnabled: enabled, refreshAutomatic: refresh, mainServerId: "manual" } });
    Reflect.set(controller, "secureStore", { put: vi.fn(async () => {}) });
    Reflect.set(controller, "applyLoginItemSettings", vi.fn());
    Reflect.set(controller, "refreshLiveLoad", vi.fn(async () => {}));
    Reflect.set(controller, "recordSyncedChanges", vi.fn(async () => {}));
    Reflect.set(controller, "emitChanged", vi.fn());
    Reflect.set(controller, "telemetry", { record: vi.fn() });
    const select = vi.spyOn(controller, "selectServer").mockResolvedValue();
    await controller.selectAutomatic();
    expect(enabled).toHaveBeenCalledWith(true); expect(refresh).toHaveBeenCalledOnce();
    expect(select).not.toHaveBeenCalled(); expect(start).not.toHaveBeenCalled(); expect(stop).not.toHaveBeenCalled();
    expect(controller.snapshot().selectedServerId).toBe("manual");
  });
});

describe("Smart Auto resume control isolation", () => {
  it("preserves a live core on resume when its control API cannot answer", async () => {
    vi.useFakeTimers();
    try {
      const controller = new AppController(); controller.cancelLogin();
      const state = Reflect.get(controller, "state") as Record<string, unknown>;
      Object.assign(state, { status: "connected" });
      Reflect.set(controller, "lastConfig", {});
      const recheck = vi.fn(async () => {}), restart = vi.fn(async () => {});
      Reflect.set(controller, "xray", { isRunning: () => true, isHealthy: async () => false,
        serviceRoutes: { smartAutoActive: true, refreshAutomatic: recheck } });
      Reflect.set(controller, "telemetry", { record: vi.fn() });
      Reflect.set(controller, "startXray", restart);
      const resuming = controller.restoreAfterSystemResume();
      await vi.advanceTimersByTimeAsync(1500); await resuming;
      expect(restart).not.toHaveBeenCalled(); expect(recheck).toHaveBeenCalledOnce();
      expect(controller.snapshot().status).toBe("connected");
    } finally { vi.useRealTimers(); }
  });
});
