import { describe, expect, it } from "vitest";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { buildLockdownConfig, buildXrayConfig } from "../src/main/vpn/xrayConfig";
import type { AppSettings } from "../src/shared/contracts";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const settings: AppSettings = {
  routingMode: "bypassRu",
  automaticServer: true,
  autoReconnect: true,
  killSwitch: true,
  useDoh: true,
  dnsServer: "1.1.1.1",
  theme: "dark",
  launchAtLogin: false,
  autoConnectOnLaunch: false,
  closeToTray: true,
  showTrayIcon: true,
  preventDnsLeaks: true,
  favoriteServerIds: [],
  antiDpiEnabled: false,
  antiDpiPackets: "tlshello",
  antiDpiLength: "100-200",
  antiDpiInterval: "10-20",
  splitTunnelMode: "off",
  splitTunnelProcesses: [],
};

describe("macOS tunnel profile", () => {
  it("validates all routing modes with the bundled macOS Xray binary", () => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "core-validation", subscriptionId: "subscription-1",
      issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?security=tls&sni=example.com#Validation" },
    })), "subscription-1");
    const assets = resolve("vendor", "xray", `darwin-${process.arch}`);
    for (const routingMode of ["global", "bypassRu", "blockedOnly"] as const) {
      const config = buildXrayConfig(profile, profile.servers[0]!, {
        ...settings, routingMode, antiDpiEnabled: true,
        splitTunnelMode: "bypass", splitTunnelProcesses: ["/Applications/Safari.app/"],
      });
      expect(() => execFileSync(resolve("build", "native", process.arch, "levik-helper"), ["--validate-config"], {
        input: JSON.stringify(config), timeout: 10_000, stdio: ["pipe", "pipe", "pipe"],
      })).not.toThrow();
      // -test parses/configures the core without creating TUN or connecting.
      expect(() => execFileSync(resolve(assets, "xray"), ["run", "-test", "-format", "json", "-config", "stdin:"], {
        input: JSON.stringify(config), timeout: 10_000, stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, XRAY_LOCATION_ASSET: assets },
      })).not.toThrow();
    }
  });

  it.each([true, false])("accepts VLESS, Trojan and Hysteria2 in the native helper with DoH=%s", (useDoh) => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "native-validation", subscriptionId: "subscription-1",
      source: { mediaType: "text/plain", content: [
        "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#VLESS",
        "trojan://test-password@example.com:443#Trojan",
        "hysteria2://test-password@example.com:443#Hysteria2",
        "hysteria2://test-password@example.com:2443?sni=hy2.example.com&obfs=salamander&obfs-password=test-obfs-password#Hysteria2-obfuscated",
      ].join("\n") },
    })), "subscription-1");
    for (const server of profile.servers) {
      const config = buildXrayConfig(profile, server, { ...settings, useDoh });
      expect(() => execFileSync(resolve("build", "native", process.arch, "levik-helper"), ["--validate-config"], {
        input: JSON.stringify(config), timeout: 10_000, stdio: ["pipe", "pipe", "pipe"],
      })).not.toThrow();
      if (server.outbound.protocol === "hysteria") {
        const assets = resolve("vendor", "xray", `darwin-${process.arch}`);
        expect(() => execFileSync(resolve(assets, "xray"), ["run", "-test", "-format", "json", "-config", "stdin:"], {
          input: JSON.stringify(config), timeout: 10_000, stdio: ["pipe", "pipe", "pipe"],
          env: { ...process.env, XRAY_LOCATION_ASSET: assets },
        })).not.toThrow();
      }
    }
  });

  it("keeps file and URL addresses forbidden outside DNS HTTPS settings", () => {
    const helper = resolve("build", "native", process.arch, "levik-helper");
    const base = buildLockdownConfig(settings);
    for (const address of ["/tmp/socket", "file:///etc/passwd", "https://example.com/dns-query"]) {
      const config = { ...base, outbounds: [{ protocol: "trojan", settings: { servers: [{ address, port: 443, password: "test-password" }] } }] };
      expect(() => execFileSync(helper, ["--validate-config"], {
        input: JSON.stringify(config), timeout: 10_000, stdio: ["pipe", "pipe", "pipe"],
      })).toThrow();
    }
    for (const address of ["/tmp/socket", "file:///etc/passwd", "http://example.com/dns-query", "https://user:password@example.com/dns-query"]) {
      expect(() => execFileSync(helper, ["--validate-config"], {
        input: JSON.stringify({ ...base, dns: { servers: [{ address }] } }),
        timeout: 10_000, stdio: ["pipe", "pipe", "pipe"],
      })).toThrow();
    }
  });

  it("converts VLESS Reality share links without exposing Android dependencies", () => {
    const profile = {
      version: 1,
      profileId: "profile-1",
      subscriptionId: "subscription-1",
      issuedAt: new Date().toISOString(),
      source: {
        mediaType: "text/plain",
        content: "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=public-key&sid=0123&type=tcp#DE%20Frankfurt",
      },
      routing: { directCidrs: ["203.0.113.0/24"], directDomains: ["domain:example.ru"], proxyDomains: ["geosite:category-anticensorship"] },
    };
    const prepared = prepareTunnelProfile(Buffer.from(JSON.stringify(profile)), "subscription-1");
    expect(prepared.servers).toHaveLength(1);
    expect(prepared.servers[0]?.name).toBe("DE Frankfurt");
    expect(prepared.servers[0]?.outbound.protocol).toBe("vless");
    const config = buildXrayConfig(prepared, prepared.servers[0]!, settings);
    const inbounds = config.inbounds as Array<Record<string, unknown>>;
    expect(inbounds[0]?.protocol).toBe("tun");
    expect(inbounds[0]?.sniffing).toEqual({ enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true });
    expect(inbounds[0]?.settings).toEqual(expect.objectContaining({
      autoSystemRoutingTable: ["0.0.0.0/0", "::/0"],
      autoOutboundsInterface: "auto",
    }));
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    expect(routing.rules).not.toContainEqual(expect.objectContaining({
      network: "tcp,udp",
      outboundTag: "levik-direct",
    }));
  });

  it("rejects a profile issued for another subscription", () => {
    const profile = { version: 1, profileId: "p", subscriptionId: "one", issuedAt: new Date().toISOString(), source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#Server" } };
    expect(() => prepareTunnelProfile(Buffer.from(JSON.stringify(profile)), "two")).toThrow(/подписке/);
  });

  it.each(["hysteria2", "hy2"])("preserves Salamander from %s subscriptions through Anti-DPI configuration", (scheme) => {
    const source = `${scheme}://secret@example.com:2443?sni=hy2.example.com&obfs=salamander&obfs-password=S%2Band%26%3DSecret#Obfuscated`;
    for (const content of [source, Buffer.from(source).toString("base64")]) {
      const prepared = prepareTunnelProfile(Buffer.from(JSON.stringify({
        version: 1, profileId: "salamander-profile", subscriptionId: "subscription-1",
        source: { mediaType: "text/plain", content },
      })), "subscription-1");
      const config = buildXrayConfig(prepared, prepared.servers[0]!, { ...settings, antiDpiEnabled: true });
      expect(config).toHaveProperty("outbounds.0.streamSettings.finalmask", {
        udp: [{ type: "salamander", settings: { password: "S+and&=Secret" } }],
      });
      expect(config).toHaveProperty("outbounds.0.streamSettings.tlsSettings.serverName", "hy2.example.com");
      expect(config).toHaveProperty("outbounds.0.streamSettings.hysteriaSettings.auth", "secret");
      expect(config).toHaveProperty("outbounds.0.settings.port", 2443);
    }
  });

  it.each([
    "obfs=gecko&obfs-password=valid-password",
    "obfs=salamander",
    "obfs=salamander&obfs-password=abc",
    `obfs=salamander&obfs-password=${"x".repeat(1025)}`,
  ])("rejects unsupported or invalid Hysteria2 obfuscation instead of dropping it", (query) => {
    expect(() => prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1, profileId: "invalid-obfs", subscriptionId: "subscription-1",
      source: { mediaType: "text/plain", content: `hysteria2://secret@example.com:2443?${query}` },
    })), "subscription-1")).toThrow(/обфускации Hysteria2/);
  });

  it("supports Hysteria2 share links", () => {
    const profile = {
      version: 1,
      profileId: "hysteria-profile",
      subscriptionId: "subscription-1",
      issuedAt: new Date().toISOString(),
      source: {
        mediaType: "text/plain",
        content: "hysteria2://secret@example.com:443?sni=cdn.example.com#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam",
      },
    };
    const prepared = prepareTunnelProfile(Buffer.from(JSON.stringify(profile)), "subscription-1");
    expect(prepared.servers[0]?.outbound.protocol).toBe("hysteria");
    expect(prepared.servers[0]?.countryCode).toBe("NL");
  });

  it("adds Anti-DPI fragmentation and process routing", () => {
    const profile = {
      version: 1,
      profileId: "routing-profile",
      subscriptionId: "subscription-1",
      issuedAt: new Date().toISOString(),
      source: {
        mediaType: "text/plain",
        content: "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#DE%20Berlin",
      },
    };
    const prepared = prepareTunnelProfile(Buffer.from(JSON.stringify(profile)), "subscription-1");
    const config = buildXrayConfig(prepared, prepared.servers[0]!, {
      ...settings,
      antiDpiEnabled: true,
      splitTunnelMode: "bypass",
      splitTunnelProcesses: ["/Applications/Google Chrome.app/"],
    });
    const outbounds = config.outbounds as Array<Record<string, unknown>>;
    const inbounds = config.inbounds as Array<Record<string, unknown>>;
    const routing = config.routing as { rules: Array<Record<string, unknown>> };
    expect(config.api).toEqual(expect.objectContaining({ services: ["StatsService"] }));
    expect(outbounds.some((outbound) => outbound.tag === "levik-fragment")).toBe(true);
    expect(routing.rules).toContainEqual(expect.objectContaining({ process: ["/Applications/Google Chrome.app/"], outboundTag: "levik-direct" }));
    expect(routing.rules).toContainEqual(expect.objectContaining({ ip: ["geoip:ru"], outboundTag: "levik-direct" }));
    expect(routing.rules).toContainEqual(expect.objectContaining({ domain: ["geosite:category-ru"], outboundTag: "levik-direct" }));
    expect((inbounds[0]?.sniffing as { destOverride: string[] }).destOverride).not.toContain("fakedns");
  });

  it("builds a fail-closed Kill Switch configuration", () => {
    const config = buildLockdownConfig(settings);
    const routing = config.routing as { rules: Array<{ outboundTag: string }> };
    expect(routing.rules.at(-1)?.outboundTag).toBe("levik-block");
    expect(config).toHaveProperty("inbounds.0.sniffing.routeOnly", true);
  });

  it("uses the expanded blocked-only domain set", () => {
    const profile = prepareTunnelProfile(Buffer.from(JSON.stringify({
      version: 1,
      profileId: "blocked-profile",
      subscriptionId: "subscription-1",
      issuedAt: new Date().toISOString(),
      source: { mediaType: "text/plain", content: "vless://11111111-1111-4111-8111-111111111111@example.com:443#DE%20Berlin" },
    })), "subscription-1");
    const config = buildXrayConfig(profile, profile.servers[0]!, { ...settings, routingMode: "blockedOnly" });
    const routing = config.routing as { rules: Array<{ domain?: string[]; outboundTag: string }> };
    const proxyRule = routing.rules.find((rule) => rule.outboundTag === profile.servers[0]?.tag && rule.domain);
    expect(proxyRule?.domain).toEqual(expect.arrayContaining([
      "domain:discord.com", "domain:discordapp.com", "domain:discord.gg",
      "domain:discord.media", "domain:discordapp.net", "domain:discordcdn.com", "geosite:discord",
    ]));
    expect(routing.rules.indexOf(proxyRule!)).toBeLessThan(routing.rules.length - 1);
    expect(routing.rules.at(-1)).toEqual({ type: "field", network: "tcp,udp", outboundTag: "levik-direct" });
  });
});


describe("alternate XHTTP Mux", () => {
  const alternateHost = "leva.levikfartik.ru";
  const uuid = "11111111-1111-4111-8111-111111111111";
  const link = (host: string, network: string) =>
    `vless://${uuid}@${host}:443?security=tls&type=${network}&path=%2Fapi%2FgetFile%2F&mode=packet-up#Alternate`;
  const prepare = (content: string) => prepareTunnelProfile(Buffer.from(JSON.stringify({
    version: 1, profileId: "alternate-xhttp", subscriptionId: "subscription-1",
    source: { mediaType: "text/plain", content },
  })), "subscription-1");

  it.each(["xhttp", "splithttp"])("enables Mux for an alternate %s share link without mutating the profile", (network) => {
    const profile = prepare(link(alternateHost, network));
    const original = structuredClone(profile);
    const server = profile.servers[0]!;
    for (const antiDpiEnabled of [false, true]) {
      const config = buildXrayConfig(profile, server, { ...settings, antiDpiEnabled });
      expect(config).toHaveProperty("outbounds.0.mux", { enabled: true, concurrency: 1 });
      expect(config).toHaveProperty("outbounds.0.streamSettings.xhttpSettings.path", "/api/getFile/");
      expect(config).toHaveProperty("outbounds.0.streamSettings.tlsSettings.serverName", alternateHost);
      if (antiDpiEnabled) {
        expect(config).toHaveProperty("outbounds.0.streamSettings.sockopt.dialerProxy", "levik-fragment");
        expect(config.outbounds).toContainEqual(expect.objectContaining({ tag: "levik-fragment" }));
      } else {
        expect(config.outbounds).not.toContainEqual(expect.objectContaining({ tag: "levik-fragment" }));
      }
      const assets = resolve("vendor", "xray", `darwin-${process.arch}`);
      expect(() => execFileSync(resolve("build", "native", process.arch, "levik-helper"), ["--validate-config"], {
        input: JSON.stringify(config), timeout: 10_000, stdio: ["pipe", "pipe", "pipe"],
      })).not.toThrow();
      expect(() => execFileSync(resolve(assets, "xray"), ["run", "-test", "-format", "json", "-config", "stdin:"], {
        input: JSON.stringify(config), timeout: 10_000, stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, XRAY_LOCATION_ASSET: assets },
      })).not.toThrow();
    }
    expect(profile).toEqual(original);
  });

  it.each([
    { enabled: false },
    { enabled: true, concurrency: 8, xudpConcurrency: 16, xudpProxyUDP443: "allow" },
    {},
    null,
  ])("preserves explicit JSON profile Mux settings: %j", (mux) => {
    const outbound = prepare(link(alternateHost, "xhttp")).servers[0]!.outbound;
    const profile = prepare(JSON.stringify({ outbounds: [{ ...outbound, mux }] }));
    for (const antiDpiEnabled of [false, true]) {
      const config = buildXrayConfig(profile, profile.servers[0]!, { ...settings, antiDpiEnabled });
      expect(config).toHaveProperty("outbounds.0.mux", mux);
    }
  });

  it("matches JSON endpoint host and transport case insensitively", () => {
    const profile = prepare(JSON.stringify({ outbounds: [{
      protocol: "vless", settings: { vnext: [{ address: "LEVA.LEVIKFARTIK.RU" }] },
      streamSettings: { network: "SplitHTTP" },
    }] }));
    expect(buildXrayConfig(profile, profile.servers[0]!, settings))
      .toHaveProperty("outbounds.0.mux", { enabled: true, concurrency: 1 });
  });

  it.each([
    ["example.com", "xhttp"],
    ["example.com", "splithttp"],
    ["leva.levikfartik.ru.example.com", "xhttp"],
    [alternateHost, "tcp"],
    [alternateHost, "ws"],
  ])("leaves %s over %s unchanged", (host, network) => {
    const profile = prepare(link(host, network));
    expect(buildXrayConfig(profile, profile.servers[0]!, settings)).not.toHaveProperty("outbounds.0.mux");
  });

  it.each([
    { protocol: "trojan", settings: { servers: [{ address: alternateHost }] } },
    { protocol: "vless", settings: { vnext: [{ address: alternateHost }, { address: "example.com" }] } },
    { protocol: "vless", settings: { vnext: [] } },
    { protocol: "vless", settings: { vnext: [null] } },
    { protocol: "vless", settings: { vnext: [{ address: 42 }] } },
    { protocol: "vless", settings: {} },
  ])("does not enable Mux for unrelated or incomplete JSON outbounds: %j", (outbound) => {
    const profile = prepare(JSON.stringify({ outbounds: [{ ...outbound, streamSettings: { network: "xhttp" } }] }));
    expect(buildXrayConfig(profile, profile.servers[0]!, settings)).not.toHaveProperty("outbounds.0.mux");
  });
});
