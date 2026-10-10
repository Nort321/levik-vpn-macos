import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";
import { buildXrayConfig, TUIC_PLACEHOLDER_ID, TUIC_PLACEHOLDER_PORT } from "../src/main/vpn/xrayConfig";
import { activeVariant, groupServers, serverProtocolShortLabel } from "../src/shared/serverGroups";
import type { AppSettings } from "../src/shared/contracts";

// Self-signed CA used only by these tests (base64url DER).
const TEST_CA = "MIIBLTCB1KADAgECAgkAlrWlAi74LtUwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjEwMDkwNjMzMzlaFw0zNjEwMDYwNjMzMzlaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQMkvwcR00n8QEH8ejxpVyrdEu2mitTmHTzJVVb-D2knRhRrsjtu5BW_5G6nQhjImjchTZSEvYh58TTUkbLgujloxMwETAPBgNVHRMBAf8EBTADAQH_MAoGCCqGSM49BAMCA0gAMEUCIQCS7Jk2t47s5ODjcF4pvBsQRoz_9CyV_roiGAHkKEDm4wIgJ2W-0_H9Nr4eiUTxs3o6LwMmI0nbP_oM6G-6pDD3fl4";
const UUID = "123e4567-e89b-42d3-a456-426614174000";
const PASSWORD = "_EnbjPjIrpPjymZ63JYDPCUY7WN9ZvWv";

const settings: AppSettings = {
  routingMode: "bypassRu", automaticServer: true, autoReconnect: true, killSwitch: true, useDoh: true,
  dnsServer: "1.1.1.1", theme: "dark", launchAtLogin: false, autoConnectOnLaunch: false, closeToTray: true,
  showTrayIcon: true, preventDnsLeaks: true, favoriteServerIds: [], antiDpiEnabled: true,
  antiDpiPackets: "tlshello", antiDpiLength: "100-200", antiDpiInterval: "10-20",
  splitTunnelMode: "off", splitTunnelProcesses: [],
  connectionTelemetry: false, telemetryNoticeShown: false, syncSettings: false,
};

function tuicLink(overrides: Record<string, string> = {}, host = "94.156.114.70"): string {
  const query = new URLSearchParams({ sni: "www.samsung.com", alpn: "h3", congestion_control: "bbr", udp_relay_mode: "native", levik_ca: TEST_CA, ...overrides });
  return `tuic://${UUID}:${PASSWORD}@${host}:8443?${query.toString()}#${encodeURIComponent("🇩🇪 TUIC")}`;
}

function profileFrom(lines: string[]) {
  return prepareTunnelProfile(Buffer.from(JSON.stringify({
    version: 1, profileId: "tuic-test", subscriptionId: "subscription-1", issuedAt: new Date().toISOString(),
    source: { mediaType: "text/plain", content: Buffer.from(lines.join("\n")).toString("base64") },
  })), "subscription-1");
}

const SUBSCRIPTION = [
  `vless://${UUID}@94.156.114.70:443?security=reality&type=xhttp&pbk=key&sid=ab#${encodeURIComponent("🇩🇪 🚀 Prime")}`,
  `hysteria2://auth@94.156.114.70:2443?sni=example.org#${encodeURIComponent("🇩🇪 🛡️ Hysteria2")}`,
  `vless://${UUID}@94.156.114.70:30443?security=reality&pbk=key&sid=ab#${encodeURIComponent("Levik Canary")}`,
  `vless://${UUID}@138.124.31.13:443?security=reality&pbk=key&sid=ab#${encodeURIComponent("🇫🇷 🚀 Prime")}`,
  tuicLink(),
];

describe("TUIC profile support", () => {
  it("parses a pinned TUIC link into a sing-box endpoint", () => {
    const tuic = profileFrom(SUBSCRIPTION).servers.find((server) => server.tuic);
    expect(tuic?.name).toBe("🇩🇪 TUIC");
    expect(tuic?.countryCode).toBe("DE");
    expect(tuic?.tuic).toMatchObject({
      address: "94.156.114.70", port: 8443, uuid: UUID, password: PASSWORD, serverName: "www.samsung.com",
      alpn: ["h3"], congestionControl: "bbr", udpRelayMode: "native",
    });
    expect(tuic?.tuic?.caCertificatePem).toMatch(/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n$/);
  });

  it("skips TUIC links that are unpinned, use names or carry invalid values", () => {
    const rejected = [
      tuicLink({ levik_ca: "" }),
      tuicLink({ levik_ca: "AAAA" }),
      tuicLink({}, "tuic.example.com"),
      tuicLink({ sni: "bad name" }),
      tuicLink({ congestion_control: "reno" }),
      `tuic://not-a-uuid:${PASSWORD}@94.156.114.70:8443?sni=www.samsung.com&levik_ca=${TEST_CA}`,
    ];
    const profile = profileFrom([SUBSCRIPTION[0]!, ...rejected]);
    expect(profile.servers.filter((server) => server.tuic)).toHaveLength(0);
  });

  it("routes a TUIC server through the loopback VLESS placeholder accepted by Xray", () => {
    const profile = profileFrom(SUBSCRIPTION);
    const server = profile.servers.find((item) => item.tuic)!;
    const config = buildXrayConfig(profile, server, settings);
    const outbounds = config.outbounds as Array<Record<string, unknown>>;
    expect(outbounds[0]).toEqual({
      tag: server.tag,
      protocol: "vless",
      settings: { vnext: [{ address: "127.0.0.1", port: TUIC_PLACEHOLDER_PORT, users: [{ id: TUIC_PLACEHOLDER_ID, encryption: "none" }] }] },
    });
    // Anti-DPI fragmentation targets TCP TLS and must not wrap the QUIC sidecar hop.
    expect(outbounds.some((outbound) => outbound.tag === "levik-fragment")).toBe(false);
    const assets = resolve("vendor", "xray", `darwin-${process.arch}`);
    const validated = { ...config, inbounds: [{ tag: "levik-tun-in", protocol: "http", listen: "127.0.0.1", port: 47199 }] };
    execFileSync(resolve(assets, "xray"), ["run", "-test", "-format", "json", "-config", "stdin:"], {
      input: JSON.stringify(validated), env: { ...process.env, XRAY_LOCATION_ASSET: assets }, stdio: ["pipe", "ignore", "pipe"],
    });
  });

  it("groups protocol variants of one server and keeps duplicates separate", () => {
    const profile = profileFrom(SUBSCRIPTION);
    const groups = groupServers(profile.servers);
    expect(groups.map((group) => group.variants.map(serverProtocolShortLabel))).toEqual([
      ["VLESS", "Hysteria 2", "TUIC"],
      ["VLESS"],
      ["VLESS"],
    ]);
    const germany = groups[0]!;
    const tuic = germany.variants[2]!;
    expect(activeVariant(germany, tuic.id)).toBe(tuic);
    expect(activeVariant(germany, null)).toBe(germany.variants[0]);
  });
});
